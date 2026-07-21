package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // Register the audited pgx database/sql driver.
)

const operationTimeout = 5 * time.Second

// Config names the protected DSN file for one PostgreSQL connection role.
type Config struct {
	DSNFile string
}

// Database is a least-privilege application connection to the platform substrate.
type Database struct {
	db       *sql.DB
	relayDB  *sql.DB
	manifest Manifest
}

// InstallationState identifies one installation timeline and its last change.
type InstallationState struct {
	InstallationID string
	TimelineID     string
	ChangeSequence int64
}

// OpenApplication opens a non-migrating, DDL-free application connection.
func OpenApplication(ctx context.Context, cfg Config) (*Database, error) {
	dsn, err := ReadDSNFile(cfg.DSNFile)
	if err != nil {
		return nil, err
	}
	db, err := open(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := verifyApplicationRole(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	relayDB, err := openPool(ctx, dsn, 4, 1)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := verifyApplicationRole(ctx, relayDB); err != nil {
		_ = relayDB.Close()
		_ = db.Close()
		return nil, err
	}
	return &Database{db: db, relayDB: relayDB, manifest: CurrentManifest()}, nil
}

func open(ctx context.Context, dsn string) (*sql.DB, error) {
	return openPool(ctx, dsn, 8, 2)
}

func openPool(ctx context.Context, dsn string, maximumOpen, maximumIdle int) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, errors.New("PostgreSQL connection configuration is invalid")
	}
	db.SetMaxOpenConns(maximumOpen)
	db.SetMaxIdleConns(maximumIdle)
	pingCtx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, errors.New("PostgreSQL is unavailable")
	}
	return db, nil
}

// Close releases both the general application and reserved relay pools.
func (d *Database) Close() error {
	if d.relayDB == nil {
		return d.db.Close()
	}
	return errors.Join(d.relayDB.Close(), d.db.Close())
}

// SchemaState inspects schema history, required objects, and role safety atomically.
func (d *Database) SchemaState(ctx context.Context) (SchemaState, error) {
	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return SchemaState{}, errors.New("PostgreSQL readiness snapshot cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	if err := verifyApplicationRole(ctx, tx); err != nil {
		return SchemaState{}, err
	}
	snapshot, err := inspect(ctx, tx)
	if err != nil {
		return SchemaState{}, err
	}
	state := Classify(snapshot, d.manifest)
	if err := tx.Commit(); err != nil {
		return SchemaState{}, errors.New("PostgreSQL readiness snapshot cannot commit")
	}
	return state, nil
}

// Ready verifies that the primary database is reachable and compatible.
func (d *Database) Ready(ctx context.Context) error {
	checkCtx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if err := d.db.PingContext(checkCtx); err != nil {
		return errors.New("PostgreSQL readiness check failed")
	}
	state, err := d.SchemaState(checkCtx)
	if err != nil {
		return err
	}
	return state.Ready()
}

// InstallationState reads stable installation, timeline, and change metadata.
func (d *Database) InstallationState(ctx context.Context) (InstallationState, error) {
	var state InstallationState
	err := d.db.QueryRowContext(ctx, `SELECT installation_id::text, timeline_id::text, change_sequence FROM jobs.server_state WHERE singleton`).Scan(&state.InstallationID, &state.TimelineID, &state.ChangeSequence)
	if err != nil {
		return InstallationState{}, errors.New("PostgreSQL installation metadata is unavailable")
	}
	return state, nil
}

// PostgreSQLMajor returns the exact server major used by release preflight.
func (d *Database) PostgreSQLMajor(ctx context.Context) (int, error) {
	var major int
	if err := d.db.QueryRowContext(ctx, `SELECT current_setting('server_version_num')::integer / 10000`).Scan(&major); err != nil || major < minimumSupportedPostgresMajor {
		return 0, errors.New("PostgreSQL major version is unavailable")
	}
	return major, nil
}

// Identity returns a content-free fingerprint of the exact target database
// within its PostgreSQL server. It is stable across schema restore operations.
func (d *Database) Identity(ctx context.Context) (string, error) {
	return databaseIdentity(ctx, d.db)
}

// Identity returns the same stable target fingerprint through owner authority.
func (a *Administration) Identity(ctx context.Context) (string, error) {
	return databaseIdentity(ctx, a.db)
}

// OwnerDatabaseIdentity fingerprints a pristine or migrated target while
// proving the protected credential authenticates as the schema owner.
func OwnerDatabaseIdentity(ctx context.Context, cfg Config) (string, error) {
	dsn, err := ReadDSNFile(cfg.DSNFile)
	if err != nil {
		return "", err
	}
	db, err := open(ctx, dsn)
	if err != nil {
		return "", err
	}
	defer func() { _ = db.Close() }()
	var owner bool
	if err := db.QueryRowContext(ctx, `SELECT session_user = current_user AND current_user = 'punaro_owner'`).Scan(&owner); err != nil || !owner {
		return "", errors.New("PostgreSQL database identity requires the schema-owner role")
	}
	return databaseIdentity(ctx, db)
}

func databaseIdentity(ctx context.Context, q queryer) (string, error) {
	var database, oid, address, port string
	if err := q.QueryRowContext(ctx, `SELECT current_database(), oid::text, COALESCE(inet_server_addr()::text, 'local'), COALESCE(inet_server_port()::text, 'local') FROM pg_database WHERE datname = current_database()`).Scan(&database, &oid, &address, &port); err != nil {
		return "", errors.New("PostgreSQL database identity is unavailable")
	}
	digest := sha256.Sum256([]byte(database + "\x00" + oid + "\x00" + address + "\x00" + port))
	return hex.EncodeToString(digest[:]), nil
}

// AcquireRestoreLock holds a cooperative database-wide advisory lock on one
// dedicated application-role session for the full restore operation.
func AcquireRestoreLock(ctx context.Context, cfg Config, identity string) (func(), error) {
	decoded, err := hex.DecodeString(identity)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != identity {
		return nil, errors.New("PostgreSQL restore lock identity is invalid")
	}
	database, err := OpenApplication(ctx, cfg)
	if err != nil {
		return nil, err
	}
	conn, err := database.db.Conn(ctx)
	if err != nil {
		_ = database.Close()
		return nil, errors.New("PostgreSQL restore lock session is unavailable")
	}
	keyDigest := sha256.Sum256(append([]byte("punaro-restore-lock\x00"), decoded...))
	var key int64
	for _, value := range keyDigest[:7] {
		key = (key << 8) | int64(value)
	}
	var acquired bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&acquired); err != nil || !acquired {
		_ = conn.Close()
		_ = database.Close()
		return nil, errors.New("PostgreSQL target is already participating in a restore")
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), operationTimeout)
			defer cancel()
			var released bool
			_ = conn.QueryRowContext(releaseCtx, `SELECT pg_advisory_unlock($1)`, key).Scan(&released)
			_ = conn.Close()
			_ = database.Close()
		})
	}, nil
}

// InstallationOwner returns the singleton owner identity visible to the
// application role so runtime configuration can be bound to one installation.
func (d *Database) InstallationOwner(ctx context.Context) (Principal, error) {
	var owner Principal
	err := d.db.QueryRowContext(ctx, `SELECT principal.id::text, principal.kind, principal.display_name
FROM auth.installation_owner AS installation
JOIN auth.principals AS principal ON principal.id = installation.principal_id
WHERE installation.singleton`).Scan(&owner.ID, &owner.Kind, &owner.DisplayName)
	if errors.Is(err, sql.ErrNoRows) {
		return Principal{}, ErrNotFound
	}
	if err != nil {
		return Principal{}, errors.New("installation owner is unavailable")
	}
	return owner, nil
}

// AdvanceChange atomically increments and returns the global change sequence.
func (d *Database) AdvanceChange(ctx context.Context) (InstallationState, error) {
	var state InstallationState
	err := d.db.QueryRowContext(ctx, `SELECT installation_id::text, timeline_id::text, change_sequence FROM jobs.advance_change_sequence()`).Scan(&state.InstallationID, &state.TimelineID, &state.ChangeSequence)
	if err != nil {
		if isMaintenanceError(err) {
			return InstallationState{}, ErrMaintenance
		}
		return InstallationState{}, errors.New("PostgreSQL change sequence could not be advanced")
	}
	return state, nil
}

type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func inspect(ctx context.Context, q queryer) (Snapshot, error) {
	var snapshot Snapshot
	err := q.QueryRowContext(ctx, `SELECT count(*) FROM pg_namespace WHERE nspname = ANY($1::text[])`, []string{"auth", "relay", "attachment", "brain", "jobs", "audit"}).Scan(&snapshot.OwnedSchemaCount)
	if err != nil {
		return Snapshot{}, errors.New("PostgreSQL schema state cannot be inspected")
	}
	err = q.QueryRowContext(ctx, `SELECT to_regclass('jobs.schema_migrations') IS NOT NULL`).Scan(&snapshot.TrackingExists)
	if err != nil || !snapshot.TrackingExists {
		if err != nil {
			return Snapshot{}, errors.New("PostgreSQL schema state cannot be inspected")
		}
		return snapshot, nil
	}
	if err := q.QueryRowContext(ctx, `
WITH objects AS (
    SELECT to_regclass('jobs.schema_migrations') AS migrations_oid,
           to_regclass('jobs.server_state') AS state_oid,
           to_regprocedure('jobs.advance_change_sequence()') AS advance_oid
)
SELECT state_oid IS NOT NULL
   AND advance_oid IS NOT NULL
   AND NOT EXISTS (
       SELECT 1 FROM pg_namespace AS namespace
       JOIN pg_roles AS owner ON owner.oid = namespace.nspowner
       WHERE namespace.nspname = ANY($1::text[]) AND owner.rolname <> 'punaro_owner'
   )
   AND COALESCE((SELECT pg_get_userbyid(relowner) = 'punaro_owner' FROM pg_class WHERE oid = migrations_oid), false)
   AND COALESCE((SELECT pg_get_userbyid(relowner) = 'punaro_owner' FROM pg_class WHERE oid = state_oid), false)
   AND COALESCE((SELECT pg_get_userbyid(proowner) = 'punaro_owner' FROM pg_proc WHERE oid = advance_oid), false)
   AND COALESCE(has_table_privilege('punaro_app', migrations_oid, 'SELECT'), false)
   AND COALESCE(has_table_privilege('punaro_app', state_oid, 'SELECT'), false)
   AND NOT COALESCE(has_table_privilege('punaro_app', migrations_oid, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'), false)
   AND NOT COALESCE(has_any_column_privilege('punaro_app', migrations_oid, 'INSERT,UPDATE,REFERENCES'), false)
   AND NOT COALESCE(has_table_privilege('punaro_app', state_oid, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'), false)
   AND NOT COALESCE(has_any_column_privilege('punaro_app', state_oid, 'INSERT,UPDATE,REFERENCES'), false)
   AND COALESCE(has_function_privilege('punaro_app', advance_oid, 'EXECUTE'), false)
FROM objects`, []string{"auth", "relay", "attachment", "brain", "jobs", "audit"}).Scan(&snapshot.BaseObjectsPresent); err != nil {
		return Snapshot{}, errors.New("PostgreSQL schema state cannot be inspected")
	}
	if snapshot.BaseObjectsPresent {
		if err := q.QueryRowContext(ctx, `SELECT COALESCE(count(*) = 1 AND bool_and(singleton AND installation_id <> '00000000-0000-0000-0000-000000000000'::uuid AND timeline_id <> '00000000-0000-0000-0000-000000000000'::uuid AND change_sequence >= 0), false) FROM jobs.server_state`).Scan(&snapshot.BaseObjectsPresent); err != nil {
			return Snapshot{}, errors.New("PostgreSQL installation metadata cannot be inspected")
		}
	}
	rows, err := q.QueryContext(ctx, `SELECT version, name, checksum, compatibility_floor, status FROM jobs.schema_migrations ORDER BY version`)
	if err != nil {
		return Snapshot{}, errors.New("PostgreSQL migration history cannot be inspected")
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var record AppliedMigration
		if err := rows.Scan(&record.Version, &record.Name, &record.Checksum, &record.CompatibilityFloor, &record.Status); err != nil {
			return Snapshot{}, errors.New("PostgreSQL migration history is malformed")
		}
		snapshot.Records = append(snapshot.Records, record)
	}
	if err := rows.Err(); err != nil {
		return Snapshot{}, errors.New("PostgreSQL migration history cannot be inspected")
	}
	if len(snapshot.Records) > 0 && snapshot.Records[len(snapshot.Records)-1].Version >= 2 {
		currentVersion := snapshot.Records[len(snapshot.Records)-1].Version
		if err := q.QueryRowContext(ctx, `
WITH objects AS (
    SELECT
        to_regclass('auth.principals') AS principals_oid,
        to_regclass('auth.capability_grants') AS grants_oid,
        to_regclass('relay.projects') AS projects_oid,
        to_regclass('relay.idempotency_records') AS idempotency_oid,
        to_regclass('audit.events') AS audit_oid,
        to_regclass('audit.events_event_id_seq') AS audit_sequence_oid,
        to_regclass('jobs.queue_capacity') AS capacity_oid,
        to_regclass('jobs.outbox') AS outbox_oid,
        to_regclass('auth.capability_grants_active_unique') AS grants_active_oid,
        to_regprocedure('jobs.guard_outbox_capacity_and_state()') AS guard_oid,
        to_regprocedure('audit.prune_events(timestamp with time zone,integer)') AS audit_prune_oid,
        to_regprocedure('jobs.prune_terminal(timestamp with time zone,integer)') AS jobs_prune_oid
), ownership AS (
    SELECT count(*) = 9 AND bool_and(pg_get_userbyid(relowner) = 'punaro_owner') AS owned
    FROM pg_class, objects
    WHERE oid = ANY(ARRAY[principals_oid, grants_oid, projects_oid, idempotency_oid, audit_oid, audit_sequence_oid, capacity_oid, outbox_oid, grants_active_oid])
), function_ownership AS (
    SELECT count(*) = 3
       AND bool_and(pg_get_userbyid(proowner) = 'punaro_owner')
       AND bool_and(prosecdef)
	   AND bool_and(COALESCE(proconfig = ARRAY['search_path=pg_catalog']::text[], false))
       -- PostgreSQL prosrc retains the dollar-quoted boundary newlines; btrim
       -- removes only ordinary spaces, so these are catalog-exact fingerprints.
       AND bool_and(
		   (oid = guard_oid AND md5(btrim(prosrc)) = '56cb3ea6402ffbf41f360cf4c8ba392f')
		   OR (oid = audit_prune_oid AND md5(btrim(prosrc)) = 'd477a1e8ffc27e7a7c652975bdd06057')
		   OR (oid = jobs_prune_oid AND md5(btrim(prosrc)) = 'ea4a8de811f6f8f9d5804f30fcd03869')
       ) AS owned
    FROM pg_proc, objects
    WHERE oid = ANY(ARRAY[guard_oid, audit_prune_oid, jobs_prune_oid])
)
SELECT
    principals_oid IS NOT NULL AND grants_oid IS NOT NULL AND projects_oid IS NOT NULL
    AND idempotency_oid IS NOT NULL AND audit_oid IS NOT NULL AND audit_sequence_oid IS NOT NULL
    AND capacity_oid IS NOT NULL AND outbox_oid IS NOT NULL AND grants_active_oid IS NOT NULL
    AND guard_oid IS NOT NULL AND audit_prune_oid IS NOT NULL AND jobs_prune_oid IS NOT NULL
    AND ownership.owned AND function_ownership.owned
    AND EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgrelid = outbox_oid AND tgfoid = guard_oid AND tgname = 'outbox_capacity_and_state'
          AND tgenabled = 'O' AND NOT tgisinternal AND tgtype = 23
    )
    AND EXISTS (
        SELECT 1 FROM pg_index
        WHERE indexrelid = grants_active_oid AND indrelid = grants_oid
          AND indisunique AND indisvalid AND indisready AND indnkeyatts = 4
          AND indkey = '2 3 0 5'::int2vector
          AND pg_get_expr(indexprs, indrelid) = 'COALESCE(project_id, ''00000000-0000-0000-0000-000000000000''::uuid)'
          AND pg_get_expr(indpred, indrelid) = '(revoked_at IS NULL)'
    )
    AND has_table_privilege('punaro_app', principals_oid, 'SELECT')
    AND has_table_privilege('punaro_app', principals_oid, 'INSERT')
    AND has_table_privilege('punaro_app', principals_oid, 'UPDATE')
    AND NOT has_table_privilege('punaro_app', principals_oid, 'DELETE')
    AND NOT has_table_privilege('punaro_app', principals_oid, 'TRUNCATE')
    AND NOT has_table_privilege('punaro_app', principals_oid, 'REFERENCES')
    AND NOT has_table_privilege('punaro_app', principals_oid, 'TRIGGER')
    AND has_table_privilege('punaro_app', grants_oid, 'SELECT')
    AND has_table_privilege('punaro_app', grants_oid, 'INSERT')
    AND has_table_privilege('punaro_app', grants_oid, 'UPDATE')
    AND NOT has_table_privilege('punaro_app', grants_oid, 'DELETE')
    AND NOT has_table_privilege('punaro_app', grants_oid, 'TRUNCATE')
    AND NOT has_table_privilege('punaro_app', grants_oid, 'REFERENCES')
    AND NOT has_table_privilege('punaro_app', grants_oid, 'TRIGGER')
    AND has_table_privilege('punaro_app', projects_oid, 'SELECT')
    AND (($1 < 4 AND has_table_privilege('punaro_app', projects_oid, 'INSERT'))
         OR ($1 >= 4 AND NOT has_table_privilege('punaro_app', projects_oid, 'INSERT')))
    AND (($1 < 4 AND has_table_privilege('punaro_app', projects_oid, 'UPDATE'))
         OR ($1 >= 4 AND NOT has_table_privilege('punaro_app', projects_oid, 'UPDATE')))
    AND NOT has_table_privilege('punaro_app', projects_oid, 'DELETE')
    AND NOT has_table_privilege('punaro_app', projects_oid, 'TRUNCATE')
    AND NOT has_table_privilege('punaro_app', projects_oid, 'REFERENCES')
    AND NOT has_table_privilege('punaro_app', projects_oid, 'TRIGGER')
    AND has_table_privilege('punaro_app', idempotency_oid, 'SELECT')
    AND has_table_privilege('punaro_app', idempotency_oid, 'INSERT')
    AND has_table_privilege('punaro_app', idempotency_oid, 'UPDATE')
    AND NOT has_table_privilege('punaro_app', idempotency_oid, 'DELETE')
    AND NOT has_table_privilege('punaro_app', idempotency_oid, 'TRUNCATE')
    AND NOT has_table_privilege('punaro_app', idempotency_oid, 'REFERENCES')
    AND NOT has_table_privilege('punaro_app', idempotency_oid, 'TRIGGER')
    AND has_table_privilege('punaro_app', audit_oid, 'SELECT')
    AND has_table_privilege('punaro_app', audit_oid, 'INSERT')
    AND NOT has_table_privilege('punaro_app', audit_oid, 'UPDATE')
    AND NOT has_table_privilege('punaro_app', audit_oid, 'DELETE')
    AND NOT has_table_privilege('punaro_app', audit_oid, 'TRUNCATE')
    AND NOT has_table_privilege('punaro_app', audit_oid, 'REFERENCES')
    AND NOT has_table_privilege('punaro_app', audit_oid, 'TRIGGER')
    AND NOT has_any_column_privilege('punaro_app', audit_oid, 'UPDATE,REFERENCES')
    AND has_sequence_privilege('punaro_app', audit_sequence_oid, 'USAGE')
    AND has_sequence_privilege('punaro_app', audit_sequence_oid, 'SELECT')
    AND NOT has_sequence_privilege('punaro_app', audit_sequence_oid, 'UPDATE')
    AND has_table_privilege('punaro_app', capacity_oid, 'SELECT')
    AND NOT has_table_privilege('punaro_app', capacity_oid, 'INSERT')
    AND NOT has_table_privilege('punaro_app', capacity_oid, 'UPDATE')
    AND NOT has_table_privilege('punaro_app', capacity_oid, 'DELETE')
    AND NOT has_table_privilege('punaro_app', capacity_oid, 'TRUNCATE')
    AND NOT has_table_privilege('punaro_app', capacity_oid, 'REFERENCES')
    AND NOT has_table_privilege('punaro_app', capacity_oid, 'TRIGGER')
    AND NOT has_any_column_privilege('punaro_app', capacity_oid, 'INSERT,UPDATE,REFERENCES')
    AND has_table_privilege('punaro_app', outbox_oid, 'SELECT')
    AND has_table_privilege('punaro_app', outbox_oid, 'INSERT')
    AND has_table_privilege('punaro_app', outbox_oid, 'UPDATE')
    AND NOT has_table_privilege('punaro_app', outbox_oid, 'DELETE')
    AND NOT has_table_privilege('punaro_app', outbox_oid, 'TRUNCATE')
    AND NOT has_table_privilege('punaro_app', outbox_oid, 'REFERENCES')
    AND NOT has_table_privilege('punaro_app', outbox_oid, 'TRIGGER')
    AND NOT has_function_privilege('punaro_app', guard_oid, 'EXECUTE')
    AND has_function_privilege('punaro_app', audit_prune_oid, 'EXECUTE')
    AND has_function_privilege('punaro_app', jobs_prune_oid, 'EXECUTE')
FROM objects, ownership, function_ownership`, currentVersion).Scan(&snapshot.CurrentObjectsPresent); err != nil {
			return Snapshot{}, errors.New("PostgreSQL control-plane schema cannot be inspected")
		}
	}
	if snapshot.CurrentObjectsPresent && len(snapshot.Records) > 0 && snapshot.Records[len(snapshot.Records)-1].Version >= 3 {
		currentVersion := snapshot.Records[len(snapshot.Records)-1].Version
		var deviceObjectsPresent bool
		if err := q.QueryRowContext(ctx, `
WITH objects AS (
    SELECT
        to_regclass('auth.installation_owner') AS owner_oid,
        to_regclass('auth.pending_enrollments') AS enrollments_oid,
        to_regclass('auth.pending_enrollment_grants') AS enrollment_grants_oid,
        to_regclass('auth.device_credentials') AS credentials_oid,
        to_regclass('auth.pending_enrollments_active_binding') AS enrollment_binding_oid,
        to_regclass('auth.device_credentials_principal_active') AS credential_principal_oid,
        to_regclass('auth.device_credentials_secret_digest') AS credential_digest_oid,
        to_regclass('auth.legacy_auth_state') AS legacy_state_oid,
        to_regclass('auth.legacy_machines') AS legacy_machines_oid,
        to_regprocedure('auth.complete_legacy_exchange(uuid,uuid)') AS legacy_exchange_oid
), ownership AS (
    SELECT count(*) = 9 AND bool_and(pg_get_userbyid(relowner) = 'punaro_owner') AS owned
    FROM pg_class, objects
    WHERE oid = ANY(ARRAY[owner_oid, enrollments_oid, enrollment_grants_oid, credentials_oid, enrollment_binding_oid, credential_principal_oid, credential_digest_oid, legacy_state_oid, legacy_machines_oid])
)
SELECT
    owner_oid IS NOT NULL AND enrollments_oid IS NOT NULL AND enrollment_grants_oid IS NOT NULL
    AND credentials_oid IS NOT NULL AND enrollment_binding_oid IS NOT NULL AND credential_principal_oid IS NOT NULL AND credential_digest_oid IS NOT NULL
    AND legacy_state_oid IS NOT NULL AND legacy_machines_oid IS NOT NULL AND legacy_exchange_oid IS NOT NULL AND ownership.owned
    AND COALESCE((
        SELECT pg_get_userbyid(proowner) = 'punaro_owner'
          AND prosecdef AND prokind = 'f' AND provolatile = 'v' AND proretset
          AND prorettype = 'boolean'::regtype AND pronargs = 2
          AND prolang = (SELECT oid FROM pg_language WHERE lanname = 'sql')
          AND COALESCE(proconfig = ARRAY['search_path=pg_catalog']::text[], false)
          AND md5(btrim(prosrc, E' \n\r\t')) = 'b831dc95c00ef6f4a55a96076131c769'
        FROM pg_proc WHERE oid = legacy_exchange_oid
    ), false)
    AND has_function_privilege('punaro_app', legacy_exchange_oid, 'EXECUTE')
    AND NOT EXISTS (
        SELECT 1 FROM pg_proc AS routine
        CROSS JOIN LATERAL aclexplode(COALESCE(routine.proacl, acldefault('f', routine.proowner))) AS acl_entry
        WHERE routine.oid = legacy_exchange_oid AND acl_entry.privilege_type = 'EXECUTE'
          AND (
              acl_entry.grantee NOT IN (routine.proowner, (SELECT oid FROM pg_roles WHERE rolname = 'punaro_app'))
              OR (acl_entry.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'punaro_app') AND acl_entry.is_grantable)
          )
    )
    AND EXISTS (
        SELECT 1 FROM pg_attribute AS attribute
        JOIN pg_attrdef AS default_value ON default_value.adrelid = attribute.attrelid AND default_value.adnum = attribute.attnum
        WHERE attribute.attrelid = 'auth.principals'::regclass AND attribute.attname = 'auth_generation' AND NOT attribute.attisdropped
          AND attribute.attnotnull AND attribute.atttypid = 'bigint'::regtype
          AND pg_get_expr(default_value.adbin, default_value.adrelid) = '0'
    )
    AND EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'auth.principals'::regclass AND contype = 'c' AND conkey = ARRAY[6]::smallint[] AND convalidated
          AND pg_get_expr(conbin, conrelid) = '(auth_generation >= 0)'
    )
    AND EXISTS (
        SELECT 1 FROM pg_index
        WHERE indexrelid = enrollment_binding_oid AND indrelid = enrollments_oid
          AND NOT indisunique AND indisvalid AND indisready AND indnkeyatts = 1 AND indkey = '3'::int2vector
          AND (($1 = 3 AND pg_get_expr(indpred, indrelid) = '(redeemed_at IS NULL)')
               OR ($1 >= 4 AND pg_get_expr(indpred, indrelid) = '((redeemed_at IS NULL) AND (invalidated_at IS NULL))'))
    )
    AND EXISTS (
        SELECT 1 FROM pg_index
        WHERE indexrelid = credential_principal_oid AND indrelid = credentials_oid
          AND NOT indisunique AND indisvalid AND indisready AND indnkeyatts = 1 AND indkey = '2'::int2vector
          AND pg_get_expr(indpred, indrelid) = '(revoked_at IS NULL)'
    )
    AND EXISTS (
        SELECT 1 FROM pg_index
        WHERE indexrelid = credential_digest_oid AND indrelid = credentials_oid
          AND indisunique AND indisvalid AND indisready AND indnkeyatts = 1 AND indkey = '4'::int2vector
          AND indexprs IS NULL AND indpred IS NULL
    )
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = owner_oid AND contype = 'p' AND conkey = ARRAY[1]::smallint[] AND convalidated)
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = owner_oid AND contype = 'u' AND conkey = ARRAY[2]::smallint[] AND convalidated)
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = owner_oid AND contype = 'f' AND conkey = ARRAY[2]::smallint[] AND confrelid = 'auth.principals'::regclass AND convalidated)
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = owner_oid AND contype = 'c' AND conkey = ARRAY[1]::smallint[] AND convalidated AND pg_get_expr(conbin, conrelid) = 'singleton')
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = credentials_oid AND contype = 'u' AND conkey = ARRAY[2]::smallint[] AND convalidated)
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = credentials_oid AND contype = 'f' AND conkey = ARRAY[2]::smallint[] AND confrelid = 'auth.principals'::regclass AND convalidated)
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = credentials_oid AND contype = 'c' AND conkey = ARRAY[4]::smallint[] AND convalidated AND pg_get_expr(conbin, conrelid) = '(octet_length(secret_digest) = 32)')
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = credentials_oid AND contype = 'c' AND conkey = ARRAY[5]::smallint[] AND convalidated AND pg_get_expr(conbin, conrelid) = '(generation >= 1)')
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = credentials_oid AND contype = 'c' AND conkey = ARRAY[8,6]::smallint[] AND convalidated AND pg_get_expr(conbin, conrelid) = '((expires_at IS NULL) OR (expires_at > created_at))')
    AND EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = credentials_oid AND contype = 'c' AND conkey = ARRAY[10,11,12,13]::smallint[] AND convalidated
          AND pg_get_expr(conbin, conrelid) = '(((rotation_code_digest IS NULL) AND (rotation_expected_generation IS NULL) AND (rotation_expires_at IS NULL) AND (rotation_completed_at IS NULL)) OR ((rotation_code_digest IS NOT NULL) AND (rotation_expected_generation >= 1) AND (rotation_expires_at IS NOT NULL)))'
    )
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = enrollments_oid AND contype = 'f' AND conkey = ARRAY[2]::smallint[] AND confrelid = 'auth.principals'::regclass AND convalidated)
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = enrollments_oid AND contype = 'f' AND conkey = ARRAY[13]::smallint[] AND confrelid = credentials_oid AND convalidated)
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = enrollments_oid AND contype = 'f' AND conkey = ARRAY[14]::smallint[] AND confrelid = 'auth.principals'::regclass AND convalidated)
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = enrollments_oid AND contype = 'c' AND conkey = ARRAY[5]::smallint[] AND convalidated AND pg_get_expr(conbin, conrelid) = '(octet_length(code_digest) = 32)')
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = enrollments_oid AND contype = 'c' AND conkey = ARRAY[8]::smallint[] AND convalidated AND pg_get_expr(conbin, conrelid) = '((credential_ttl_seconds IS NULL) OR ((credential_ttl_seconds >= 60) AND (credential_ttl_seconds <= 31536000)))')
    AND EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = enrollments_oid AND contype = 'c' AND conkey = ARRAY[10,11,12,13]::smallint[] AND convalidated
          AND pg_get_expr(conbin, conrelid) = '(((redeemed_at IS NULL) AND (redemption_key IS NULL) AND (redeemed_principal_id IS NULL) AND (credential_lookup_id IS NULL)) OR ((redeemed_at IS NOT NULL) AND (redemption_key IS NOT NULL) AND (redeemed_principal_id IS NOT NULL) AND (credential_lookup_id IS NOT NULL)))'
    )
	AND (($1 = 3 AND NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = enrollments_oid AND attname = 'invalidated_at' AND NOT attisdropped))
	     OR ($1 >= 4 AND EXISTS (
	         SELECT 1 FROM pg_attribute WHERE attrelid = enrollments_oid AND attname = 'invalidated_at' AND NOT attisdropped
	           AND NOT attnotnull AND atttypid = 'timestamptz'::regtype
	     )))
	AND (($1 = 3 AND NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = enrollments_oid AND conname = 'pending_enrollments_invalidation_check'))
	     OR ($1 >= 4 AND EXISTS (
	         SELECT 1 FROM pg_constraint WHERE conrelid = enrollments_oid AND conname = 'pending_enrollments_invalidation_check'
	           AND contype = 'c' AND conkey = ARRAY[15,9]::smallint[] AND convalidated
	           AND pg_get_expr(conbin, conrelid) = '((invalidated_at IS NULL) OR (invalidated_at >= created_at))'
	     )))
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = enrollment_grants_oid AND contype = 'p' AND conkey = ARRAY[1,2]::smallint[] AND convalidated)
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = enrollment_grants_oid AND contype = 'f' AND conkey = ARRAY[1]::smallint[] AND confrelid = enrollments_oid AND confdeltype = 'c' AND convalidated)
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = enrollment_grants_oid AND contype = 'f' AND conkey = ARRAY[4]::smallint[] AND confrelid = 'relay.projects'::regclass AND convalidated)
    AND EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = enrollment_grants_oid AND contype = 'c' AND conkey = ARRAY[3,4,5]::smallint[] AND convalidated
          AND pg_get_expr(conbin, conrelid) = '(((scope = ''installation''::text) AND (project_id IS NULL) AND (capability = ''project.create''::text)) OR ((scope = ANY (ARRAY[''project''::text, ''all_projects''::text])) AND (((scope = ''project''::text) AND (project_id IS NOT NULL)) OR ((scope = ''all_projects''::text) AND (project_id IS NULL))) AND (capability <> ''project.create''::text)))'
    )
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = legacy_machines_oid AND contype = 'c' AND conkey = ARRAY[2]::smallint[] AND convalidated AND pg_get_expr(conbin, conrelid) = '(octet_length(public_key) = 32)')
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = legacy_machines_oid AND contype = 'c' AND conkey = ARRAY[4]::smallint[] AND convalidated AND pg_get_expr(conbin, conrelid) = '(state = ANY (ARRAY[''pending''::text, ''migrated''::text, ''retired''::text]))')
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = legacy_machines_oid AND contype = 'c' AND conkey = ARRAY[4,5]::smallint[] AND convalidated AND pg_get_expr(conbin, conrelid) = '((state = ''migrated''::text) = (migrated_credential_lookup_id IS NOT NULL))')
    AND EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'audit.events'::regclass AND conname = 'events_action_check'
          AND contype = 'c' AND conkey = ARRAY[5]::smallint[] AND convalidated
          AND (($1 = 3 AND pg_get_expr(conbin, conrelid) = '(action = ANY (ARRAY[''principal.create''::text, ''project.create''::text, ''grant.create''::text, ''grant.delete''::text, ''job.enqueue''::text, ''job.complete''::text, ''job.retry''::text, ''job.fail''::text, ''owner.bootstrap''::text, ''enrollment.create''::text, ''enrollment.redeem''::text, ''credential.rotate''::text, ''credential.revoke''::text, ''legacy.register''::text, ''legacy.exchange''::text, ''legacy.retire''::text, ''legacy.disable''::text]))')
            OR ($1 >= 4 AND pg_get_expr(conbin, conrelid) = '(action = ANY (ARRAY[''principal.create''::text, ''project.create''::text, ''grant.create''::text, ''grant.delete''::text, ''job.enqueue''::text, ''job.complete''::text, ''job.retry''::text, ''job.fail''::text, ''owner.bootstrap''::text, ''enrollment.create''::text, ''enrollment.redeem''::text, ''credential.rotate''::text, ''credential.revoke''::text, ''legacy.register''::text, ''legacy.exchange''::text, ''legacy.retire''::text, ''legacy.disable''::text, ''project.identity.attach''::text, ''project.merge.preview''::text, ''project.merge''::text]))'))
    )
    AND EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'audit.events'::regclass AND conname = 'events_target_kind_check'
          AND contype = 'c' AND conkey = ARRAY[7]::smallint[] AND convalidated
          AND (($1 = 3 AND pg_get_expr(conbin, conrelid) = '(target_kind = ANY (ARRAY[''principal''::text, ''project''::text, ''grant''::text, ''job''::text, ''enrollment''::text, ''credential''::text, ''legacy_machine''::text]))')
            OR ($1 >= 4 AND pg_get_expr(conbin, conrelid) = '(target_kind = ANY (ARRAY[''principal''::text, ''project''::text, ''grant''::text, ''job''::text, ''enrollment''::text, ''credential''::text, ''legacy_machine''::text, ''project_identity''::text, ''project_merge''::text]))'))
    )
    AND has_table_privilege('punaro_app', owner_oid, 'SELECT')
    AND NOT has_table_privilege('punaro_app', owner_oid, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
    AND NOT has_any_column_privilege('punaro_app', owner_oid, 'INSERT,UPDATE,REFERENCES')
    AND has_table_privilege('punaro_app', enrollments_oid, 'SELECT')
    AND NOT has_table_privilege('punaro_app', enrollments_oid, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
    AND NOT has_any_column_privilege('punaro_app', enrollments_oid, 'INSERT,REFERENCES')
    AND has_column_privilege('punaro_app', enrollments_oid, 'redeemed_at', 'UPDATE')
    AND has_column_privilege('punaro_app', enrollments_oid, 'redemption_key', 'UPDATE')
    AND has_column_privilege('punaro_app', enrollments_oid, 'redeemed_principal_id', 'UPDATE')
    AND has_column_privilege('punaro_app', enrollments_oid, 'credential_lookup_id', 'UPDATE')
	AND (($1 = 3 AND NOT has_column_privilege('punaro_app', enrollments_oid, 'invalidated_at', 'UPDATE'))
	     OR ($1 >= 4 AND has_column_privilege('punaro_app', enrollments_oid, 'invalidated_at', 'UPDATE')))
    AND NOT has_column_privilege('punaro_app', enrollments_oid, 'issuer_principal_id', 'UPDATE')
    AND NOT has_column_privilege('punaro_app', enrollments_oid, 'client_binding', 'UPDATE')
    AND NOT has_column_privilege('punaro_app', enrollments_oid, 'code_digest', 'UPDATE')
    AND NOT has_column_privilege('punaro_app', enrollments_oid, 'preview_hash', 'UPDATE')
    AND NOT has_column_privilege('punaro_app', enrollments_oid, 'legacy_principal_id', 'UPDATE')
    AND NOT EXISTS (
        SELECT 1 FROM pg_attribute
        WHERE attrelid = enrollments_oid AND attnum > 0 AND NOT attisdropped
		  AND attname <> ALL (ARRAY['redeemed_at', 'redemption_key', 'redeemed_principal_id', 'credential_lookup_id', 'invalidated_at'])
          AND has_column_privilege('punaro_app', enrollments_oid, attname, 'UPDATE')
    )
    AND has_table_privilege('punaro_app', enrollment_grants_oid, 'SELECT')
    AND NOT has_table_privilege('punaro_app', enrollment_grants_oid, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
    AND NOT has_any_column_privilege('punaro_app', enrollment_grants_oid, 'INSERT,UPDATE,REFERENCES')
    AND has_table_privilege('punaro_app', credentials_oid, 'SELECT')
    AND NOT has_table_privilege('punaro_app', credentials_oid, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
    AND has_column_privilege('punaro_app', credentials_oid, 'lookup_id', 'INSERT')
    AND has_column_privilege('punaro_app', credentials_oid, 'principal_id', 'INSERT')
    AND has_column_privilege('punaro_app', credentials_oid, 'label', 'INSERT')
    AND has_column_privilege('punaro_app', credentials_oid, 'secret_digest', 'INSERT')
    AND has_column_privilege('punaro_app', credentials_oid, 'expires_at', 'INSERT')
    AND NOT has_column_privilege('punaro_app', credentials_oid, 'generation', 'INSERT')
    AND NOT has_column_privilege('punaro_app', credentials_oid, 'revoked_at', 'INSERT')
    AND has_column_privilege('punaro_app', credentials_oid, 'last_used_at', 'UPDATE')
    AND NOT has_column_privilege('punaro_app', credentials_oid, 'secret_digest', 'UPDATE')
    AND NOT has_column_privilege('punaro_app', credentials_oid, 'generation', 'UPDATE')
    AND NOT has_column_privilege('punaro_app', credentials_oid, 'revoked_at', 'UPDATE')
    AND NOT EXISTS (
        SELECT 1 FROM pg_attribute
        WHERE attrelid = credentials_oid AND attnum > 0 AND NOT attisdropped
          AND attname <> ALL (ARRAY['lookup_id', 'principal_id', 'label', 'secret_digest', 'expires_at'])
          AND has_column_privilege('punaro_app', credentials_oid, attname, 'INSERT')
    )
    AND NOT EXISTS (
        SELECT 1 FROM pg_attribute
        WHERE attrelid = credentials_oid AND attnum > 0 AND NOT attisdropped
          AND attname <> 'last_used_at'
          AND has_column_privilege('punaro_app', credentials_oid, attname, 'UPDATE')
    )
    AND NOT has_any_column_privilege('punaro_app', credentials_oid, 'REFERENCES')
    AND has_table_privilege('punaro_app', legacy_state_oid, 'SELECT')
    AND NOT has_table_privilege('punaro_app', legacy_state_oid, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
    AND NOT has_any_column_privilege('punaro_app', legacy_state_oid, 'INSERT,UPDATE,REFERENCES')
    AND has_table_privilege('punaro_app', legacy_machines_oid, 'SELECT')
    AND NOT has_table_privilege('punaro_app', legacy_machines_oid, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
    AND NOT has_any_column_privilege('punaro_app', legacy_machines_oid, 'INSERT,UPDATE,REFERENCES')
FROM objects, ownership`, currentVersion).Scan(&deviceObjectsPresent); err != nil {
			return Snapshot{}, errors.New("PostgreSQL device-auth schema cannot be inspected")
		}
		snapshot.CurrentObjectsPresent = deviceObjectsPresent
	}
	if snapshot.CurrentObjectsPresent && len(snapshot.Records) > 0 && snapshot.Records[len(snapshot.Records)-1].Version >= 4 {
		var identityObjectsPresent bool
		if err := q.QueryRowContext(ctx, `
WITH objects AS (
    SELECT to_regclass('auth.project_acl_state') AS acl_state_oid,
           to_regclass('relay.project_identities') AS identities_oid,
           to_regclass('relay.project_lookup_aliases') AS aliases_oid,
           to_regclass('relay.project_merge_previews') AS previews_oid,
           to_regclass('relay.project_identities_project') AS identities_project_oid,
           to_regclass('relay.project_lookup_aliases_canonical') AS aliases_canonical_oid,
           to_regclass('relay.project_merge_previews_live_actor') AS previews_live_actor_oid,
           to_regclass('relay.project_merge_previews_prune') AS previews_prune_oid,
           to_regprocedure('auth.guard_pending_enrollment_invalidation()') AS enrollment_invalidation_guard_oid
), ownership AS (
    SELECT count(*) = 4 AND bool_and(pg_get_userbyid(relowner) = 'punaro_owner') AS owned
    FROM pg_class, objects
    WHERE oid = ANY(ARRAY[acl_state_oid, identities_oid, aliases_oid, previews_oid])
)
SELECT acl_state_oid IS NOT NULL AND identities_oid IS NOT NULL AND aliases_oid IS NOT NULL AND previews_oid IS NOT NULL
    AND identities_project_oid IS NOT NULL AND aliases_canonical_oid IS NOT NULL
	AND previews_live_actor_oid IS NOT NULL AND previews_prune_oid IS NOT NULL
	AND enrollment_invalidation_guard_oid IS NOT NULL AND ownership.owned
	AND COALESCE((
	    SELECT pg_get_userbyid(proowner) = 'punaro_owner' AND NOT prosecdef
	      AND prokind = 'f' AND provolatile = 'v' AND NOT proretset
	      AND prorettype = 'trigger'::regtype AND pronargs = 0
	      AND prolang = (SELECT oid FROM pg_language WHERE lanname = 'plpgsql')
	      AND COALESCE(proconfig = ARRAY['search_path=pg_catalog']::text[], false)
	      AND md5(btrim(prosrc, E' \n\r\t')) = '56c6a353ea2c14eaaf72c9a6bada4a5d'
	    FROM pg_proc WHERE oid = enrollment_invalidation_guard_oid
	), false)
	AND NOT has_function_privilege('punaro_app', enrollment_invalidation_guard_oid, 'EXECUTE')
	AND NOT EXISTS (
	    SELECT 1 FROM pg_proc AS routine
	    CROSS JOIN LATERAL aclexplode(COALESCE(routine.proacl, acldefault('f', routine.proowner))) AS acl_entry
	    WHERE routine.oid = enrollment_invalidation_guard_oid
	      AND acl_entry.grantee <> routine.proowner
	)
	AND EXISTS (
	    SELECT 1 FROM pg_trigger
	    WHERE tgrelid = 'auth.pending_enrollments'::regclass
	      AND tgname = 'pending_enrollment_invalidation_guard'
	      AND tgfoid = enrollment_invalidation_guard_oid
	      AND NOT tgisinternal AND tgenabled = 'O' AND tgtype = 19
	      AND tgattr = '15'::int2vector AND tgqual IS NULL
	)
    AND (SELECT count(*) = 1 AND bool_and(singleton AND global_generation >= 0) FROM auth.project_acl_state)
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = acl_state_oid AND contype = 'p' AND conkey = ARRAY[1]::smallint[] AND convalidated)
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = acl_state_oid AND contype = 'c' AND conkey = ARRAY[1]::smallint[] AND convalidated AND pg_get_expr(conbin, conrelid) = 'singleton')
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = acl_state_oid AND contype = 'c' AND conkey = ARRAY[2]::smallint[] AND convalidated AND pg_get_expr(conbin, conrelid) = '(global_generation >= 0)')
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = identities_oid AND contype = 'p' AND conkey = ARRAY[1]::smallint[] AND convalidated)
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = identities_oid AND contype = 'u' AND conkey = ARRAY[3,4]::smallint[] AND convalidated)
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = identities_oid AND contype = 'f' AND conkey = ARRAY[2]::smallint[] AND confrelid = 'relay.projects'::regclass AND confkey = ARRAY[1]::smallint[] AND confupdtype = 'a' AND confdeltype = 'a' AND confmatchtype = 's' AND NOT condeferrable AND NOT condeferred AND convalidated)
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = identities_oid AND contype = 'f' AND conkey = ARRAY[5]::smallint[] AND confrelid = 'auth.principals'::regclass AND confkey = ARRAY[1]::smallint[] AND confupdtype = 'a' AND confdeltype = 'a' AND confmatchtype = 's' AND NOT condeferrable AND NOT condeferred AND convalidated)
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = identities_oid AND contype = 'c' AND conkey = ARRAY[3]::smallint[] AND convalidated AND pg_get_expr(conbin, conrelid) = '(kind = ANY (ARRAY[''local_git''::text, ''git_remote''::text, ''operator_alias''::text, ''workspace''::text]))')
    AND NOT EXISTS (
        SELECT 1 FROM (VALUES
            ('project_identities_locator_min_check', ARRAY[4]::smallint[], '(char_length(normalized_locator) >= 1)'),
            ('project_identities_locator_max_check', ARRAY[4]::smallint[], '(char_length(normalized_locator) <= 2048)'),
            ('project_identities_locator_bytes_check', ARRAY[4]::smallint[], '(octet_length(normalized_locator) <= 8192)'),
            ('project_identities_locator_control_check', ARRAY[4]::smallint[], '(normalized_locator !~ ''[[:cntrl:]]''::text)')
        ) AS expected(name, key, expression)
        WHERE NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = identities_oid AND conname = expected.name AND contype = 'c' AND conkey = expected.key AND convalidated AND pg_get_expr(conbin, conrelid) = expected.expression)
    )
    AND EXISTS (SELECT 1 FROM pg_index WHERE indexrelid = identities_project_oid AND indrelid = identities_oid AND NOT indisunique AND indisvalid AND indisready AND indnkeyatts = 2 AND indkey = '2 1'::int2vector AND indexprs IS NULL AND indpred IS NULL)
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = aliases_oid AND contype = 'p' AND conkey = ARRAY[1]::smallint[] AND convalidated)
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = aliases_oid AND conname = 'project_lookup_aliases_alias_project_id_fkey' AND contype = 'f' AND conkey = ARRAY[1]::smallint[] AND confrelid = 'relay.projects'::regclass AND confkey = ARRAY[1]::smallint[] AND confupdtype = 'a' AND confdeltype = 'a' AND confmatchtype = 's' AND NOT condeferrable AND NOT condeferred AND convalidated)
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = aliases_oid AND conname = 'project_lookup_aliases_canonical_project_id_fkey' AND contype = 'f' AND conkey = ARRAY[2]::smallint[] AND confrelid = 'relay.projects'::regclass AND confkey = ARRAY[1]::smallint[] AND confupdtype = 'a' AND confdeltype = 'a' AND confmatchtype = 's' AND NOT condeferrable AND NOT condeferred AND convalidated)
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = aliases_oid AND contype = 'c' AND conkey = ARRAY[1,2]::smallint[] AND convalidated AND pg_get_expr(conbin, conrelid) = '(alias_project_id <> canonical_project_id)')
    AND EXISTS (SELECT 1 FROM pg_index WHERE indexrelid = aliases_canonical_oid AND indrelid = aliases_oid AND NOT indisunique AND indisvalid AND indisready AND indnkeyatts = 2 AND indkey = '2 1'::int2vector AND indexprs IS NULL AND indpred IS NULL)
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = previews_oid AND contype = 'p' AND conkey = ARRAY[1]::smallint[] AND convalidated)
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = previews_oid AND conname = 'project_merge_previews_actor_principal_id_fkey' AND contype = 'f' AND conkey = ARRAY[2]::smallint[] AND confrelid = 'auth.principals'::regclass AND confkey = ARRAY[1]::smallint[] AND confupdtype = 'a' AND confdeltype = 'a' AND confmatchtype = 's' AND NOT condeferrable AND NOT condeferred AND convalidated)
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = previews_oid AND conname = 'project_merge_previews_source_project_id_fkey' AND contype = 'f' AND conkey = ARRAY[3]::smallint[] AND confrelid = 'relay.projects'::regclass AND confkey = ARRAY[1]::smallint[] AND confupdtype = 'a' AND confdeltype = 'a' AND confmatchtype = 's' AND NOT condeferrable AND NOT condeferred AND convalidated)
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = previews_oid AND conname = 'project_merge_previews_canonical_project_id_fkey' AND contype = 'f' AND conkey = ARRAY[4]::smallint[] AND confrelid = 'relay.projects'::regclass AND confkey = ARRAY[1]::smallint[] AND confupdtype = 'a' AND confdeltype = 'a' AND confmatchtype = 's' AND NOT condeferrable AND NOT condeferred AND convalidated)
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = previews_oid AND conname = 'project_merge_previews_identity_id_fkey' AND contype = 'f' AND conkey = ARRAY[5]::smallint[] AND confrelid = identities_oid AND confkey = ARRAY[1]::smallint[] AND confupdtype = 'a' AND confdeltype = 'a' AND confmatchtype = 's' AND NOT condeferrable AND NOT condeferred AND convalidated)
    AND NOT EXISTS (
        SELECT 1 FROM (VALUES
            ('project_merge_previews_source_identity_generation_check', ARRAY[6]::smallint[], '(source_identity_generation >= 0)'),
            ('project_merge_previews_source_acl_generation_check', ARRAY[7]::smallint[], '(source_acl_generation >= 0)'),
            ('project_merge_previews_source_content_generation_check', ARRAY[8]::smallint[], '(source_content_generation >= 0)'),
            ('project_merge_previews_canonical_identity_generation_check', ARRAY[9]::smallint[], '(canonical_identity_generation >= 0)'),
            ('project_merge_previews_canonical_acl_generation_check', ARRAY[10]::smallint[], '(canonical_acl_generation >= 0)'),
            ('project_merge_previews_canonical_content_generation_check', ARRAY[11]::smallint[], '(canonical_content_generation >= 0)'),
            ('project_merge_previews_global_acl_generation_check', ARRAY[12]::smallint[], '(global_acl_generation >= 0)'),
            ('project_merge_previews_identity_count_min_check', ARRAY[13]::smallint[], '(identity_count >= 1)'),
            ('project_merge_previews_identity_count_max_check', ARRAY[13]::smallint[], '(identity_count <= 100)'),
            ('project_merge_previews_grant_count_min_check', ARRAY[14]::smallint[], '(grant_count >= 0)'),
            ('project_merge_previews_grant_count_max_check', ARRAY[14]::smallint[], '(grant_count <= 1000)'),
            ('project_merge_previews_alias_count_min_check', ARRAY[15]::smallint[], '(alias_count >= 0)'),
            ('project_merge_previews_alias_count_max_check', ARRAY[15]::smallint[], '(alias_count <= 1000)'),
            ('project_merge_previews_new_principals_check', ARRAY[16]::smallint[], '(cardinality(newly_authorized_principal_ids) <= 256)'),
            ('project_merge_previews_private_count_min_check', ARRAY[17]::smallint[], '(private_record_count >= 0)'),
            ('project_merge_previews_private_count_max_check', ARRAY[17]::smallint[], '(private_record_count <= 1000)'),
            ('project_merge_previews_conflict_count_min_check', ARRAY[18]::smallint[], '(conflict_count >= 0)'),
            ('project_merge_previews_conflict_count_max_check', ARRAY[18]::smallint[], '(conflict_count <= 1000)'),
            ('project_merge_previews_result_check', ARRAY[21]::smallint[], '((result IS NULL) OR (octet_length((result)::text) <= 4096))'),
            ('project_merge_previews_distinct_projects_check', ARRAY[3,4]::smallint[], '(source_project_id <> canonical_project_id)'),
            ('project_merge_previews_expiry_check', ARRAY[19,22]::smallint[], '(expires_at > created_at)'),
            ('project_merge_previews_consumption_check', ARRAY[20,21]::smallint[], '(((consumed_at IS NULL) AND (result IS NULL)) OR ((consumed_at IS NOT NULL) AND (result IS NOT NULL)))'),
			('project_merge_previews_pending_enrollment_count_min_check', ARRAY[23]::smallint[], '(pending_enrollment_count >= 0)'),
			('project_merge_previews_pending_enrollment_count_max_check', ARRAY[23]::smallint[], '(pending_enrollment_count <= 1000)')
        ) AS expected(name, key, expression)
        WHERE NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = previews_oid AND conname = expected.name AND contype = 'c' AND conkey = expected.key AND convalidated AND pg_get_expr(conbin, conrelid) = expected.expression)
    )
    AND EXISTS (SELECT 1 FROM pg_index WHERE indexrelid = previews_live_actor_oid AND indrelid = previews_oid AND NOT indisunique AND indisvalid AND indisready AND indnkeyatts = 3 AND indkey = '2 19 1'::int2vector AND indexprs IS NULL AND pg_get_expr(indpred, indrelid) = '(consumed_at IS NULL)')
    AND EXISTS (SELECT 1 FROM pg_index WHERE indexrelid = previews_prune_oid AND indrelid = previews_oid AND NOT indisunique AND indisvalid AND indisready AND indnkeyatts = 2 AND indkey = '0 1'::int2vector AND pg_get_expr(indexprs, indrelid) = 'COALESCE(consumed_at, expires_at)' AND indpred IS NULL)
    AND has_table_privilege('punaro_app', acl_state_oid, 'SELECT')
    AND NOT has_table_privilege('punaro_app', acl_state_oid, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
    AND has_column_privilege('punaro_app', acl_state_oid, 'global_generation', 'UPDATE')
    AND NOT has_column_privilege('punaro_app', acl_state_oid, 'singleton', 'UPDATE')
    AND has_table_privilege('punaro_app', identities_oid, 'SELECT')
    AND NOT has_table_privilege('punaro_app', identities_oid, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
    AND NOT has_any_column_privilege('punaro_app', identities_oid, 'REFERENCES')
    AND NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = identities_oid AND attnum > 0 AND NOT attisdropped AND attname <> ALL (ARRAY['project_id','kind','normalized_locator','created_by']) AND has_column_privilege('punaro_app', identities_oid, attname, 'INSERT'))
    AND NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = identities_oid AND attnum > 0 AND NOT attisdropped AND attname <> 'project_id' AND has_column_privilege('punaro_app', identities_oid, attname, 'UPDATE'))
    AND has_column_privilege('punaro_app', identities_oid, 'project_id', 'INSERT,UPDATE')
    AND has_column_privilege('punaro_app', identities_oid, 'kind', 'INSERT')
    AND has_column_privilege('punaro_app', identities_oid, 'normalized_locator', 'INSERT')
    AND has_column_privilege('punaro_app', identities_oid, 'created_by', 'INSERT')
    AND has_table_privilege('punaro_app', aliases_oid, 'SELECT')
    AND NOT has_table_privilege('punaro_app', aliases_oid, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
    AND has_column_privilege('punaro_app', aliases_oid, 'alias_project_id', 'INSERT')
    AND has_column_privilege('punaro_app', aliases_oid, 'canonical_project_id', 'INSERT,UPDATE')
    AND NOT has_column_privilege('punaro_app', aliases_oid, 'alias_project_id', 'UPDATE')
    AND NOT has_column_privilege('punaro_app', aliases_oid, 'created_at', 'INSERT,UPDATE')
    AND has_table_privilege('punaro_app', previews_oid, 'SELECT,DELETE')
    AND NOT has_table_privilege('punaro_app', previews_oid, 'INSERT,UPDATE,TRUNCATE,REFERENCES,TRIGGER')
    AND has_column_privilege('punaro_app', previews_oid, 'consumed_at', 'UPDATE')
    AND has_column_privilege('punaro_app', previews_oid, 'result', 'UPDATE')
    AND NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = previews_oid AND attnum > 0 AND NOT attisdropped AND attname <> ALL (ARRAY['consumed_at','result']) AND has_column_privilege('punaro_app', previews_oid, attname, 'UPDATE'))
	AND NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = previews_oid AND attnum > 0 AND NOT attisdropped AND attname <> ALL (ARRAY['actor_principal_id','source_project_id','canonical_project_id','identity_id','source_identity_generation','source_acl_generation','source_content_generation','canonical_identity_generation','canonical_acl_generation','canonical_content_generation','global_acl_generation','identity_count','grant_count','alias_count','newly_authorized_principal_ids','expires_at','private_record_count','pending_enrollment_count']) AND has_column_privilege('punaro_app', previews_oid, attname, 'INSERT'))
	AND (SELECT count(*) = 18 FROM pg_attribute WHERE attrelid = previews_oid AND attnum > 0 AND NOT attisdropped AND attname = ANY (ARRAY['actor_principal_id','source_project_id','canonical_project_id','identity_id','source_identity_generation','source_acl_generation','source_content_generation','canonical_identity_generation','canonical_acl_generation','canonical_content_generation','global_acl_generation','identity_count','grant_count','alias_count','newly_authorized_principal_ids','expires_at','private_record_count','pending_enrollment_count']) AND has_column_privilege('punaro_app', previews_oid, attname, 'INSERT'))
    AND EXISTS (
        SELECT 1 FROM pg_attribute AS attribute
        JOIN pg_attrdef AS default_value ON default_value.adrelid = attribute.attrelid AND default_value.adnum = attribute.attnum
        WHERE attribute.attrelid = 'relay.projects'::regclass AND attribute.attname = 'identity_generation'
          AND attribute.attnotnull AND attribute.atttypid = 'bigint'::regtype AND pg_get_expr(default_value.adbin, default_value.adrelid) = '0'
    )
    AND (SELECT count(*) = 3 FROM pg_attribute AS attribute JOIN pg_attrdef AS default_value ON default_value.adrelid = attribute.attrelid AND default_value.adnum = attribute.attnum WHERE attribute.attrelid = 'relay.projects'::regclass AND attribute.attname = ANY (ARRAY['identity_generation','acl_generation','content_generation']) AND attribute.attnotnull AND attribute.atttypid = 'bigint'::regtype AND pg_get_expr(default_value.adbin, default_value.adrelid) = '0')
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'relay.projects'::regclass AND contype = 'c' AND conkey = ARRAY[5]::smallint[] AND convalidated AND pg_get_expr(conbin, conrelid) = '(identity_generation >= 0)')
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'relay.projects'::regclass AND contype = 'c' AND conkey = ARRAY[6]::smallint[] AND convalidated AND pg_get_expr(conbin, conrelid) = '(acl_generation >= 0)')
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'relay.projects'::regclass AND contype = 'c' AND conkey = ARRAY[7]::smallint[] AND convalidated AND pg_get_expr(conbin, conrelid) = '(content_generation >= 0)')
    AND NOT has_table_privilege('punaro_app', 'relay.projects', 'UPDATE')
    AND NOT has_table_privilege('punaro_app', 'relay.projects', 'INSERT')
    AND has_column_privilege('punaro_app', 'relay.projects', 'display_name', 'INSERT')
    AND has_column_privilege('punaro_app', 'relay.projects', 'created_by', 'INSERT')
    AND NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = 'relay.projects'::regclass AND attnum > 0 AND NOT attisdropped AND attname <> ALL (ARRAY['display_name','created_by']) AND has_column_privilege('punaro_app', 'relay.projects', attname, 'INSERT'))
    AND NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = 'relay.projects'::regclass AND attnum > 0 AND NOT attisdropped AND attname <> ALL (ARRAY['identity_generation','acl_generation','content_generation','merged_into','merged_at']) AND has_column_privilege('punaro_app', 'relay.projects', attname, 'UPDATE'))
    AND has_column_privilege('punaro_app', 'relay.projects', 'identity_generation', 'UPDATE')
    AND has_column_privilege('punaro_app', 'relay.projects', 'acl_generation', 'UPDATE')
    AND has_column_privilege('punaro_app', 'relay.projects', 'content_generation', 'UPDATE')
    AND has_column_privilege('punaro_app', 'relay.projects', 'merged_into', 'UPDATE')
    AND has_column_privilege('punaro_app', 'relay.projects', 'merged_at', 'UPDATE')
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'relay.projects'::regclass AND contype = 'f' AND conkey = ARRAY[8]::smallint[] AND confrelid = 'relay.projects'::regclass AND confkey = ARRAY[1]::smallint[] AND confupdtype = 'a' AND confdeltype = 'a' AND confmatchtype = 's' AND NOT condeferrable AND NOT condeferred AND convalidated)
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'relay.projects'::regclass AND contype = 'c' AND conkey = ARRAY[8,9]::smallint[] AND convalidated AND pg_get_expr(conbin, conrelid) = '((merged_into IS NULL) = (merged_at IS NULL))')
    AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'relay.projects'::regclass AND contype = 'c' AND conkey = ARRAY[8,1]::smallint[] AND convalidated AND pg_get_expr(conbin, conrelid) = '((merged_into IS NULL) OR (merged_into <> id))')
FROM objects, ownership`).Scan(&identityObjectsPresent); err != nil {
			return Snapshot{}, errors.New("PostgreSQL project-identity schema cannot be inspected")
		}
		snapshot.CurrentObjectsPresent = identityObjectsPresent
	}
	if snapshot.CurrentObjectsPresent && len(snapshot.Records) > 0 && snapshot.Records[len(snapshot.Records)-1].Version >= 5 {
		var backupObjectsPresent bool
		if err := q.QueryRowContext(ctx, `
WITH objects AS (
    SELECT to_regnamespace('attachment') AS attachment_namespace_oid,
           to_regclass('attachment.ready_blob_manifest') AS ready_oid,
           to_regclass('jobs.backup_gc_fences') AS fences_oid,
           to_regclass('jobs.restore_events') AS restores_oid,
           to_regclass('jobs.backup_gc_fences_active') AS active_index_oid,
           to_regprocedure('jobs.acquire_backup_gc_fence(interval)') AS acquire_oid,
           to_regprocedure('jobs.bind_backup_snapshot(uuid,text)') AS bind_oid,
		   to_regprocedure('jobs.renew_backup_gc_fence(uuid,text,interval)') AS renew_oid,
		   to_regprocedure('jobs.cancel_unbound_backup_gc_fence(uuid)') AS cancel_oid,
           to_regprocedure('jobs.release_backup_gc_fence(uuid,text,boolean)') AS release_oid,
           to_regprocedure('jobs.physical_blob_gc_permitted()') AS gc_oid,
           to_regprocedure('jobs.rotate_restored_timeline(uuid,uuid,uuid,bigint)') AS rotate_oid
), table_ownership AS (
    SELECT count(*) = 3 AND bool_and(pg_get_userbyid(relowner) = 'punaro_owner') AS owned
    FROM pg_class, objects WHERE oid = ANY(ARRAY[ready_oid, fences_oid, restores_oid])
), routine_expected(oid, body_hash, language_name, volatility, security_definer, result_type) AS (
	SELECT expected.* FROM objects, LATERAL (VALUES
		(acquire_oid, 'f6929fb868a6ecf26876141eba7c6225', 'plpgsql', 'v'::"char", true, 'uuid'),
		(bind_oid, '7cd70c2bf1e678bf0e9457759ddd69d2', 'sql', 'v'::"char", true, 'boolean'),
		(renew_oid, '2b86effb929fb20879f101e761d8fb6b', 'plpgsql', 'v'::"char", true, 'boolean'),
		(cancel_oid, 'bfbe9c5f6f92a230acd0ff519167b60a', 'sql', 'v'::"char", true, 'boolean'),
		(release_oid, 'bcbf6a051343bc3a368c986ae799a1ef', 'sql', 'v'::"char", true, 'boolean'),
		(gc_oid, '73e11885930565575ee1c496b16749d7', 'sql', 's'::"char", true, 'boolean'),
		(rotate_oid, 'bacc5a1a2184a80240f570b8624535ea', 'plpgsql', 'v'::"char", false, 'TABLE(installation_id uuid, timeline_id uuid, change_sequence bigint)')
	) AS expected(oid, body_hash, language_name, volatility, security_definer, result_type)
), routine_safety AS (
	SELECT count(*) = 7
	   AND bool_and(pg_get_userbyid(proc.proowner) = 'punaro_owner')
	   AND bool_and(COALESCE(proc.proconfig = ARRAY['search_path=pg_catalog']::text[], false))
	   AND bool_and(md5(btrim(proc.prosrc)) = expected.body_hash)
	   AND bool_and(language.lanname = expected.language_name)
	   AND bool_and(proc.provolatile = expected.volatility)
	   AND bool_and(proc.prosecdef = expected.security_definer)
	   AND bool_and(proc.prokind = 'f' AND pg_get_function_result(proc.oid) = expected.result_type) AS safe
	FROM routine_expected AS expected
	JOIN pg_proc AS proc ON proc.oid = expected.oid
	JOIN pg_language AS language ON language.oid = proc.prolang
), routine_acl AS (
	SELECT count(*) = 8
	   AND bool_and(acl.privilege_type = 'EXECUTE' AND NOT acl.is_grantable)
	   AND bool_and(grantee.rolname = 'punaro_owner' OR (grantee.rolname = 'punaro_app' AND proc.oid = objects.gc_oid)) AS exact
	FROM objects
	JOIN pg_proc AS proc ON proc.oid = ANY(ARRAY[acquire_oid, bind_oid, renew_oid, cancel_oid, release_oid, gc_oid, rotate_oid])
	CROSS JOIN LATERAL aclexplode(COALESCE(proc.proacl, acldefault('f', proc.proowner))) AS acl
	LEFT JOIN pg_roles AS grantee ON grantee.oid = acl.grantee
), table_acl AS (
	SELECT count(*) = 25
	   AND bool_and(NOT acl.is_grantable)
	   AND bool_and(grantee.rolname = 'punaro_owner' OR (grantee.rolname = 'punaro_app' AND relation.oid = objects.ready_oid AND acl.privilege_type = 'SELECT')) AS exact
	FROM objects
	JOIN pg_class AS relation ON relation.oid = ANY(ARRAY[ready_oid, fences_oid, restores_oid])
	CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl, acldefault('r', relation.relowner))) AS acl
	LEFT JOIN pg_roles AS grantee ON grantee.oid = acl.grantee
), schema_acl AS (
	SELECT count(*) = 3
	   AND bool_and(pg_get_userbyid(namespace.nspowner) = 'punaro_owner')
	   AND bool_and(NOT acl.is_grantable)
	   AND bool_and(grantee.rolname = 'punaro_owner'
	       OR (grantee.rolname = 'punaro_app' AND acl.privilege_type = 'USAGE')) AS exact
	FROM objects
	JOIN pg_namespace AS namespace ON namespace.oid = objects.attachment_namespace_oid
	CROSS JOIN LATERAL aclexplode(COALESCE(namespace.nspacl, acldefault('n', namespace.nspowner))) AS acl
	LEFT JOIN pg_roles AS grantee ON grantee.oid = acl.grantee
), column_expected(relation_oid, column_name, type_oid, type_modifier, required, default_expression) AS (
	SELECT expected.* FROM objects, LATERAL (VALUES
		(ready_oid, 'storage_path', 'text'::regtype, -1, true, ''),
		(ready_oid, 'size_bytes', 'bigint'::regtype, -1, true, ''),
		(ready_oid, 'sha256', 'character'::regtype, 68, true, ''),
		(ready_oid, 'ready_at', 'timestamptz'::regtype, -1, true, 'statement_timestamp()'),
		(fences_oid, 'fence_id', 'uuid'::regtype, -1, true, ''),
		(fences_oid, 'installation_id', 'uuid'::regtype, -1, true, ''),
		(fences_oid, 'timeline_id', 'uuid'::regtype, -1, true, ''),
		(fences_oid, 'snapshot_id', 'text'::regtype, -1, false, ''),
		(fences_oid, 'acquired_at', 'timestamptz'::regtype, -1, true, 'statement_timestamp()'),
		(fences_oid, 'expires_at', 'timestamptz'::regtype, -1, true, ''),
		(fences_oid, 'released_at', 'timestamptz'::regtype, -1, false, ''),
		(fences_oid, 'verified', 'boolean'::regtype, -1, false, ''),
		(restores_oid, 'restore_id', 'uuid'::regtype, -1, true, ''),
		(restores_oid, 'backup_id', 'uuid'::regtype, -1, true, ''),
		(restores_oid, 'installation_id', 'uuid'::regtype, -1, true, ''),
		(restores_oid, 'previous_timeline_id', 'uuid'::regtype, -1, true, ''),
		(restores_oid, 'restored_timeline_id', 'uuid'::regtype, -1, true, ''),
		(restores_oid, 'restored_change_sequence', 'bigint'::regtype, -1, true, ''),
		(restores_oid, 'restored_at', 'timestamptz'::regtype, -1, true, 'statement_timestamp()')
	) AS expected(relation_oid, column_name, type_oid, type_modifier, required, default_expression)
), column_safety AS (
	SELECT count(*) = 19
	   AND bool_and(attribute.atttypid = expected.type_oid AND attribute.atttypmod = expected.type_modifier
	       AND attribute.attnotnull = expected.required
	       AND COALESCE(pg_get_expr(default_value.adbin, default_value.adrelid), '') = expected.default_expression)
	   AND (SELECT count(*) = 19 FROM pg_attribute, objects
	        WHERE attrelid = ANY(ARRAY[ready_oid, fences_oid, restores_oid]) AND attnum > 0 AND NOT attisdropped) AS exact
	FROM column_expected AS expected
	JOIN pg_attribute AS attribute ON attribute.attrelid = expected.relation_oid AND attribute.attname = expected.column_name AND attribute.attnum > 0 AND NOT attribute.attisdropped
	LEFT JOIN pg_attrdef AS default_value ON default_value.adrelid = attribute.attrelid AND default_value.adnum = attribute.attnum
)
SELECT attachment_namespace_oid IS NOT NULL AND ready_oid IS NOT NULL AND fences_oid IS NOT NULL AND restores_oid IS NOT NULL
	   AND active_index_oid IS NOT NULL AND acquire_oid IS NOT NULL AND bind_oid IS NOT NULL
	   AND renew_oid IS NOT NULL AND cancel_oid IS NOT NULL AND release_oid IS NOT NULL AND gc_oid IS NOT NULL AND rotate_oid IS NOT NULL
   AND table_ownership.owned AND routine_safety.safe AND routine_acl.exact AND table_acl.exact AND schema_acl.exact AND column_safety.exact
	AND (SELECT index.indisunique AND index.indisvalid AND index.indisready AND index.indnkeyatts = 1 AND index.indnatts = 1
		AND index.indrelid = fences_oid AND index.indkey::text = '2' AND index.indexprs IS NULL AND pg_get_expr(index.indpred, index.indrelid) = '(released_at IS NULL)'
		FROM pg_index AS index WHERE index.indexrelid = active_index_oid)
   AND (SELECT count(*) = 1 FROM pg_constraint WHERE conrelid = ready_oid AND contype = 'p' AND conkey = ARRAY[1]::smallint[] AND convalidated)
   AND (SELECT count(*) = 1 FROM pg_constraint WHERE conrelid = ready_oid AND contype = 'u' AND conkey = ARRAY[3]::smallint[] AND convalidated)
   AND (SELECT count(*) = 1 FROM pg_constraint WHERE conrelid = fences_oid AND contype = 'p' AND conkey = ARRAY[1]::smallint[] AND convalidated)
   AND (SELECT count(*) = 1 FROM pg_constraint WHERE conrelid = restores_oid AND contype = 'p' AND conkey = ARRAY[1]::smallint[] AND convalidated)
	AND (SELECT count(*) = 1 FROM pg_constraint WHERE conrelid = restores_oid AND contype = 'u' AND conkey = ARRAY[2]::smallint[] AND convalidated)
   AND (SELECT count(*) = 1 FROM pg_constraint WHERE conrelid = restores_oid AND contype = 'u' AND conkey = ARRAY[5]::smallint[] AND convalidated)
	AND (SELECT count(*) = 3 FROM pg_constraint WHERE conrelid = ready_oid AND contype = 'c' AND convalidated)
	AND NOT EXISTS (
		SELECT 1 FROM (VALUES
			(ARRAY[2]::smallint[], '((size_bytes >= 0) AND (size_bytes <= ''17179869184''::bigint))'),
			(ARRAY[3]::smallint[], '(sha256 ~ ''^[0-9a-f]{64}$''::text)'),
			(ARRAY[1]::smallint[], '((storage_path <> ''''::text) AND (char_length(storage_path) <= 1024) AND (octet_length(storage_path) <= 4096) AND (storage_path !~ ''[[:cntrl:]]''::text) AND (storage_path !~ ''(^|/)\.\.?(/|$)''::text) AND (storage_path !~ ''^/''::text) AND (storage_path !~ ''\\''::text))')
		) AS expected(key, expression)
		WHERE NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = ready_oid AND contype = 'c' AND conkey = expected.key AND convalidated AND pg_get_expr(conbin, conrelid) = expected.expression)
	)
	AND (SELECT count(*) = 4 FROM pg_constraint WHERE conrelid = fences_oid AND contype = 'c' AND convalidated)
	AND NOT EXISTS (
		-- PostgreSQL 18 pg_dump/pg_restore flattens the associative AND terms in
		-- snapshot_id's parse tree; accept only the migrated and restored forms.
		SELECT 1 FROM (VALUES
			(ARRAY[5,6]::smallint[], '(expires_at > acquired_at)', '(expires_at > acquired_at)'),
			(ARRAY[4]::smallint[], '((snapshot_id IS NULL) OR (((char_length(snapshot_id) >= 1) AND (char_length(snapshot_id) <= 200)) AND (snapshot_id ~ ''^[0-9A-Z-]+$''::text)))', '((snapshot_id IS NULL) OR ((char_length(snapshot_id) >= 1) AND (char_length(snapshot_id) <= 200) AND (snapshot_id ~ ''^[0-9A-Z-]+$''::text)))'),
			(ARRAY[7,8]::smallint[], '((released_at IS NULL) = (verified IS NULL))', '((released_at IS NULL) = (verified IS NULL))'),
			(ARRAY[5,7]::smallint[], '((released_at IS NULL) OR (released_at >= acquired_at))', '((released_at IS NULL) OR (released_at >= acquired_at))')
		) AS expected(key, migration_expression, restored_expression)
		WHERE NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = fences_oid AND contype = 'c' AND conkey @> expected.key AND conkey <@ expected.key AND convalidated AND pg_get_expr(conbin, conrelid) IN (expected.migration_expression, expected.restored_expression))
	)
	AND (SELECT count(*) = 2 FROM pg_constraint WHERE conrelid = restores_oid AND contype = 'c' AND convalidated)
	AND NOT EXISTS (
		SELECT 1 FROM (VALUES
			(ARRAY[6]::smallint[], '(restored_change_sequence >= 0)'),
			(ARRAY[4,5]::smallint[], '(previous_timeline_id <> restored_timeline_id)')
		) AS expected(key, expression)
		WHERE NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = restores_oid AND contype = 'c' AND conkey @> expected.key AND conkey <@ expected.key AND convalidated AND pg_get_expr(conbin, conrelid) = expected.expression)
	)
   AND has_table_privilege('punaro_app', ready_oid, 'SELECT')
   AND NOT has_table_privilege('punaro_app', ready_oid, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
   AND NOT has_any_column_privilege('punaro_app', ready_oid, 'INSERT,UPDATE,REFERENCES')
   AND NOT has_table_privilege('punaro_app', fences_oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
   AND NOT has_any_column_privilege('punaro_app', fences_oid, 'INSERT,UPDATE,REFERENCES')
   AND NOT has_table_privilege('punaro_app', restores_oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
   AND NOT has_any_column_privilege('punaro_app', restores_oid, 'INSERT,UPDATE,REFERENCES')
	AND NOT has_function_privilege('punaro_app', acquire_oid, 'EXECUTE')
	AND NOT has_function_privilege('punaro_app', bind_oid, 'EXECUTE')
	AND NOT has_function_privilege('punaro_app', renew_oid, 'EXECUTE')
	AND NOT has_function_privilege('punaro_app', cancel_oid, 'EXECUTE')
	AND NOT has_function_privilege('punaro_app', release_oid, 'EXECUTE')
   AND has_function_privilege('punaro_app', gc_oid, 'EXECUTE')
   AND NOT has_function_privilege('punaro_app', rotate_oid, 'EXECUTE')
FROM objects, table_ownership, routine_safety, routine_acl, table_acl, schema_acl, column_safety`).Scan(&backupObjectsPresent); err != nil {
			return Snapshot{}, errors.New("PostgreSQL backup schema cannot be inspected")
		}
		snapshot.CurrentObjectsPresent = backupObjectsPresent
	}
	if snapshot.CurrentObjectsPresent && len(snapshot.Records) > 0 && snapshot.Records[len(snapshot.Records)-1].Version >= 6 {
		updateObjectsPresent, err := updateControlsAvailable(ctx, q)
		if err != nil {
			return Snapshot{}, errors.New("PostgreSQL update-control schema cannot be inspected")
		}
		snapshot.CurrentObjectsPresent = updateObjectsPresent
	}
	if snapshot.CurrentObjectsPresent && len(snapshot.Records) > 0 && snapshot.Records[len(snapshot.Records)-1].Version >= 7 {
		relayObjectsPresent, err := relayControlsAvailable(ctx, q)
		if err != nil {
			return Snapshot{}, errors.New("PostgreSQL relay schema cannot be inspected")
		}
		snapshot.CurrentObjectsPresent = relayObjectsPresent
	}
	if snapshot.CurrentObjectsPresent && len(snapshot.Records) > 0 && snapshot.Records[len(snapshot.Records)-1].Version >= 8 {
		cutoverObjectsPresent, err := mailCutoverControlsAvailable(ctx, q)
		if err != nil {
			return Snapshot{}, errors.New("PostgreSQL mail-cutover schema cannot be inspected")
		}
		snapshot.CurrentObjectsPresent = cutoverObjectsPresent
	}
	return snapshot, nil
}

func verifyApplicationRole(ctx context.Context, db queryer) error {
	var isApplicationRole, unsafeAttributes, canCreateDatabaseObjects, canCreatePublicObjects, canAssumeOtherRole, ownsPersistentObjects, defaultWritable, primary bool
	if err := db.QueryRowContext(ctx, `
SELECT session_user = current_user AND current_user = 'punaro_app',
       EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_user AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls OR rolinherit OR NOT rolcanlogin)),
       has_database_privilege(current_user, current_database(), 'CREATE'),
       has_schema_privilege(current_user, 'public', 'CREATE'),
       EXISTS (SELECT 1 FROM pg_roles WHERE rolname <> current_user AND pg_has_role(current_user, oid, 'MEMBER')),
       EXISTS (
           SELECT 1 FROM pg_roles AS app
           WHERE app.rolname = current_user AND (
               EXISTS (SELECT 1 FROM pg_shdepend WHERE refclassid = 'pg_authid'::regclass AND refobjid = app.oid AND deptype = 'o')
               OR
               EXISTS (SELECT 1 FROM pg_namespace WHERE nspname !~ '^pg_' AND nspname <> 'information_schema' AND nspowner = app.oid)
               OR EXISTS (SELECT 1 FROM pg_class AS object JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace WHERE namespace.nspname !~ '^pg_' AND namespace.nspname <> 'information_schema' AND object.relowner = app.oid)
               OR EXISTS (SELECT 1 FROM pg_proc AS object JOIN pg_namespace AS namespace ON namespace.oid = object.pronamespace WHERE namespace.nspname !~ '^pg_' AND namespace.nspname <> 'information_schema' AND object.proowner = app.oid)
           )
       ),
       current_setting('default_transaction_read_only') = 'off',
       NOT pg_is_in_recovery()`).Scan(&isApplicationRole, &unsafeAttributes, &canCreateDatabaseObjects, &canCreatePublicObjects, &canAssumeOtherRole, &ownsPersistentObjects, &defaultWritable, &primary); err != nil {
		return errors.New("PostgreSQL application role cannot be verified")
	}
	if !isApplicationRole || unsafeAttributes || canCreateDatabaseObjects || canCreatePublicObjects || canAssumeOtherRole || ownsPersistentObjects || !defaultWritable || !primary {
		return errors.New("PostgreSQL application role has forbidden DDL authority")
	}
	rows, err := db.QueryContext(ctx, `SELECT has_schema_privilege(current_user, oid, 'CREATE') FROM pg_namespace WHERE nspname !~ '^pg_' AND nspname <> 'information_schema'`)
	if err != nil {
		return errors.New("PostgreSQL application role cannot be verified")
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var canCreate bool
		if err := rows.Scan(&canCreate); err != nil {
			return errors.New("PostgreSQL application role cannot be verified")
		}
		if canCreate {
			return errors.New("PostgreSQL application role has forbidden DDL authority")
		}
	}
	if err := rows.Err(); err != nil {
		return errors.New("PostgreSQL application role cannot be verified")
	}
	return nil
}

func contentFreeMigrationError(classification Classification) error {
	return fmt.Errorf("PostgreSQL migration refused: schema is %s", classification)
}
