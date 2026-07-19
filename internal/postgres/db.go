package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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
	return &Database{db: db, manifest: CurrentManifest()}, nil
}

func open(ctx context.Context, dsn string) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, errors.New("PostgreSQL connection configuration is invalid")
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(2)
	pingCtx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, errors.New("PostgreSQL is unavailable")
	}
	return db, nil
}

// Close releases the application connection pool.
func (d *Database) Close() error { return d.db.Close() }

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

// AdvanceChange atomically increments and returns the global change sequence.
func (d *Database) AdvanceChange(ctx context.Context) (InstallationState, error) {
	var state InstallationState
	err := d.db.QueryRowContext(ctx, `SELECT installation_id::text, timeline_id::text, change_sequence FROM jobs.advance_change_sequence()`).Scan(&state.InstallationID, &state.TimelineID, &state.ChangeSequence)
	if err != nil {
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
       AND bool_and(proconfig = ARRAY['search_path=pg_catalog']::text[])
       AND bool_and(
           (oid = guard_oid AND md5(btrim(prosrc)) = '41e8a2a4da5bd7808324e6d578683255')
           OR (oid = audit_prune_oid AND md5(btrim(prosrc)) = '3d2f09c73e6a7be1c16e7430482ed6ea')
           OR (oid = jobs_prune_oid AND md5(btrim(prosrc)) = 'db608e8aa6217526decd4ff30635c134')
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
    AND has_table_privilege('punaro_app', projects_oid, 'INSERT')
    AND has_table_privilege('punaro_app', projects_oid, 'UPDATE')
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
FROM objects, ownership, function_ownership`).Scan(&snapshot.CurrentObjectsPresent); err != nil {
			return Snapshot{}, errors.New("PostgreSQL control-plane schema cannot be inspected")
		}
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
