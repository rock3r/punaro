package postgres

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

const minimumSupportedPostgresMajor = 14
const updateCoordinatorLockKey int64 = 579001230607

var (
	updateReleasePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	updateImagePattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9./_:-]*@sha256:[0-9a-f]{64}$`)
	updateDigestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	updateSnapshotPattern = regexp.MustCompile(`^[0-9A-Z-]{1,200}$`)
	updateHashPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)

	// ErrMaintenance is retryable: the mutation was rejected before acknowledgement.
	ErrMaintenance = errors.New("installation is in maintenance mode; retry later")
	// ErrUpdateConflict reports a different durable update already owning the fence.
	ErrUpdateConflict = errors.New("another update transaction owns the maintenance fence")
	// ErrInvalidUpdateTransition reports a fail-closed update state transition.
	ErrInvalidUpdateTransition = errors.New("update phase transition is invalid")
)

// UpdatePhase is the durable, content-free phase of one update transaction.
type UpdatePhase string

const (
	// UpdateFenced is the first durable phase after all earlier writers drain.
	UpdateFenced UpdatePhase = "fenced"
	// UpdateWritersStopped records proof that configured writers are stopped.
	UpdateWritersStopped UpdatePhase = "writers_stopped"
	// UpdateBackupVerified records the exact pre-update recovery point.
	UpdateBackupVerified UpdatePhase = "backup_verified"
	// UpdateMigrationStarted is the irreversible migration boundary.
	UpdateMigrationStarted UpdatePhase = "migration_started"
	// UpdateMigrated records successful target-schema migration.
	UpdateMigrated UpdatePhase = "migrated"
	// UpdateCandidateReady records deep readiness of the fenced target.
	UpdateCandidateReady UpdatePhase = "candidate_ready"
	// UpdateDoctorPassed records the target's non-mutating doctor result.
	UpdateDoctorPassed UpdatePhase = "doctor_passed"
	// UpdateConfigPublished records marker-last target publication.
	UpdateConfigPublished UpdatePhase = "config_published"
	// UpdateRecoveryRequired keeps an unsuccessful migrated update fenced.
	UpdateRecoveryRequired UpdatePhase = "recovery_required"
	// UpdateRecoveryReady records readiness of the selected recovery image.
	UpdateRecoveryReady UpdatePhase = "recovery_ready"
	// UpdateRecoveryDoctor records the recovery doctor result.
	UpdateRecoveryDoctor UpdatePhase = "recovery_doctor_passed"
	// UpdateRecoveryConfig records recovery configuration publication.
	UpdateRecoveryConfig UpdatePhase = "recovery_config_published"
	// UpdateCommitted is a successful target terminal outcome.
	UpdateCommitted UpdatePhase = "committed"
	// UpdateRecovered is a successful rollback terminal outcome.
	UpdateRecovered UpdatePhase = "recovered"
	// UpdateAborted is a pre-migration terminal outcome.
	UpdateAborted UpdatePhase = "aborted"
)

// UpdateRequest immutably identifies the source and target update boundary.
type UpdateRequest struct {
	UpdateID                string
	SourceRelease           string
	TargetRelease           string
	SourceImage             string
	TargetImage             string
	SourceSchema            int64
	TargetSchema            int64
	SchemaMin               int64
	SchemaMax               int64
	RollbackFloor           int64
	PostgresMajor           int
	ReleaseSHA256           string
	ComposeSHA256           string
	MigrationManifestSHA256 string
}

// Validate rejects a request that is not a complete immutable update boundary.
func (r UpdateRequest) Validate() error {
	if uuid.Validate(r.UpdateID) != nil || !updateReleasePattern.MatchString(r.SourceRelease) || !updateReleasePattern.MatchString(r.TargetRelease) || r.SourceRelease == r.TargetRelease || !updateImagePattern.MatchString(r.SourceImage) || !updateImagePattern.MatchString(r.TargetImage) || r.SourceImage == r.TargetImage || r.SourceSchema < 1 || r.SchemaMin < 1 || r.SchemaMax < r.SchemaMin || r.TargetSchema < r.SourceSchema || r.TargetSchema < r.SchemaMin || r.TargetSchema > r.SchemaMax || r.SourceSchema < r.SchemaMin || r.SourceSchema > r.TargetSchema || r.RollbackFloor < r.SchemaMin || r.RollbackFloor > r.TargetSchema || r.PostgresMajor < minimumSupportedPostgresMajor || !updateHashPattern.MatchString(r.ReleaseSHA256) || !updateHashPattern.MatchString(r.ComposeSHA256) || !updateHashPattern.MatchString(r.MigrationManifestSHA256) {
		return errors.New("invalid update request")
	}
	return nil
}

// UpdateBackupMarker binds recovery to one exact verified snapshot boundary.
type UpdateBackupMarker struct {
	UpdateID           string
	BackupID           string
	InstallationID     string
	TimelineID         string
	ChangeSequence     int64
	SourceSchema       int64
	TargetRelease      string
	TargetImageDigest  string
	ExportedSnapshotID string
	ManifestSHA256     string
}

// Validate rejects an incomplete or noncanonical backup binding.
func (m UpdateBackupMarker) Validate() error {
	if uuid.Validate(m.UpdateID) != nil || uuid.Validate(m.BackupID) != nil || uuid.Validate(m.InstallationID) != nil || uuid.Validate(m.TimelineID) != nil || m.ChangeSequence < 0 || m.SourceSchema < 1 || !updateReleasePattern.MatchString(m.TargetRelease) || !updateDigestPattern.MatchString(m.TargetImageDigest) || !updateSnapshotPattern.MatchString(m.ExportedSnapshotID) || !updateHashPattern.MatchString(m.ManifestSHA256) {
		return errors.New("invalid update backup marker")
	}
	return nil
}

// UpdateTransaction is the resumable owner-side view. It contains no secrets.
type UpdateTransaction struct {
	UpdateRequest
	Phase                UpdatePhase
	BackupID             string
	BackupInstallationID string
	BackupTimelineID     string
	BackupChangeSequence int64
	BackupSourceSchema   int64
	BackupSnapshotID     string
	BackupManifestSHA256 string
}

const updateSelectColumns = `update_id::text,source_release,target_release,source_image,target_image,source_schema,target_schema,schema_min,schema_max,rollback_floor,postgres_major,release_sha256,compose_sha256,migration_manifest_sha256,phase,COALESCE(backup_id::text,''),COALESCE(backup_installation_id::text,''),COALESCE(backup_timeline_id::text,''),COALESCE(backup_change_sequence,0),COALESCE(backup_source_schema,0),COALESCE(backup_snapshot_id,''),COALESCE(backup_manifest_sha256::text,'')`

type rowScanner interface{ Scan(...any) error }

func scanUpdate(row rowScanner) (UpdateTransaction, error) {
	var transaction UpdateTransaction
	err := row.Scan(&transaction.UpdateID, &transaction.SourceRelease, &transaction.TargetRelease, &transaction.SourceImage, &transaction.TargetImage, &transaction.SourceSchema, &transaction.TargetSchema, &transaction.SchemaMin, &transaction.SchemaMax, &transaction.RollbackFloor, &transaction.PostgresMajor, &transaction.ReleaseSHA256, &transaction.ComposeSHA256, &transaction.MigrationManifestSHA256, &transaction.Phase, &transaction.BackupID, &transaction.BackupInstallationID, &transaction.BackupTimelineID, &transaction.BackupChangeSequence, &transaction.BackupSourceSchema, &transaction.BackupSnapshotID, &transaction.BackupManifestSHA256)
	return transaction, err
}

// UpdateMigrationAuthorization is the exact durable evidence a one-shot owner
// migrator must match before it may touch an existing schema.
type UpdateMigrationAuthorization struct {
	UpdateID           string
	BackupID           string
	TargetRelease      string
	TargetImage        string
	TargetSchema       int64
	ExportedSnapshotID string
	ManifestSHA256     string
}

// Validate rejects migration authority that is not bound to an exact update.
func (authorization UpdateMigrationAuthorization) Validate() error {
	if uuid.Validate(authorization.UpdateID) != nil || uuid.Validate(authorization.BackupID) != nil || !updateReleasePattern.MatchString(authorization.TargetRelease) || !updateImagePattern.MatchString(authorization.TargetImage) || authorization.TargetSchema < 1 || !updateSnapshotPattern.MatchString(authorization.ExportedSnapshotID) || !updateHashPattern.MatchString(authorization.ManifestSHA256) {
		return errors.New("invalid update migration authorization")
	}
	return nil
}

func validateUpdateTransition(from, to UpdatePhase) error {
	allowed := map[UpdatePhase]map[UpdatePhase]bool{
		UpdateFenced:           {UpdateWritersStopped: true, UpdateAborted: true},
		UpdateWritersStopped:   {UpdateBackupVerified: true, UpdateAborted: true},
		UpdateBackupVerified:   {UpdateMigrationStarted: true, UpdateAborted: true},
		UpdateMigrationStarted: {UpdateMigrated: true, UpdateRecoveryRequired: true},
		UpdateMigrated:         {UpdateCandidateReady: true, UpdateRecoveryRequired: true},
		UpdateCandidateReady:   {UpdateDoctorPassed: true, UpdateRecoveryRequired: true},
		UpdateDoctorPassed:     {UpdateConfigPublished: true, UpdateRecoveryRequired: true},
		UpdateConfigPublished:  {UpdateCommitted: true},
		UpdateRecoveryRequired: {UpdateRecoveryReady: true},
		UpdateRecoveryReady:    {UpdateRecoveryDoctor: true},
		UpdateRecoveryDoctor:   {UpdateRecoveryConfig: true},
		UpdateRecoveryConfig:   {UpdateRecovered: true},
	}
	if !allowed[from][to] {
		return ErrInvalidUpdateTransition
	}
	return nil
}

func guardMutation(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `SELECT jobs.assert_application_mutation()`); err != nil {
		if isMaintenanceError(err) {
			return ErrMaintenance
		}
		return errors.New("mutation maintenance gate is unavailable")
	}
	return nil
}

// MaintenanceActive reports whether an unfinished update transaction owns the
// installation write fence. It is safe for the application role to inspect.
func (d *Database) MaintenanceActive(ctx context.Context) (bool, error) {
	var active bool
	if err := d.db.QueryRowContext(ctx, `SELECT jobs.maintenance_active()`).Scan(&active); err != nil {
		return false, errors.New("maintenance state is unavailable")
	}
	return active, nil
}

func beginMutation(ctx context.Context, database *sql.DB) (*sql.Tx, error) {
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if err := guardMutation(ctx, tx); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func mutationStartError(err error, fallback string) error {
	if errors.Is(err, ErrMaintenance) {
		return ErrMaintenance
	}
	return errors.New(fallback)
}

func isMaintenanceError(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) && postgresError.Code == "55P03" && postgresError.Message == "punaro maintenance in progress"
}

const updateControlsInspectionSQL = `
WITH objects AS (
    SELECT to_regclass('jobs.update_transactions') AS updates_oid,
           to_regclass('jobs.update_transactions_one_active') AS active_index_oid,
           to_regprocedure('jobs.assert_application_mutation()') AS assert_oid,
           to_regprocedure('jobs.guard_application_mutation()') AS guard_oid,
		   to_regprocedure('jobs.begin_update(uuid,text,text,text,text,bigint,bigint,bigint,bigint,bigint,integer,text,text,text)') AS begin_oid,
		   to_regprocedure('jobs.advance_update(uuid,text,text,uuid,uuid,uuid,bigint,bigint,text,text,text,text)') AS advance_oid,
			   to_regprocedure('jobs.restore_update_recovery(uuid,uuid,uuid,uuid,bigint,bigint,text,text,text,text)') AS restore_oid,
	           to_regprocedure('jobs.maintenance_active()') AS active_oid
	), expected_routines(oid, body_hash, language_name, volatility, result_type) AS (
	    SELECT expected.* FROM objects, LATERAL (VALUES
	        (assert_oid, '76bdbbc1411f2b9624c4730787ff75be', 'plpgsql', 'v'::"char", 'void'),
			(guard_oid, 'f3339d7f9b6b1ebfec5172945f5c07ef', 'plpgsql', 'v'::"char", 'trigger'),
			(begin_oid, '5f4cd7037a75c59ccea616622970d29e', 'plpgsql', 'v'::"char", 'SETOF jobs.update_transactions'),
			(advance_oid, '4702d7cedcdf4b46e01beaf2b15e47cc', 'plpgsql', 'v'::"char", 'SETOF jobs.update_transactions'),
			(restore_oid, '772d62b8629b384e84dc8a49c078be96', 'plpgsql', 'v'::"char", 'SETOF jobs.update_transactions'),
	        (active_oid, 'e4475b6b4ac88f44927f2fc357f0ada3', 'sql', 's'::"char", 'boolean')
	    ) AS expected(oid, body_hash, language_name, volatility, result_type)
	), expected_tables(oid) AS (
    SELECT unnest(ARRAY[
        'jobs.server_state'::regclass, 'auth.principals'::regclass,
        'relay.projects'::regclass, 'auth.capability_grants'::regclass,
        'relay.idempotency_records'::regclass, 'audit.events'::regclass,
        'jobs.queue_capacity'::regclass, 'jobs.outbox'::regclass,
        'auth.installation_owner'::regclass, 'auth.pending_enrollments'::regclass,
        'auth.pending_enrollment_grants'::regclass, 'auth.device_credentials'::regclass,
        'auth.legacy_auth_state'::regclass, 'auth.legacy_machines'::regclass,
        'auth.project_acl_state'::regclass, 'relay.project_identities'::regclass,
        'relay.project_lookup_aliases'::regclass, 'relay.project_merge_previews'::regclass,
        'attachment.ready_blob_manifest'::regclass
    ])
	), expected_columns(attnum, column_name, type_oid, type_modifier, required, default_expression) AS (
		VALUES
		(1,'update_id','uuid'::regtype,-1,true,''),(2,'installation_id','uuid'::regtype,-1,true,''),
		(3,'timeline_id','uuid'::regtype,-1,true,''),(4,'owner_principal_id','uuid'::regtype,-1,true,''),
		(5,'source_release','text'::regtype,-1,true,''),(6,'target_release','text'::regtype,-1,true,''),
		(7,'source_image','text'::regtype,-1,true,''),(8,'target_image','text'::regtype,-1,true,''),
		(9,'source_schema','bigint'::regtype,-1,true,''),(10,'target_schema','bigint'::regtype,-1,true,''),
		(11,'schema_min','bigint'::regtype,-1,true,''),(12,'schema_max','bigint'::regtype,-1,true,''),
		(13,'rollback_floor','bigint'::regtype,-1,true,''),(14,'postgres_major','integer'::regtype,-1,true,''),
		(15,'release_sha256','character'::regtype,68,true,''),(16,'compose_sha256','character'::regtype,68,true,''),
		(17,'migration_manifest_sha256','character'::regtype,68,true,''),(18,'phase','text'::regtype,-1,true,''),
		(19,'backup_id','uuid'::regtype,-1,false,''),(20,'backup_installation_id','uuid'::regtype,-1,false,''),
		(21,'backup_timeline_id','uuid'::regtype,-1,false,''),(22,'backup_change_sequence','bigint'::regtype,-1,false,''),
		(23,'backup_source_schema','bigint'::regtype,-1,false,''),(24,'backup_snapshot_id','text'::regtype,-1,false,''),
		(25,'backup_manifest_sha256','character'::regtype,68,false,''),(26,'created_at','timestamptz'::regtype,-1,true,'statement_timestamp()'),
		(27,'updated_at','timestamptz'::regtype,-1,true,'statement_timestamp()'),(28,'completed_at','timestamptz'::regtype,-1,false,'')
	), actual_columns AS (
		SELECT attribute.attnum::integer, attribute.attname, attribute.atttypid, attribute.atttypmod,
		       attribute.attnotnull, COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),'')
		FROM objects JOIN pg_attribute AS attribute ON attribute.attrelid=objects.updates_oid
		LEFT JOIN pg_attrdef AS default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum
		WHERE attribute.attnum>0 AND NOT attribute.attisdropped
	), column_safety AS (
		SELECT NOT EXISTS (SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns)
		   AND NOT EXISTS (SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns) AS safe
	), expected_checks(key, migration_expression, restored_expression) AS (
		VALUES
		(ARRAY[5]::smallint[], '(source_release ~ ''^[A-Za-z0-9][A-Za-z0-9._+\-]{0,127}$''::text)', '(source_release ~ ''^[A-Za-z0-9][A-Za-z0-9._+\-]{0,127}$''::text)'),
		(ARRAY[6,5]::smallint[], '((target_release ~ ''^[A-Za-z0-9][A-Za-z0-9._+\-]{0,127}$''::text) AND (target_release <> source_release))', '((target_release ~ ''^[A-Za-z0-9][A-Za-z0-9._+\-]{0,127}$''::text) AND (target_release <> source_release))'),
		(ARRAY[7]::smallint[], '(source_image ~ ''^[a-z0-9][a-z0-9./_:\-]*@sha256:[0-9a-f]{64}$''::text)', '(source_image ~ ''^[a-z0-9][a-z0-9./_:\-]*@sha256:[0-9a-f]{64}$''::text)'),
		(ARRAY[8,7]::smallint[], '((target_image ~ ''^[a-z0-9][a-z0-9./_:\-]*@sha256:[0-9a-f]{64}$''::text) AND (target_image <> source_image))', '((target_image ~ ''^[a-z0-9][a-z0-9./_:\-]*@sha256:[0-9a-f]{64}$''::text) AND (target_image <> source_image))'),
		(ARRAY[9]::smallint[], '(source_schema > 0)', '(source_schema > 0)'),
		(ARRAY[10,9]::smallint[], '(target_schema >= source_schema)', '(target_schema >= source_schema)'),
		(ARRAY[11]::smallint[], '(schema_min > 0)', '(schema_min > 0)'),
		(ARRAY[12,11]::smallint[], '(schema_max >= schema_min)', '(schema_max >= schema_min)'),
		(ARRAY[13,11,10]::smallint[], '((rollback_floor >= schema_min) AND (rollback_floor <= target_schema))', '((rollback_floor >= schema_min) AND (rollback_floor <= target_schema))'),
		(ARRAY[14]::smallint[], '(postgres_major >= 14)', '(postgres_major >= 14)'),
		(ARRAY[15]::smallint[], '(release_sha256 ~ ''^[0-9a-f]{64}$''::text)', '(release_sha256 ~ ''^[0-9a-f]{64}$''::text)'),
		(ARRAY[16]::smallint[], '(compose_sha256 ~ ''^[0-9a-f]{64}$''::text)', '(compose_sha256 ~ ''^[0-9a-f]{64}$''::text)'),
		(ARRAY[17]::smallint[], '(migration_manifest_sha256 ~ ''^[0-9a-f]{64}$''::text)', '(migration_manifest_sha256 ~ ''^[0-9a-f]{64}$''::text)'),
		(ARRAY[18]::smallint[], '(phase = ANY (ARRAY[''fenced''::text, ''writers_stopped''::text, ''backup_verified''::text, ''migration_started''::text, ''migrated''::text, ''candidate_ready''::text, ''doctor_passed''::text, ''config_published''::text, ''recovery_required''::text, ''recovery_ready''::text, ''recovery_doctor_passed''::text, ''recovery_config_published''::text, ''committed''::text, ''recovered''::text, ''aborted''::text]))', '(phase = ANY (ARRAY[''fenced''::text, ''writers_stopped''::text, ''backup_verified''::text, ''migration_started''::text, ''migrated''::text, ''candidate_ready''::text, ''doctor_passed''::text, ''config_published''::text, ''recovery_required''::text, ''recovery_ready''::text, ''recovery_doctor_passed''::text, ''recovery_config_published''::text, ''committed''::text, ''recovered''::text, ''aborted''::text]))'),
		(ARRAY[22]::smallint[], '(backup_change_sequence >= 0)', '(backup_change_sequence >= 0)'),
		(ARRAY[23]::smallint[], '(backup_source_schema > 0)', '(backup_source_schema > 0)'),
		(ARRAY[24]::smallint[], '(backup_snapshot_id ~ ''^[0-9A-Z-]{1,200}$''::text)', '(backup_snapshot_id ~ ''^[0-9A-Z-]{1,200}$''::text)'),
		(ARRAY[25]::smallint[], '(backup_manifest_sha256 ~ ''^[0-9a-f]{64}$''::text)', '(backup_manifest_sha256 ~ ''^[0-9a-f]{64}$''::text)'),
		(ARRAY[9,11,10,12]::smallint[], '(((source_schema >= schema_min) AND (source_schema <= target_schema)) AND (target_schema <= schema_max))', '((source_schema >= schema_min) AND (source_schema <= target_schema) AND (target_schema <= schema_max))'),
		(ARRAY[19,20]::smallint[], '((backup_id IS NULL) = (backup_installation_id IS NULL))', '((backup_id IS NULL) = (backup_installation_id IS NULL))'),
		(ARRAY[19,21]::smallint[], '((backup_id IS NULL) = (backup_timeline_id IS NULL))', '((backup_id IS NULL) = (backup_timeline_id IS NULL))'),
		(ARRAY[19,22]::smallint[], '((backup_id IS NULL) = (backup_change_sequence IS NULL))', '((backup_id IS NULL) = (backup_change_sequence IS NULL))'),
		(ARRAY[19,23]::smallint[], '((backup_id IS NULL) = (backup_source_schema IS NULL))', '((backup_id IS NULL) = (backup_source_schema IS NULL))'),
		(ARRAY[19,24]::smallint[], '((backup_id IS NULL) = (backup_snapshot_id IS NULL))', '((backup_id IS NULL) = (backup_snapshot_id IS NULL))'),
		(ARRAY[19,25]::smallint[], '((backup_id IS NULL) = (backup_manifest_sha256 IS NULL))', '((backup_id IS NULL) = (backup_manifest_sha256 IS NULL))'),
		(ARRAY[18,19]::smallint[], '((phase = ANY (ARRAY[''fenced''::text, ''writers_stopped''::text, ''aborted''::text])) OR (backup_id IS NOT NULL))', '((phase = ANY (ARRAY[''fenced''::text, ''writers_stopped''::text, ''aborted''::text])) OR (backup_id IS NOT NULL))'),
		(ARRAY[18,28]::smallint[], '((phase = ANY (ARRAY[''committed''::text, ''recovered''::text, ''aborted''::text])) = (completed_at IS NOT NULL))', '((phase = ANY (ARRAY[''committed''::text, ''recovered''::text, ''aborted''::text])) = (completed_at IS NOT NULL))')
	), constraint_safety AS (
		SELECT (SELECT count(*)=29 FROM pg_constraint,objects WHERE conrelid=updates_oid)
		   AND (SELECT count(*)=1 FROM pg_constraint,objects WHERE conrelid=updates_oid AND contype='p' AND conkey=ARRAY[1]::smallint[] AND convalidated AND NOT condeferrable AND NOT condeferred)
		   AND (SELECT count(*)=1 FROM pg_constraint,objects WHERE conrelid=updates_oid AND contype='f' AND conkey=ARRAY[4]::smallint[] AND confrelid='auth.principals'::regclass AND confkey=ARRAY[1]::smallint[] AND confupdtype='a' AND confdeltype='a' AND confmatchtype='s' AND convalidated AND NOT condeferrable AND NOT condeferred)
		   AND (SELECT count(*)=27 FROM pg_constraint,objects WHERE conrelid=updates_oid AND contype='c' AND convalidated AND NOT condeferrable AND NOT condeferred)
		   AND NOT EXISTS (SELECT 1 FROM expected_checks,objects WHERE NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=updates_oid AND contype='c' AND convalidated AND NOT condeferrable AND NOT condeferred AND conkey @> expected_checks.key AND conkey <@ expected_checks.key AND pg_get_expr(conbin,conrelid) IN (expected_checks.migration_expression,expected_checks.restored_expression))) AS safe
	), routine_safety AS (
	    SELECT count(*) = 6
	       AND bool_and(pg_get_userbyid(proc.proowner) = 'punaro_owner' AND proc.prosecdef AND proc.prokind = 'f')
	       AND bool_and(COALESCE(proc.proconfig = ARRAY['search_path=pg_catalog']::text[], false))
	       AND bool_and(md5(btrim(proc.prosrc)) = expected.body_hash AND language.lanname=expected.language_name
	           AND proc.provolatile=expected.volatility AND pg_get_function_result(proc.oid)=expected.result_type
	           AND NOT proc.proisstrict AND NOT proc.proleakproof AND proc.proparallel='u' AND proc.provariadic=0
	           AND proc.proargmodes IS NULL AND proc.proallargtypes IS NULL) AS safe
	    FROM expected_routines AS expected
	    JOIN pg_proc AS proc ON proc.oid = expected.oid
	    JOIN pg_language AS language ON language.oid=proc.prolang
	), routine_acl AS (
		SELECT count(*)=8 AND bool_and(NOT acl.is_grantable AND (grantee.rolname='punaro_owner' OR (grantee.rolname='punaro_app' AND proc.oid IN (objects.assert_oid,objects.active_oid)))) AS exact
		FROM objects JOIN pg_proc AS proc ON proc.oid=ANY(ARRAY[assert_oid,guard_oid,begin_oid,advance_oid,restore_oid,active_oid])
		CROSS JOIN LATERAL aclexplode(COALESCE(proc.proacl,acldefault('f',proc.proowner))) AS acl
		LEFT JOIN pg_roles AS grantee ON grantee.oid=acl.grantee
	), table_safety AS (
		SELECT COALESCE((SELECT relation.relkind='r' AND relation.relpersistence='p' AND NOT relation.relrowsecurity AND NOT relation.relforcerowsecurity
		   AND pg_get_userbyid(relation.relowner)='punaro_owner'
		   AND (SELECT count(*)=CASE WHEN current_setting('server_version_num')::integer/10000 >= 15 THEN 8 ELSE 7 END
		        AND bool_and(grantee.rolname='punaro_owner' AND NOT acl.is_grantable)
		        FROM LATERAL aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) AS acl
		        LEFT JOIN pg_roles AS grantee ON grantee.oid=acl.grantee)
		   AND NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid=relation.oid AND attnum>0 AND attacl IS NOT NULL)
		   FROM pg_class AS relation WHERE relation.oid=objects.updates_oid),false) AS safe
		FROM objects
	), trigger_safety AS (
		SELECT count(*) = 19
	       AND bool_and(trigger.tgenabled = 'O' AND NOT trigger.tgisinternal
	           AND trigger.tgtype = 62 AND trigger.tgfoid = objects.guard_oid AND trigger.tgconstraint=0
	           AND NOT trigger.tgdeferrable AND NOT trigger.tginitdeferred AND trigger.tgnargs=0
	           AND trigger.tgqual IS NULL AND trigger.tgnewtable IS NULL AND trigger.tgoldtable IS NULL
	           AND trigger.tgattr::text='') AS safe
	FROM expected_tables
	JOIN pg_trigger AS trigger ON trigger.tgrelid = expected_tables.oid
	   AND trigger.tgname = 'application_mutation_fence'
	CROSS JOIN objects
)
SELECT updates_oid IS NOT NULL AND active_index_oid IS NOT NULL
   AND assert_oid IS NOT NULL AND guard_oid IS NOT NULL AND begin_oid IS NOT NULL
   AND advance_oid IS NOT NULL AND restore_oid IS NOT NULL AND active_oid IS NOT NULL
	   AND column_safety.safe AND constraint_safety.safe AND routine_safety.safe AND routine_acl.exact AND table_safety.safe AND trigger_safety.safe
	   AND (SELECT index.indisunique AND index.indisvalid AND index.indisready AND index.indislive AND index.indimmediate
	        AND NOT index.indisprimary AND NOT index.indisexclusion AND NOT index.indisclustered
	        AND index.indrelid = updates_oid AND index.indnkeyatts=1 AND index.indnatts=1 AND index.indkey::text='0'
	        AND index.indcollation::text='0' AND index.indoption::text='0'
	        AND index.indclass::text=(SELECT oid::text FROM pg_opclass WHERE opcname='bool_ops' AND opcmethod=access_method.oid)
	        AND index_relation.relkind='i' AND pg_get_userbyid(index_relation.relowner)='punaro_owner' AND access_method.amname='btree'
	        AND pg_get_expr(index.indexprs,index.indrelid)='true'
	        AND pg_get_expr(index.indpred,index.indrelid) = '(phase <> ALL (ARRAY[''committed''::text, ''recovered''::text, ''aborted''::text]))'
	        FROM pg_index AS index JOIN pg_class AS index_relation ON index_relation.oid=index.indexrelid
	        JOIN pg_am AS access_method ON access_method.oid=index_relation.relam WHERE index.indexrelid = active_index_oid)
	FROM objects,column_safety,constraint_safety,routine_safety,routine_acl,table_safety,trigger_safety`

func updateControlsAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, updateControlsInspectionSQL).Scan(&available)
	if err != nil {
		return false, errors.New("PostgreSQL update controls cannot be inspected")
	}
	return available, nil
}

func administrationSchemaAllowed(state SchemaState, bridgeControls, knownBridge bool) bool {
	return state.Classification == Compatible || (state.Classification == UpgradeRequired && state.Version == 5 && bridgeControls && knownBridge)
}

// BeginUpdate drains mutation transactions through the database gate and then
// publishes exactly one durable active owner. Exact retries return that owner.
func (a *Administration) BeginUpdate(ctx context.Context, request UpdateRequest) (UpdateTransaction, error) {
	if request.Validate() != nil {
		return UpdateTransaction{}, errors.New("invalid update request")
	}
	transaction, err := scanUpdate(a.db.QueryRowContext(ctx, `SELECT `+updateSelectColumns+` FROM jobs.begin_update($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, request.UpdateID, request.SourceRelease, request.TargetRelease, request.SourceImage, request.TargetImage, request.SourceSchema, request.TargetSchema, request.SchemaMin, request.SchemaMax, request.RollbackFloor, request.PostgresMajor, request.ReleaseSHA256, request.ComposeSHA256, request.MigrationManifestSHA256))
	if err != nil {
		if strings.Contains(err.Error(), "update fence is already owned") {
			return UpdateTransaction{}, ErrUpdateConflict
		}
		return UpdateTransaction{}, errors.New("update transaction could not acquire the maintenance fence")
	}
	return transaction, nil
}

// ActiveUpdate returns the one unfinished durable update, if present.
func (a *Administration) ActiveUpdate(ctx context.Context) (UpdateTransaction, error) {
	transaction, err := scanUpdate(a.db.QueryRowContext(ctx, `SELECT `+updateSelectColumns+` FROM jobs.update_transactions WHERE phase NOT IN ('committed','recovered','aborted')`))
	if errors.Is(err, sql.ErrNoRows) {
		return UpdateTransaction{}, ErrNotFound
	}
	if err != nil {
		return UpdateTransaction{}, errors.New("update transaction is unavailable")
	}
	return transaction, nil
}

// LatestUpdate returns the newest durable update outcome or active transaction.
// It lets the host reconcile a lost final command response after the active
// fence has already committed.
func (a *Administration) LatestUpdate(ctx context.Context) (UpdateTransaction, error) {
	transaction, err := scanUpdate(a.db.QueryRowContext(ctx, `SELECT `+updateSelectColumns+` FROM jobs.update_transactions ORDER BY created_at DESC, update_id DESC LIMIT 1`))
	if errors.Is(err, sql.ErrNoRows) {
		return UpdateTransaction{}, ErrNotFound
	}
	if err != nil {
		return UpdateTransaction{}, errors.New("latest update transaction is unavailable")
	}
	return transaction, nil
}

// Update returns one exact durable transaction, including terminal outcomes.
func (a *Administration) Update(ctx context.Context, updateID string) (UpdateTransaction, error) {
	if uuid.Validate(updateID) != nil {
		return UpdateTransaction{}, errors.New("invalid update identity")
	}
	transaction, err := scanUpdate(a.db.QueryRowContext(ctx, `SELECT `+updateSelectColumns+` FROM jobs.update_transactions WHERE update_id=$1::uuid`, updateID))
	if errors.Is(err, sql.ErrNoRows) {
		return UpdateTransaction{}, ErrNotFound
	}
	if err != nil {
		return UpdateTransaction{}, errors.New("update transaction is unavailable")
	}
	return transaction, nil
}

// AdvanceUpdate performs one CAS phase transition. Backup verification requires
// the exact marker; commit/abort are the only operations that release the gate.
func (a *Administration) AdvanceUpdate(ctx context.Context, updateID string, from, to UpdatePhase, marker *UpdateBackupMarker) (UpdateTransaction, error) {
	if uuid.Validate(updateID) != nil || validateUpdateTransition(from, to) != nil || (to == UpdateBackupVerified && (marker == nil || marker.Validate() != nil || marker.UpdateID != updateID)) || (to != UpdateBackupVerified && marker != nil) {
		return UpdateTransaction{}, ErrInvalidUpdateTransition
	}
	var backupID any
	if marker != nil {
		backupID = marker.BackupID
	}
	transaction, err := scanUpdate(a.db.QueryRowContext(ctx, `SELECT `+updateSelectColumns+` FROM jobs.advance_update($1::uuid,$2,$3,$4::uuid,$5::uuid,$6::uuid,$7,$8,$9,$10,$11,$12)`, updateID, from, to, backupID, nullableText(marker, func(m *UpdateBackupMarker) string { return m.InstallationID }), nullableText(marker, func(m *UpdateBackupMarker) string { return m.TimelineID }), optionalInt64(marker, func(m *UpdateBackupMarker) int64 { return m.ChangeSequence }), optionalInt64(marker, func(m *UpdateBackupMarker) int64 { return m.SourceSchema }), nullableText(marker, func(m *UpdateBackupMarker) string { return m.TargetRelease }), nullableText(marker, func(m *UpdateBackupMarker) string { return m.TargetImageDigest }), nullableText(marker, func(m *UpdateBackupMarker) string { return m.ExportedSnapshotID }), nullableText(marker, func(m *UpdateBackupMarker) string { return m.ManifestSHA256 })))
	if err != nil {
		return UpdateTransaction{}, ErrInvalidUpdateTransition
	}
	return transaction, nil
}

// RestoreUpdateRecovery atomically rotates a restored pre-update timeline and
// reconstructs the durable backup marker which, by design, was recorded only
// after the exported snapshot. Exact retries return the same recovery state.
func (a *Administration) RestoreUpdateRecovery(ctx context.Context, marker UpdateBackupMarker) (InstallationState, UpdateTransaction, error) {
	if marker.Validate() != nil {
		return InstallationState{}, UpdateTransaction{}, errors.New("invalid restored update authorization")
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return InstallationState{}, UpdateTransaction{}, errors.New("restored update recovery could not start")
	}
	defer func() { _ = tx.Rollback() }()
	transaction, err := scanUpdate(tx.QueryRowContext(ctx, `SELECT `+updateSelectColumns+` FROM jobs.restore_update_recovery($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7,$8,$9,$10)`, marker.UpdateID, marker.BackupID, marker.InstallationID, marker.TimelineID, marker.ChangeSequence, marker.SourceSchema, marker.TargetRelease, marker.TargetImageDigest, marker.ExportedSnapshotID, marker.ManifestSHA256))
	if err != nil {
		return InstallationState{}, UpdateTransaction{}, errors.New("restored update evidence does not match")
	}
	var state InstallationState
	if err := tx.QueryRowContext(ctx, `SELECT installation_id::text,timeline_id::text,change_sequence FROM jobs.server_state WHERE singleton`).Scan(&state.InstallationID, &state.TimelineID, &state.ChangeSequence); err != nil ||
		state.InstallationID != marker.InstallationID || state.TimelineID == marker.TimelineID || state.ChangeSequence != marker.ChangeSequence ||
		transaction.UpdateID != marker.UpdateID || transaction.Phase != UpdateRecoveryRequired || transaction.BackupID != marker.BackupID ||
		transaction.TargetRelease != marker.TargetRelease || !strings.HasSuffix(transaction.TargetImage, "@"+marker.TargetImageDigest) ||
		transaction.BackupInstallationID != marker.InstallationID || transaction.BackupTimelineID != marker.TimelineID || transaction.BackupChangeSequence != marker.ChangeSequence ||
		transaction.BackupSourceSchema != marker.SourceSchema || transaction.BackupSnapshotID != marker.ExportedSnapshotID || transaction.BackupManifestSHA256 != marker.ManifestSHA256 {
		return InstallationState{}, UpdateTransaction{}, errors.New("restored update recovery result is invalid")
	}
	if err := tx.Commit(); err != nil {
		return InstallationState{}, UpdateTransaction{}, errors.New("restored update recovery could not be committed")
	}
	return state, transaction, nil
}

func nullableText[T any](value *T, field func(*T) string) any {
	if value == nil {
		return nil
	}
	return field(value)
}

func optionalInt64[T any](value *T, field func(*T) int64) any {
	if value == nil {
		return nil
	}
	return field(value)
}
