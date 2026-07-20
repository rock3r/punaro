CREATE TABLE jobs.update_transactions (
    update_id uuid PRIMARY KEY,
    installation_id uuid NOT NULL,
    timeline_id uuid NOT NULL,
    owner_principal_id uuid NOT NULL REFERENCES auth.principals(id),
    source_release text NOT NULL CHECK (source_release ~ '^[A-Za-z0-9][A-Za-z0-9._+\-]{0,127}$'),
    target_release text NOT NULL CHECK (target_release ~ '^[A-Za-z0-9][A-Za-z0-9._+\-]{0,127}$' AND target_release <> source_release),
    source_image text NOT NULL CHECK (source_image ~ '^[a-z0-9][a-z0-9./_:\-]*@sha256:[0-9a-f]{64}$'),
    target_image text NOT NULL CHECK (target_image ~ '^[a-z0-9][a-z0-9./_:\-]*@sha256:[0-9a-f]{64}$' AND target_image <> source_image),
    source_schema bigint NOT NULL CHECK (source_schema > 0),
    target_schema bigint NOT NULL CHECK (target_schema >= source_schema),
    schema_min bigint NOT NULL CHECK (schema_min > 0),
    schema_max bigint NOT NULL CHECK (schema_max >= schema_min),
    rollback_floor bigint NOT NULL CHECK (rollback_floor BETWEEN schema_min AND target_schema),
    postgres_major integer NOT NULL CHECK (postgres_major >= 14),
    release_sha256 char(64) NOT NULL CHECK (release_sha256 ~ '^[0-9a-f]{64}$'),
    compose_sha256 char(64) NOT NULL CHECK (compose_sha256 ~ '^[0-9a-f]{64}$'),
    migration_manifest_sha256 char(64) NOT NULL CHECK (migration_manifest_sha256 ~ '^[0-9a-f]{64}$'),
    phase text NOT NULL CHECK (phase IN ('fenced','writers_stopped','backup_verified','migration_started','migrated','candidate_ready','doctor_passed','config_published','recovery_required','recovery_ready','recovery_doctor_passed','recovery_config_published','committed','recovered','aborted')),
    backup_id uuid,
    backup_installation_id uuid,
    backup_timeline_id uuid,
    backup_change_sequence bigint CHECK (backup_change_sequence >= 0),
    backup_source_schema bigint CHECK (backup_source_schema > 0),
    backup_snapshot_id text CHECK (backup_snapshot_id ~ '^[0-9A-Z-]{1,200}$'),
    backup_manifest_sha256 char(64) CHECK (backup_manifest_sha256 ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    completed_at timestamptz,
    CHECK (source_schema BETWEEN schema_min AND target_schema AND target_schema <= schema_max),
    CHECK ((backup_id IS NULL) = (backup_installation_id IS NULL)),
    CHECK ((backup_id IS NULL) = (backup_timeline_id IS NULL)),
    CHECK ((backup_id IS NULL) = (backup_change_sequence IS NULL)),
    CHECK ((backup_id IS NULL) = (backup_source_schema IS NULL)),
    CHECK ((backup_id IS NULL) = (backup_snapshot_id IS NULL)),
    CHECK ((backup_id IS NULL) = (backup_manifest_sha256 IS NULL)),
    CHECK (phase IN ('fenced','writers_stopped','aborted') OR backup_id IS NOT NULL),
    CHECK ((phase IN ('committed','recovered','aborted')) = (completed_at IS NOT NULL))
);

CREATE UNIQUE INDEX update_transactions_one_active
ON jobs.update_transactions ((true))
WHERE phase NOT IN ('committed','recovered','aborted');

CREATE FUNCTION jobs.assert_application_mutation()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    -- The shared transaction lock makes a writer visible to fence acquisition
    -- until its commit or rollback.
    PERFORM pg_advisory_xact_lock_shared(579001230607);
    IF EXISTS (
        SELECT 1 FROM jobs.update_transactions
        WHERE phase NOT IN ('committed','recovered','aborted')
    ) THEN
        RAISE EXCEPTION 'punaro maintenance in progress'
            USING ERRCODE = '55P03';
    END IF;
END
$function$;

CREATE FUNCTION jobs.guard_application_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
	-- Only the dedicated migrator may write business tables as owner while a
	-- fence is active. A custom GUC alone grants nothing: it must match the
	-- durable transaction already in the irreversible migration phase.
	IF session_user = 'punaro_owner'
	   AND EXISTS (
		SELECT 1 FROM jobs.update_transactions
		WHERE update_id::text = current_setting('punaro.update_id', true)
		  AND phase = 'migration_started'
	   ) THEN
		RETURN NULL;
    END IF;
	-- A restored pre-update snapshot still contains its writers_stopped row.
	-- The dedicated recovery function inserts exact restore evidence before it
	-- rotates server_state; this exception expires in the same statement when
	-- that row moves to recovery_required.
	IF session_user = 'punaro_owner'
	   AND EXISTS (
		SELECT 1
		FROM jobs.update_transactions AS txn
		JOIN jobs.restore_events AS event
		  ON event.backup_id::text = current_setting('punaro.restore_backup_id', true)
		 AND event.installation_id = txn.installation_id
		 AND event.previous_timeline_id = txn.timeline_id
		JOIN jobs.server_state AS state
		  ON state.singleton
		 AND state.installation_id = event.installation_id
		 AND state.timeline_id = event.previous_timeline_id
		 AND state.change_sequence = event.restored_change_sequence
		WHERE txn.update_id::text = current_setting('punaro.restore_update_id', true)
		  AND txn.phase = 'writers_stopped'
	   ) THEN
		RETURN NULL;
	END IF;
	PERFORM jobs.assert_application_mutation();
    RETURN NULL;
END
$function$;

CREATE FUNCTION jobs.restore_update_recovery(
    requested_id uuid,
    requested_backup_id uuid,
    requested_installation_id uuid,
    requested_timeline_id uuid,
    requested_change_sequence bigint,
    requested_source_schema bigint,
    requested_target_release text,
    requested_target_image_digest text,
    requested_snapshot_id text,
    requested_manifest_sha256 text
)
RETURNS SETOF jobs.update_transactions
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    active jobs.update_transactions%ROWTYPE;
    next_timeline uuid;
BEGIN
    IF session_user <> 'punaro_owner'
       OR requested_id IS NULL OR requested_backup_id IS NULL
       OR requested_installation_id IS NULL OR requested_timeline_id IS NULL
       OR requested_change_sequence IS NULL OR requested_change_sequence < 0
       OR requested_source_schema IS NULL OR requested_source_schema < 1
	   OR requested_source_schema <> COALESCE((SELECT max(version) FROM jobs.schema_migrations WHERE status = 'applied'), 0)
       OR requested_target_release IS NULL
       OR requested_target_image_digest IS NULL
       OR requested_snapshot_id IS NULL
       OR requested_manifest_sha256 IS NULL
       OR requested_target_release !~ '^[A-Za-z0-9][A-Za-z0-9._+\-]{0,127}$'
       OR requested_target_image_digest !~ '^sha256:[0-9a-f]{64}$'
       OR requested_snapshot_id !~ '^[0-9A-Z-]{1,200}$'
       OR requested_manifest_sha256 !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'restored update authority is unavailable';
    END IF;
    PERFORM pg_advisory_xact_lock(579001230607);
    SELECT * INTO active FROM jobs.update_transactions
    WHERE update_id = requested_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'restored update is unavailable';
    END IF;

    SELECT event.restored_timeline_id INTO next_timeline
    FROM jobs.restore_events AS event
    WHERE event.backup_id = requested_backup_id
      AND event.installation_id = requested_installation_id
      AND event.previous_timeline_id = requested_timeline_id
      AND event.restored_change_sequence = requested_change_sequence;
    IF FOUND THEN
        IF active.phase = 'recovery_required'
           AND active.installation_id = requested_installation_id
           AND active.timeline_id = next_timeline
           AND active.source_schema = requested_source_schema
           AND active.target_release = requested_target_release
           AND split_part(active.target_image, '@', 2) = requested_target_image_digest
           AND active.backup_id = requested_backup_id
           AND active.backup_installation_id = requested_installation_id
           AND active.backup_timeline_id = requested_timeline_id
           AND active.backup_change_sequence = requested_change_sequence
           AND active.backup_source_schema = requested_source_schema
           AND active.backup_snapshot_id = requested_snapshot_id
           AND active.backup_manifest_sha256 = requested_manifest_sha256
           AND EXISTS (
               SELECT 1 FROM jobs.server_state AS state
               WHERE state.singleton
                 AND state.installation_id = requested_installation_id
                 AND state.timeline_id = next_timeline
                 AND state.change_sequence = requested_change_sequence
           ) THEN
            RETURN NEXT active;
            RETURN;
        END IF;
        RAISE EXCEPTION 'restored update retry evidence does not match';
    END IF;

    IF active.phase <> 'writers_stopped'
       OR active.installation_id <> requested_installation_id
       OR active.timeline_id <> requested_timeline_id
       OR active.source_schema <> requested_source_schema
       OR active.target_release <> requested_target_release
       OR split_part(active.target_image, '@', 2) <> requested_target_image_digest
       OR active.backup_id IS NOT NULL
       OR NOT EXISTS (
           SELECT 1 FROM jobs.server_state AS state
           WHERE state.singleton
             AND state.installation_id = requested_installation_id
             AND state.timeline_id = requested_timeline_id
             AND state.change_sequence = requested_change_sequence
       ) THEN
        RAISE EXCEPTION 'restored update boundary does not match';
    END IF;

    next_timeline := gen_random_uuid();
    INSERT INTO jobs.restore_events (
        restore_id, backup_id, installation_id, previous_timeline_id,
        restored_timeline_id, restored_change_sequence
    ) VALUES (
        gen_random_uuid(), requested_backup_id, requested_installation_id,
        requested_timeline_id, next_timeline, requested_change_sequence
    );
    PERFORM set_config('punaro.restore_update_id', requested_id::text, true);
    PERFORM set_config('punaro.restore_backup_id', requested_backup_id::text, true);
    UPDATE jobs.server_state AS state
    SET timeline_id = next_timeline,
        timeline_started_at = statement_timestamp()
    WHERE state.singleton
      AND state.installation_id = requested_installation_id
      AND state.timeline_id = requested_timeline_id
      AND state.change_sequence = requested_change_sequence;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'restored timeline changed during recovery';
    END IF;
    UPDATE jobs.update_transactions
    SET timeline_id = next_timeline,
        phase = 'recovery_required',
        backup_id = requested_backup_id,
        backup_installation_id = requested_installation_id,
        backup_timeline_id = requested_timeline_id,
        backup_change_sequence = requested_change_sequence,
        backup_source_schema = requested_source_schema,
        backup_snapshot_id = requested_snapshot_id,
        backup_manifest_sha256 = requested_manifest_sha256,
        updated_at = statement_timestamp(),
        completed_at = NULL
    WHERE update_id = requested_id AND phase = 'writers_stopped'
    RETURNING * INTO active;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'restored update changed during recovery';
    END IF;
    RETURN NEXT active;
END
$function$;

CREATE FUNCTION jobs.begin_update(
    requested_id uuid,
    requested_source_release text,
    requested_target_release text,
    requested_source_image text,
    requested_target_image text,
    requested_source_schema bigint,
    requested_target_schema bigint,
    requested_schema_min bigint,
    requested_schema_max bigint,
    requested_rollback_floor bigint,
    requested_postgres_major integer,
    requested_release_sha256 text,
    requested_compose_sha256 text,
    requested_migration_manifest_sha256 text
)
RETURNS SETOF jobs.update_transactions
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    active jobs.update_transactions%ROWTYPE;
BEGIN
    IF session_user <> 'punaro_owner' OR requested_id IS NULL THEN
        RAISE EXCEPTION 'update authority is unavailable';
    END IF;
    IF requested_source_schema <> (SELECT max(version) FROM jobs.schema_migrations WHERE status='applied')
       OR requested_target_schema < requested_source_schema
       OR requested_source_schema < requested_schema_min
       OR requested_target_schema NOT BETWEEN requested_schema_min AND requested_schema_max
       OR requested_rollback_floor NOT BETWEEN requested_schema_min AND requested_target_schema
       OR requested_release_sha256 !~ '^[0-9a-f]{64}$'
       OR requested_compose_sha256 !~ '^[0-9a-f]{64}$'
       OR requested_migration_manifest_sha256 !~ '^[0-9a-f]{64}$'
       OR requested_postgres_major <> current_setting('server_version_num')::integer / 10000 THEN
        RAISE EXCEPTION 'update environment does not match the durable source';
    END IF;
    -- Wait for every transaction that has crossed a mutation trigger. Once the
    -- exclusive lock is granted, its durable row is committed before later
    -- writers can acquire their shared lock and reject.
    PERFORM pg_advisory_xact_lock(579001230607);
    SELECT * INTO active FROM jobs.update_transactions
    WHERE phase NOT IN ('committed','recovered','aborted');
    IF FOUND THEN
        IF active.update_id = requested_id
           AND active.source_release = requested_source_release
           AND active.target_release = requested_target_release
           AND active.source_image = requested_source_image
           AND active.target_image = requested_target_image
           AND active.source_schema = requested_source_schema
           AND active.target_schema = requested_target_schema
           AND active.schema_min = requested_schema_min
           AND active.schema_max = requested_schema_max
           AND active.rollback_floor = requested_rollback_floor
           AND active.postgres_major = requested_postgres_major
           AND active.release_sha256 = requested_release_sha256
           AND active.compose_sha256 = requested_compose_sha256
           AND active.migration_manifest_sha256 = requested_migration_manifest_sha256 THEN
            RETURN NEXT active;
            RETURN;
        END IF;
        RAISE EXCEPTION 'update fence is already owned';
    END IF;
    INSERT INTO jobs.update_transactions (
        update_id, installation_id, timeline_id, owner_principal_id, source_release,
        target_release, source_image, target_image, source_schema,
        target_schema, schema_min, schema_max, rollback_floor, postgres_major,
        release_sha256, compose_sha256, migration_manifest_sha256, phase
    )
    SELECT requested_id, state.installation_id, state.timeline_id, owner.principal_id,
           requested_source_release, requested_target_release,
           requested_source_image, requested_target_image,
           requested_source_schema, requested_target_schema, requested_schema_min,
           requested_schema_max, requested_rollback_floor, requested_postgres_major,
           requested_release_sha256, requested_compose_sha256,
           requested_migration_manifest_sha256, 'fenced'
    FROM jobs.server_state AS state
    JOIN auth.installation_owner AS owner ON owner.singleton
    WHERE state.singleton
    RETURNING * INTO active;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'installation state is unavailable';
    END IF;
    RETURN NEXT active;
END
$function$;

CREATE FUNCTION jobs.advance_update(
    requested_id uuid,
    expected_phase text,
    requested_phase text,
    requested_backup_id uuid,
    requested_installation_id uuid,
    requested_timeline_id uuid,
    requested_change_sequence bigint,
    requested_source_schema bigint,
    requested_target_release text,
    requested_target_image_digest text,
    requested_snapshot_id text,
    requested_manifest_sha256 text
)
RETURNS SETOF jobs.update_transactions
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    active jobs.update_transactions%ROWTYPE;
    transition_allowed boolean;
BEGIN
    IF session_user <> 'punaro_owner' THEN
        RAISE EXCEPTION 'update authority is unavailable';
    END IF;
    transition_allowed := CASE expected_phase
        WHEN 'fenced' THEN requested_phase IN ('writers_stopped','aborted')
        WHEN 'writers_stopped' THEN requested_phase IN ('backup_verified','aborted')
        WHEN 'backup_verified' THEN requested_phase IN ('migration_started','aborted')
        WHEN 'migration_started' THEN requested_phase IN ('migrated','recovery_required')
        WHEN 'migrated' THEN requested_phase IN ('candidate_ready','recovery_required')
        WHEN 'candidate_ready' THEN requested_phase IN ('doctor_passed','recovery_required')
        WHEN 'doctor_passed' THEN requested_phase IN ('config_published','recovery_required')
        WHEN 'config_published' THEN requested_phase = 'committed'
        WHEN 'recovery_required' THEN requested_phase = 'recovery_ready'
        WHEN 'recovery_ready' THEN requested_phase = 'recovery_doctor_passed'
        WHEN 'recovery_doctor_passed' THEN requested_phase = 'recovery_config_published'
        WHEN 'recovery_config_published' THEN requested_phase = 'recovered'
        ELSE false
    END;
    IF NOT transition_allowed THEN
        RAISE EXCEPTION 'update phase transition is invalid';
    END IF;
    PERFORM pg_advisory_xact_lock(579001230607);
    SELECT * INTO active FROM jobs.update_transactions
    WHERE update_id = requested_id AND phase = expected_phase
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'update phase precondition changed';
    END IF;
    IF requested_phase = 'backup_verified' THEN
        IF requested_backup_id IS NULL
           OR requested_installation_id <> active.installation_id
           OR requested_timeline_id <> active.timeline_id
           OR requested_source_schema <> active.source_schema
           OR requested_target_release <> active.target_release
           OR requested_target_image_digest <> split_part(active.target_image, '@', 2)
           OR requested_snapshot_id !~ '^[0-9A-Z-]{1,200}$'
           OR requested_manifest_sha256 !~ '^[0-9a-f]{64}$'
           OR requested_change_sequence IS NULL
           OR NOT EXISTS (
               SELECT 1 FROM jobs.server_state
               WHERE singleton
                 AND installation_id = requested_installation_id
                 AND timeline_id = requested_timeline_id
                 AND change_sequence = requested_change_sequence
           ) THEN
            RAISE EXCEPTION 'verified backup boundary does not match update';
        END IF;
    ELSIF requested_backup_id IS NOT NULL OR requested_installation_id IS NOT NULL
       OR requested_timeline_id IS NOT NULL OR requested_change_sequence IS NOT NULL
       OR requested_source_schema IS NOT NULL OR requested_target_release IS NOT NULL
       OR requested_target_image_digest IS NOT NULL OR requested_snapshot_id IS NOT NULL
       OR requested_manifest_sha256 IS NOT NULL THEN
        RAISE EXCEPTION 'unexpected backup marker';
    END IF;
    UPDATE jobs.update_transactions
    SET phase = requested_phase,
        backup_id = COALESCE(requested_backup_id, backup_id),
        backup_installation_id = COALESCE(requested_installation_id, backup_installation_id),
        backup_timeline_id = COALESCE(requested_timeline_id, backup_timeline_id),
        backup_change_sequence = COALESCE(requested_change_sequence, backup_change_sequence),
        backup_source_schema = COALESCE(requested_source_schema, backup_source_schema),
        backup_snapshot_id = COALESCE(requested_snapshot_id, backup_snapshot_id),
        backup_manifest_sha256 = COALESCE(requested_manifest_sha256, backup_manifest_sha256),
        updated_at = statement_timestamp(),
        completed_at = CASE WHEN requested_phase IN ('committed','recovered','aborted') THEN statement_timestamp() ELSE NULL END
    WHERE update_id = requested_id AND phase = expected_phase
    RETURNING * INTO active;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'update phase precondition changed';
    END IF;
    RETURN NEXT active;
END
$function$;

CREATE FUNCTION jobs.maintenance_active()
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT EXISTS (
        SELECT 1 FROM jobs.update_transactions
        WHERE phase NOT IN ('committed','recovered','aborted')
    )
$function$;

DO $block$
DECLARE
    target regclass;
BEGIN
    FOREACH target IN ARRAY ARRAY[
        'jobs.server_state'::regclass,
        'auth.principals'::regclass,
        'relay.projects'::regclass,
        'auth.capability_grants'::regclass,
        'relay.idempotency_records'::regclass,
        'audit.events'::regclass,
        'jobs.queue_capacity'::regclass,
        'jobs.outbox'::regclass,
        'auth.installation_owner'::regclass,
        'auth.pending_enrollments'::regclass,
        'auth.pending_enrollment_grants'::regclass,
        'auth.device_credentials'::regclass,
        'auth.legacy_auth_state'::regclass,
        'auth.legacy_machines'::regclass,
        'auth.project_acl_state'::regclass,
        'relay.project_identities'::regclass,
        'relay.project_lookup_aliases'::regclass,
        'relay.project_merge_previews'::regclass,
        'attachment.ready_blob_manifest'::regclass
    ]
    LOOP
        EXECUTE format(
            'CREATE TRIGGER application_mutation_fence BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION jobs.guard_application_mutation()',
            target
        );
    END LOOP;
END
$block$;

REVOKE ALL ON jobs.update_transactions FROM PUBLIC, punaro_app;
REVOKE ALL ON FUNCTION jobs.assert_application_mutation() FROM PUBLIC, punaro_app;
REVOKE ALL ON FUNCTION jobs.guard_application_mutation() FROM PUBLIC, punaro_app;
REVOKE ALL ON FUNCTION jobs.begin_update(uuid,text,text,text,text,bigint,bigint,bigint,bigint,bigint,integer,text,text,text) FROM PUBLIC, punaro_app;
REVOKE ALL ON FUNCTION jobs.advance_update(uuid,text,text,uuid,uuid,uuid,bigint,bigint,text,text,text,text) FROM PUBLIC, punaro_app;
REVOKE ALL ON FUNCTION jobs.restore_update_recovery(uuid,uuid,uuid,uuid,bigint,bigint,text,text,text,text) FROM PUBLIC, punaro_app;
REVOKE ALL ON FUNCTION jobs.maintenance_active() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION jobs.assert_application_mutation() TO punaro_app;
GRANT EXECUTE ON FUNCTION jobs.maintenance_active() TO punaro_app;
