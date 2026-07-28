WITH RECURSIVE lineage(timeline_id) AS (
  SELECT state.timeline_id FROM jobs.server_state AS state WHERE state.singleton
  UNION
  SELECT event.previous_timeline_id FROM jobs.restore_events AS event JOIN lineage ON event.restored_timeline_id=lineage.timeline_id
), root AS (
  SELECT candidate.timeline_id FROM lineage AS candidate
  WHERE NOT EXISTS (SELECT 1 FROM jobs.restore_events AS event WHERE event.restored_timeline_id=candidate.timeline_id)
)
UPDATE brain.memory_consolidation_checkpoints AS checkpoint
SET timeline_id=(SELECT timeline_id FROM root),change_sequence=0,lease_holder=NULL,lease_token=NULL,lease_generation=checkpoint.lease_generation+1,lease_until=NULL,updated_at=statement_timestamp();

CREATE FUNCTION brain.read_memory_consolidation_sources(requested_scope uuid, requested_token uuid, requested_generation bigint)
RETURNS TABLE(timeline_id uuid,item_id uuid,revision bigint,change_sequence bigint,is_fence boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $function$
BEGIN
    IF requested_scope IS NULL OR requested_token IS NULL OR requested_generation < 1 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='invalid consolidation source request';
    END IF;
    RETURN QUERY WITH RECURSIVE lineage(timeline_id) AS (
      SELECT state.timeline_id FROM jobs.server_state AS state WHERE state.singleton
      UNION
      SELECT event.previous_timeline_id FROM jobs.restore_events AS event JOIN lineage ON event.restored_timeline_id=lineage.timeline_id
    ), fence AS (
      SELECT checkpoint.timeline_id,checkpoint.scope_id,checkpoint.change_sequence,event.restored_change_sequence AS rebase_sequence
      FROM brain.memory_consolidation_checkpoints AS checkpoint
      JOIN lineage ON lineage.timeline_id=checkpoint.timeline_id
      LEFT JOIN jobs.restore_events AS event ON event.previous_timeline_id=checkpoint.timeline_id
      WHERE checkpoint.scope_id=requested_scope AND checkpoint.lease_token=requested_token
        AND checkpoint.lease_generation=requested_generation AND checkpoint.lease_until > statement_timestamp()
    ), page AS MATERIALIZED (
      SELECT change.timeline_id,change.scope_id,change.item_id,change.operation,change.revision,change.change_sequence
      FROM fence JOIN brain.memory_changes AS change ON change.scope_id=fence.scope_id AND change.timeline_id=fence.timeline_id
      WHERE change.change_sequence>fence.change_sequence
      ORDER BY change.change_sequence
      LIMIT 128
    )
    SELECT fence.timeline_id,NULL::uuid,NULL::bigint,fence.change_sequence,true FROM fence
    UNION ALL
    SELECT fence.timeline_id,CASE WHEN change.operation<>'delete' AND memory_item.state='active' AND memory_revision.item_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM brain.memory_quarantines AS quarantine WHERE quarantine.item_id=change.item_id AND (quarantine.released_at IS NULL OR (change.revision<=quarantine.detected_revision AND memory_item.current_revision>quarantine.detected_revision))) THEN change.item_id END,CASE WHEN change.operation<>'delete' AND memory_item.state='active' AND memory_revision.item_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM brain.memory_quarantines AS quarantine WHERE quarantine.item_id=change.item_id AND (quarantine.released_at IS NULL OR (change.revision<=quarantine.detected_revision AND memory_item.current_revision>quarantine.detected_revision))) THEN change.revision END,change.change_sequence,false
    FROM fence JOIN page AS change ON change.scope_id=fence.scope_id AND change.timeline_id=fence.timeline_id
    LEFT JOIN brain.memory_items AS memory_item ON memory_item.id=change.item_id
    LEFT JOIN brain.memory_revisions AS memory_revision ON memory_revision.item_id=change.item_id AND memory_revision.revision=change.revision
    UNION ALL
    SELECT fence.timeline_id,NULL::uuid,NULL::bigint,fence.rebase_sequence,false
    FROM fence WHERE fence.rebase_sequence>fence.change_sequence
    ORDER BY 4,2
    LIMIT 129;
END
$function$;

CREATE OR REPLACE FUNCTION jobs.restore_update_recovery(
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
    UPDATE brain.memory_consolidation_checkpoints AS checkpoint
    SET lease_holder=NULL,lease_token=NULL,lease_generation=checkpoint.lease_generation+1,lease_until=NULL,updated_at=statement_timestamp()
    WHERE checkpoint.lease_until IS NOT NULL;
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
REVOKE ALL ON FUNCTION brain.read_memory_consolidation_sources(uuid,uuid,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION brain.read_memory_consolidation_sources(uuid,uuid,bigint) TO punaro_app;

CREATE OR REPLACE FUNCTION brain.claim_memory_consolidation_checkpoint(requested_scope uuid, requested_holder uuid, requested_lease_micros bigint)
RETURNS TABLE(scope_id uuid,timeline_id uuid,change_sequence bigint,lease_holder uuid,lease_token uuid,lease_generation bigint,lease_until timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
BEGIN
    PERFORM jobs.assert_application_mutation();
    IF requested_scope IS NULL OR requested_holder IS NULL OR requested_lease_micros < 5000000 OR requested_lease_micros > 300000000 THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='invalid consolidation claim request'; END IF;
    UPDATE brain.memory_consolidation_checkpoints AS checkpoint SET timeline_id=event.restored_timeline_id,change_sequence=0,updated_at=statement_timestamp()
    FROM jobs.restore_events AS event
    WHERE checkpoint.scope_id=requested_scope AND checkpoint.lease_until IS NULL
      AND event.previous_timeline_id=checkpoint.timeline_id AND checkpoint.change_sequence>=event.restored_change_sequence;
    INSERT INTO brain.memory_consolidation_checkpoints(scope_id,timeline_id)
    SELECT scope.id,(WITH RECURSIVE lineage(timeline_id) AS (
      SELECT state.timeline_id FROM jobs.server_state AS state WHERE state.singleton
      UNION
      SELECT event.previous_timeline_id FROM jobs.restore_events AS event JOIN lineage ON event.restored_timeline_id=lineage.timeline_id
    ) SELECT candidate.timeline_id FROM lineage AS candidate WHERE NOT EXISTS (SELECT 1 FROM jobs.restore_events AS event WHERE event.restored_timeline_id=candidate.timeline_id))
    FROM brain.scopes AS scope WHERE scope.id=requested_scope ON CONFLICT (scope_id) DO NOTHING;
    RETURN QUERY UPDATE brain.memory_consolidation_checkpoints AS checkpoint SET lease_holder=requested_holder,lease_token=gen_random_uuid(),lease_generation=checkpoint.lease_generation+1,lease_until=statement_timestamp()+(requested_lease_micros * interval '1 microsecond'),updated_at=statement_timestamp()
    WHERE checkpoint.scope_id=requested_scope AND (checkpoint.lease_until IS NULL OR checkpoint.lease_until <= statement_timestamp()) RETURNING checkpoint.scope_id,checkpoint.timeline_id,checkpoint.change_sequence,checkpoint.lease_holder,checkpoint.lease_token,checkpoint.lease_generation,checkpoint.lease_until;
END
$function$;

CREATE OR REPLACE FUNCTION brain.advance_memory_consolidation_checkpoint(requested_scope uuid, requested_token uuid, requested_generation bigint, requested_timeline uuid, requested_sequence bigint)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $function$
BEGIN
    PERFORM jobs.assert_application_mutation();
    UPDATE brain.memory_consolidation_checkpoints AS checkpoint SET timeline_id=requested_timeline,change_sequence=requested_sequence,lease_holder=NULL,lease_token=NULL,lease_until=NULL,updated_at=statement_timestamp()
    FROM jobs.server_state AS state
    WHERE state.singleton AND checkpoint.scope_id=requested_scope AND checkpoint.lease_token=requested_token AND checkpoint.lease_generation=requested_generation AND checkpoint.lease_until>statement_timestamp()
      AND requested_sequence>=checkpoint.change_sequence AND ((checkpoint.timeline_id=state.timeline_id AND requested_timeline=state.timeline_id AND requested_sequence<=state.change_sequence) OR (requested_timeline=checkpoint.timeline_id AND EXISTS (SELECT 1 FROM jobs.restore_events AS event WHERE event.previous_timeline_id=checkpoint.timeline_id AND requested_sequence<=event.restored_change_sequence)));
    RETURN FOUND;
END
$function$;

CREATE OR REPLACE FUNCTION jobs.rotate_restored_timeline(
    requested_backup_id uuid,
    expected_installation_id uuid,
    expected_timeline_id uuid,
    expected_change_sequence bigint
)
RETURNS TABLE (installation_id uuid, timeline_id uuid, change_sequence bigint)
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
DECLARE
    next_timeline uuid;
BEGIN
    SELECT state.timeline_id
    INTO next_timeline
    FROM jobs.server_state AS state
    JOIN jobs.restore_events AS event
      ON event.installation_id = state.installation_id
     AND event.restored_timeline_id = state.timeline_id
     AND event.restored_change_sequence = state.change_sequence
    WHERE state.singleton
      AND event.backup_id = requested_backup_id
      AND event.installation_id = expected_installation_id
      AND event.previous_timeline_id = expected_timeline_id
      AND event.restored_change_sequence = expected_change_sequence;
    IF FOUND THEN
        RETURN QUERY
        SELECT state.installation_id, state.timeline_id, state.change_sequence
        FROM jobs.server_state AS state WHERE state.singleton;
        RETURN;
    END IF;
    next_timeline := gen_random_uuid();
    UPDATE jobs.server_state AS state
    SET timeline_id = next_timeline,
        timeline_started_at = statement_timestamp()
    WHERE state.singleton
      AND state.installation_id = expected_installation_id
      AND state.timeline_id = expected_timeline_id
      AND state.change_sequence = expected_change_sequence;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'restored state does not match the verified backup';
    END IF;
    UPDATE brain.memory_consolidation_checkpoints AS checkpoint
    SET lease_holder=NULL,lease_token=NULL,lease_generation=checkpoint.lease_generation+1,lease_until=NULL,updated_at=statement_timestamp()
    WHERE checkpoint.lease_until IS NOT NULL;
    INSERT INTO jobs.restore_events (
        restore_id, backup_id, installation_id, previous_timeline_id,
        restored_timeline_id, restored_change_sequence
    ) VALUES (
        gen_random_uuid(), requested_backup_id, expected_installation_id,
        expected_timeline_id, next_timeline, expected_change_sequence
    );
    RETURN QUERY
    SELECT state.installation_id, state.timeline_id, state.change_sequence
    FROM jobs.server_state AS state WHERE state.singleton;
END
$function$;
