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
    )
    SELECT fence.timeline_id,NULL::uuid,NULL::bigint,fence.change_sequence,true FROM fence
    UNION ALL
    SELECT fence.timeline_id,CASE WHEN change.operation<>'delete' AND NOT EXISTS (SELECT 1 FROM brain.memory_quarantines AS quarantine WHERE quarantine.item_id=change.item_id AND (quarantine.released_at IS NULL OR change.revision<=quarantine.detected_revision)) THEN change.item_id END,CASE WHEN change.operation<>'delete' AND NOT EXISTS (SELECT 1 FROM brain.memory_quarantines AS quarantine WHERE quarantine.item_id=change.item_id AND (quarantine.released_at IS NULL OR change.revision<=quarantine.detected_revision)) THEN change.revision END,change.change_sequence,false
    FROM fence JOIN brain.memory_changes AS change ON change.scope_id=fence.scope_id AND change.timeline_id=fence.timeline_id
    WHERE change.change_sequence>fence.change_sequence
    UNION ALL
    SELECT fence.timeline_id,NULL::uuid,NULL::bigint,fence.rebase_sequence,false
    FROM fence WHERE fence.rebase_sequence>fence.change_sequence
    ORDER BY 4,2
    LIMIT 129;
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
      AND requested_sequence>=checkpoint.change_sequence AND ((requested_timeline=state.timeline_id AND requested_sequence<=state.change_sequence) OR (requested_timeline=checkpoint.timeline_id AND EXISTS (SELECT 1 FROM jobs.restore_events AS event WHERE event.previous_timeline_id=checkpoint.timeline_id AND requested_sequence<=event.restored_change_sequence)));
    RETURN FOUND;
END
$function$;
