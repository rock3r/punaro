CREATE FUNCTION brain.read_memory_consolidation_sources(requested_scope uuid, requested_token uuid, requested_generation bigint)
RETURNS TABLE(timeline_id uuid,item_id uuid,revision bigint,change_sequence bigint,is_fence boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $function$
BEGIN
    IF requested_scope IS NULL OR requested_token IS NULL OR requested_generation < 1 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='invalid consolidation source request';
    END IF;
    RETURN QUERY WITH fence AS (
      SELECT checkpoint.timeline_id,checkpoint.scope_id,checkpoint.change_sequence
      FROM brain.memory_consolidation_checkpoints AS checkpoint
      JOIN jobs.server_state AS state ON state.singleton AND state.timeline_id=checkpoint.timeline_id
      WHERE checkpoint.scope_id=requested_scope AND checkpoint.lease_token=requested_token
        AND checkpoint.lease_generation=requested_generation AND checkpoint.lease_until > statement_timestamp()
    )
    SELECT fence.timeline_id,NULL::uuid,NULL::bigint,fence.change_sequence,true FROM fence
    UNION ALL
    SELECT fence.timeline_id,CASE WHEN NOT EXISTS (SELECT 1 FROM brain.memory_quarantines AS quarantine WHERE quarantine.item_id=change.item_id AND (quarantine.released_at IS NULL OR change.revision<=quarantine.detected_revision)) THEN change.item_id END,CASE WHEN NOT EXISTS (SELECT 1 FROM brain.memory_quarantines AS quarantine WHERE quarantine.item_id=change.item_id AND (quarantine.released_at IS NULL OR change.revision<=quarantine.detected_revision)) THEN change.revision END,change.change_sequence,false
    FROM fence JOIN brain.memory_changes AS change ON change.scope_id=fence.scope_id AND change.timeline_id=fence.timeline_id
    WHERE change.change_sequence>fence.change_sequence
    ORDER BY 4,2
    LIMIT 129;
END
$function$;
REVOKE ALL ON FUNCTION brain.read_memory_consolidation_sources(uuid,uuid,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION brain.read_memory_consolidation_sources(uuid,uuid,bigint) TO punaro_app;
