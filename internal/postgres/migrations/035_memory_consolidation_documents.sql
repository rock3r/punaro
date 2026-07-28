CREATE FUNCTION brain.read_memory_consolidation_documents(requested_scope uuid, requested_token uuid, requested_generation bigint)
RETURNS TABLE(timeline_id uuid,item_id uuid,revision bigint,change_sequence bigint,document jsonb,is_fence boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $function$
BEGIN
    RETURN QUERY
    SELECT source.timeline_id,source.item_id,source.revision,source.change_sequence,
           revision.document,source.is_fence
    FROM brain.read_memory_consolidation_sources(requested_scope,requested_token,requested_generation) AS source
    LEFT JOIN brain.memory_revisions AS revision
      ON revision.item_id=source.item_id AND revision.revision=source.revision
    ORDER BY source.change_sequence,source.item_id;
END
$function$;

REVOKE ALL ON FUNCTION brain.read_memory_consolidation_documents(uuid,uuid,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION brain.read_memory_consolidation_documents(uuid,uuid,bigint) TO punaro_app;
