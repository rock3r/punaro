CREATE OR REPLACE FUNCTION brain.read_memory_consolidation_documents(requested_scope uuid, requested_token uuid, requested_generation bigint)
RETURNS TABLE(timeline_id uuid,item_id uuid,revision bigint,change_sequence bigint,document jsonb,is_fence boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $function$
BEGIN
    RETURN QUERY
    SELECT source.timeline_id,
           CASE WHEN source.item_id IS NOT NULL
                     AND scan.revision=source.revision
                     AND scan.rule_version=guard.rule_version
                     AND scan.rule_digest=guard.rule_digest
                     AND scan.exception_generation=COALESCE(project_state.exception_generation,0)
                     AND scan.outcome='clear'
                THEN source.item_id END,
           CASE WHEN source.item_id IS NOT NULL
                     AND scan.revision=source.revision
                     AND scan.rule_version=guard.rule_version
                     AND scan.rule_digest=guard.rule_digest
                     AND scan.exception_generation=COALESCE(project_state.exception_generation,0)
                     AND scan.outcome='clear'
                THEN source.revision END,
           source.change_sequence,
           CASE WHEN source.item_id IS NOT NULL
                     AND scan.revision=source.revision
                     AND scan.rule_version=guard.rule_version
                     AND scan.rule_digest=guard.rule_digest
                     AND scan.exception_generation=COALESCE(project_state.exception_generation,0)
                     AND scan.outcome='clear'
                THEN revision.document END,
           source.is_fence
    FROM brain.read_memory_consolidation_sources(requested_scope,requested_token,requested_generation) AS source
    CROSS JOIN brain.secret_guard_state AS guard
    LEFT JOIN brain.memory_revisions AS revision ON revision.item_id=source.item_id AND revision.revision=source.revision
    LEFT JOIN brain.memory_items AS item ON item.id=source.item_id
    LEFT JOIN brain.scopes AS scope ON scope.id=item.scope_id
    LEFT JOIN brain.memory_secret_scans AS scan ON scan.item_id=source.item_id
    LEFT JOIN brain.secret_project_state AS project_state ON project_state.project_id=scope.project_id
    ORDER BY source.change_sequence,source.item_id;
END
$function$;
