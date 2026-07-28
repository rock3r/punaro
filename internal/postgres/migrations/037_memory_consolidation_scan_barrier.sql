CREATE OR REPLACE FUNCTION brain.read_memory_consolidation_documents(requested_scope uuid, requested_token uuid, requested_generation bigint)
RETURNS TABLE(timeline_id uuid,item_id uuid,revision bigint,change_sequence bigint,document jsonb,is_fence boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $function$
DECLARE
    raw_page jsonb;
    source_page jsonb;
BEGIN
    LOCK TABLE brain.secret_guard_state IN SHARE MODE;
    LOCK TABLE brain.secret_project_state IN SHARE MODE;
    WITH raw_source AS MATERIALIZED (
        SELECT * FROM brain.read_memory_consolidation_sources(requested_scope,requested_token,requested_generation)
    ) SELECT COALESCE(jsonb_agg(jsonb_build_object('timeline_id',raw_source.timeline_id,'item_id',raw_source.item_id,'revision',raw_source.revision,'change_sequence',raw_source.change_sequence,'is_fence',raw_source.is_fence) ORDER BY raw_source.change_sequence,raw_source.item_id),'[]'::jsonb)
    INTO raw_page FROM raw_source;
    PERFORM 1
    FROM brain.memory_items AS item
    JOIN jsonb_to_recordset(raw_page) AS raw(timeline_id uuid,item_id uuid,revision bigint,change_sequence bigint,is_fence boolean) ON raw.item_id=item.id
    ORDER BY item.id
    FOR SHARE OF item;
    LOCK TABLE brain.memory_quarantines IN SHARE MODE;
    PERFORM 1
    FROM brain.memory_secret_scans AS scan
    JOIN jsonb_to_recordset(raw_page) AS raw(timeline_id uuid,item_id uuid,revision bigint,change_sequence bigint,is_fence boolean) ON raw.item_id=scan.item_id
    ORDER BY scan.item_id
    FOR SHARE OF scan;
    WITH raw AS MATERIALIZED (
        SELECT * FROM jsonb_to_recordset(raw_page) AS record(timeline_id uuid,item_id uuid,revision bigint,change_sequence bigint,is_fence boolean)
    ), source AS MATERIALIZED (
        SELECT raw.timeline_id,
               CASE WHEN raw.item_id IS NOT NULL AND item.state='active' AND item.current_revision=raw.revision AND NOT EXISTS (SELECT 1 FROM brain.memory_quarantines AS quarantine WHERE quarantine.item_id=raw.item_id AND (quarantine.released_at IS NULL OR raw.revision<>item.current_revision)) THEN raw.item_id END AS item_id,
               CASE WHEN raw.item_id IS NOT NULL AND item.state='active' AND item.current_revision=raw.revision AND NOT EXISTS (SELECT 1 FROM brain.memory_quarantines AS quarantine WHERE quarantine.item_id=raw.item_id AND (quarantine.released_at IS NULL OR raw.revision<>item.current_revision)) THEN raw.revision END AS revision,
               raw.change_sequence,raw.is_fence
        FROM raw LEFT JOIN brain.memory_items AS item ON item.id=raw.item_id
    ) SELECT COALESCE(jsonb_agg(jsonb_build_object('timeline_id',source.timeline_id,'item_id',source.item_id,'revision',source.revision,'change_sequence',source.change_sequence,'is_fence',source.is_fence) ORDER BY source.change_sequence,source.item_id),'[]'::jsonb)
    INTO source_page FROM source;
    IF EXISTS (
        SELECT 1
        FROM jsonb_to_recordset(source_page) AS source(timeline_id uuid,item_id uuid,revision bigint,change_sequence bigint,is_fence boolean)
        CROSS JOIN brain.secret_guard_state AS guard
        LEFT JOIN brain.memory_items AS item ON item.id=source.item_id
        LEFT JOIN brain.scopes AS scope ON scope.id=item.scope_id
        LEFT JOIN brain.memory_secret_scans AS scan ON scan.item_id=source.item_id
        LEFT JOIN brain.secret_project_state AS project_state ON project_state.project_id=scope.project_id
        WHERE source.item_id IS NOT NULL
          AND (scan.revision IS DISTINCT FROM source.revision
               OR scan.rule_version IS DISTINCT FROM guard.rule_version
               OR scan.rule_digest IS DISTINCT FROM guard.rule_digest
               OR scan.exception_generation IS DISTINCT FROM COALESCE(project_state.exception_generation,0)
               OR scan.outcome IS DISTINCT FROM 'clear')
    ) THEN
        RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='consolidation source scan coverage is stale';
    END IF;
    RETURN QUERY
    SELECT source.timeline_id,source.item_id,source.revision,source.change_sequence,revision.document,source.is_fence
    FROM jsonb_to_recordset(source_page) AS source(timeline_id uuid,item_id uuid,revision bigint,change_sequence bigint,is_fence boolean)
    LEFT JOIN brain.memory_revisions AS revision ON revision.item_id=source.item_id AND revision.revision=source.revision
    ORDER BY source.change_sequence,source.item_id;
END
$function$;
