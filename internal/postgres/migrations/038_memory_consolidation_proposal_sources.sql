CREATE TABLE brain.memory_consolidation_proposal_sources (
    proposal_id uuid NOT NULL REFERENCES brain.memory_proposals(id) ON DELETE CASCADE,
    ordinal smallint NOT NULL CONSTRAINT memory_consolidation_proposal_sources_ordinal_check CHECK (ordinal BETWEEN 0 AND 127),
    timeline_id uuid NOT NULL,
    item_id uuid NOT NULL,
    revision bigint NOT NULL CONSTRAINT memory_consolidation_proposal_sources_revision_check CHECK (revision >= 1),
    change_sequence bigint NOT NULL CONSTRAINT memory_consolidation_proposal_sources_sequence_check CHECK (change_sequence >= 0),
    PRIMARY KEY (proposal_id, ordinal)
    -- Provenance retains opaque historical coordinates. It must not prevent
    -- an authorized irreversible purge of the referenced item or revision.
);

CREATE INDEX memory_consolidation_proposal_sources_item_revision
ON brain.memory_consolidation_proposal_sources (item_id, revision, proposal_id);

CREATE FUNCTION brain.guard_memory_consolidation_proposal_source()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    PERFORM 1
    FROM brain.memory_proposals AS proposal
    JOIN brain.scopes AS proposal_scope ON proposal_scope.id=proposal.scope_id
    JOIN brain.memory_items AS item ON item.id=NEW.item_id
    JOIN brain.scopes AS item_scope ON item_scope.id=item.scope_id AND item_scope.id=proposal_scope.id
    WHERE proposal.id=NEW.proposal_id
      AND proposal.state='pending'
      AND proposal.assembly_xid=pg_current_xact_id();
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='consolidation proposal source is immutable or outside its scope';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER memory_consolidation_proposal_source_insert_guard
BEFORE INSERT ON brain.memory_consolidation_proposal_sources
FOR EACH ROW EXECUTE FUNCTION brain.guard_memory_consolidation_proposal_source();

CREATE TRIGGER application_mutation_fence
BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON brain.memory_consolidation_proposal_sources
FOR EACH STATEMENT EXECUTE FUNCTION jobs.guard_application_mutation();

REVOKE ALL ON brain.memory_consolidation_proposal_sources FROM PUBLIC, punaro_app;
REVOKE ALL ON FUNCTION brain.guard_memory_consolidation_proposal_source() FROM PUBLIC;
GRANT SELECT ON brain.memory_consolidation_proposal_sources TO punaro_app;
GRANT INSERT (proposal_id, ordinal, timeline_id, item_id, revision, change_sequence)
    ON brain.memory_consolidation_proposal_sources TO punaro_app;

-- Consolidation is restricted to the curated canonical layer. Evidence is
-- immutable, revision-bound supporting material and cannot be applied by an
-- ordinary consolidation proposal. Preserve it as a non-actionable gap in
-- the fenced page so a mixed change stream remains stageable and its cursor
-- can advance.
CREATE OR REPLACE FUNCTION brain.read_memory_consolidation_documents(requested_scope uuid, requested_token uuid, requested_generation bigint)
RETURNS TABLE(timeline_id uuid,item_id uuid,revision bigint,change_sequence bigint,document jsonb,content_sha256 bytea,is_fence boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $function$
DECLARE
    raw_page jsonb;
    source_page jsonb;
BEGIN
    PERFORM 1
    FROM brain.memory_consolidation_checkpoints AS checkpoint
    WHERE checkpoint.scope_id=requested_scope
      AND checkpoint.lease_token=requested_token
      AND checkpoint.lease_generation=requested_generation
      AND checkpoint.lease_until>statement_timestamp()
    FOR SHARE OF checkpoint;
    IF NOT FOUND THEN
        RETURN;
    END IF;
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
               CASE WHEN raw.item_id IS NOT NULL AND item.layer='curated' AND item.state='active' AND item.current_revision=raw.revision AND NOT EXISTS (SELECT 1 FROM brain.memory_quarantines AS quarantine WHERE quarantine.item_id=raw.item_id AND (quarantine.released_at IS NULL OR raw.revision<>item.current_revision)) THEN raw.item_id END AS item_id,
               CASE WHEN raw.item_id IS NOT NULL AND item.layer='curated' AND item.state='active' AND item.current_revision=raw.revision AND NOT EXISTS (SELECT 1 FROM brain.memory_quarantines AS quarantine WHERE quarantine.item_id=raw.item_id AND (quarantine.released_at IS NULL OR raw.revision<>item.current_revision)) THEN raw.revision END AS revision,
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
        LEFT JOIN relay.project_lookup_aliases AS alias ON alias.alias_project_id=scope.project_id
        LEFT JOIN brain.secret_project_state AS project_state ON project_state.project_id=COALESCE(alias.canonical_project_id,scope.project_id)
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
    SELECT source.timeline_id,source.item_id,source.revision,source.change_sequence,revision.document,revision.content_sha256,source.is_fence
    FROM jsonb_to_recordset(source_page) AS source(timeline_id uuid,item_id uuid,revision bigint,change_sequence bigint,is_fence boolean)
    LEFT JOIN brain.memory_revisions AS revision ON revision.item_id=source.item_id AND revision.revision=source.revision
    ORDER BY source.change_sequence,source.item_id;
END
$function$;

REVOKE ALL ON FUNCTION brain.read_memory_consolidation_documents(uuid,uuid,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION brain.read_memory_consolidation_documents(uuid,uuid,bigint) TO punaro_app;
