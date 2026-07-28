CREATE TABLE brain.memory_consolidation_proposal_sources (
    proposal_id uuid NOT NULL REFERENCES brain.memory_proposals(id) ON DELETE CASCADE,
    ordinal smallint NOT NULL CONSTRAINT memory_consolidation_proposal_sources_ordinal_check CHECK (ordinal BETWEEN 0 AND 127),
    timeline_id uuid NOT NULL,
    item_id uuid NOT NULL,
    revision bigint NOT NULL CONSTRAINT memory_consolidation_proposal_sources_revision_check CHECK (revision >= 1),
    change_sequence bigint NOT NULL CONSTRAINT memory_consolidation_proposal_sources_sequence_check CHECK (change_sequence >= 0),
    PRIMARY KEY (proposal_id, ordinal),
    CONSTRAINT memory_consolidation_proposal_sources_item_key UNIQUE (proposal_id, item_id)
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
