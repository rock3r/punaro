CREATE TABLE brain.memory_proposals (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id uuid NOT NULL REFERENCES brain.scopes(id),
    action text NOT NULL CONSTRAINT memory_proposals_action_check CHECK (
        action IN ('create', 'update', 'archive', 'merge', 'split')
    ),
    state text NOT NULL DEFAULT 'pending' CONSTRAINT memory_proposals_state_check CHECK (
        state IN ('pending', 'approved', 'rejected')
    ),
    proposed_by uuid NOT NULL REFERENCES auth.principals(id),
    decided_by uuid REFERENCES auth.principals(id),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    decided_at timestamptz,
    payload_sha256 bytea NOT NULL CONSTRAINT memory_proposals_payload_sha256_check CHECK (octet_length(payload_sha256) = 32),
    payload bytea NOT NULL CONSTRAINT memory_proposals_payload_check CHECK (octet_length(payload) BETWEEN 2 AND 4194304),
    assembly_xid xid8 NOT NULL DEFAULT pg_current_xact_id(),
    decided_xid xid8,
    CONSTRAINT memory_proposals_decision_check CHECK (
        (state = 'pending' AND decided_by IS NULL AND decided_at IS NULL AND decided_xid IS NULL)
        OR (state IN ('approved', 'rejected') AND decided_by IS NOT NULL AND decided_at IS NOT NULL AND decided_at >= created_at AND decided_xid IS NOT NULL)
    )
);

CREATE INDEX memory_proposals_scope_state
ON brain.memory_proposals (scope_id, state, created_at, id);

CREATE TABLE brain.memory_proposal_steps (
    proposal_id uuid NOT NULL REFERENCES brain.memory_proposals(id) ON DELETE CASCADE,
    ordinal smallint NOT NULL CONSTRAINT memory_proposal_steps_ordinal_check CHECK (ordinal BETWEEN 0 AND 7),
    operation text NOT NULL CONSTRAINT memory_proposal_steps_operation_check CHECK (
        operation IN ('create', 'update', 'archive')
    ),
    item_id uuid,
    target_revision bigint CONSTRAINT memory_proposal_steps_target_revision_check CHECK (
        target_revision IS NULL OR target_revision >= 1
    ),
    logical_key text CONSTRAINT memory_proposal_steps_logical_key_check CHECK (
        logical_key IS NULL OR (
            char_length(logical_key) BETWEEN 1 AND 128
            AND octet_length(logical_key) <= 512
            AND logical_key !~ '[[:cntrl:]]'
        )
    ),
    kind text CONSTRAINT memory_proposal_steps_kind_check CHECK (
        kind IS NULL OR kind ~ '^[a-z][a-z0-9_.:-]{0,63}$'
    ),
    trust text CONSTRAINT memory_proposal_steps_trust_check CHECK (
        trust IS NULL OR trust ~ '^[a-z][a-z0-9_.:-]{0,63}$'
    ),
    document bytea CONSTRAINT memory_proposal_steps_document_check CHECK (
        document IS NULL OR (jsonb_typeof(convert_from(document, 'UTF8')::jsonb) = 'object' AND octet_length(document) <= 262144)
    ),
    archived boolean,
    CONSTRAINT memory_proposal_steps_shape_check CHECK (
        (operation = 'create' AND item_id IS NULL AND target_revision IS NULL
            AND kind IS NOT NULL AND trust IS NOT NULL AND document IS NOT NULL AND archived IS NULL)
        OR
        (operation = 'update' AND item_id IS NOT NULL AND target_revision IS NOT NULL
            AND kind IS NOT NULL AND trust IS NOT NULL AND document IS NOT NULL AND archived IS NULL)
        OR
        (operation = 'archive' AND item_id IS NOT NULL AND target_revision IS NOT NULL
            AND logical_key IS NULL AND kind IS NULL AND trust IS NULL AND document IS NULL AND archived IS NOT NULL)
    ),
    PRIMARY KEY (proposal_id, ordinal)
);

CREATE UNIQUE INDEX memory_proposal_steps_target
ON brain.memory_proposal_steps (proposal_id, item_id)
WHERE item_id IS NOT NULL;

CREATE TABLE brain.memory_proposal_evidence (
    proposal_id uuid NOT NULL REFERENCES brain.memory_proposals(id) ON DELETE CASCADE,
    ordinal smallint NOT NULL CONSTRAINT memory_proposal_evidence_ordinal_check CHECK (ordinal BETWEEN 0 AND 15),
    item_id uuid NOT NULL,
    revision bigint NOT NULL CONSTRAINT memory_proposal_evidence_revision_check CHECK (revision >= 1),
    PRIMARY KEY (proposal_id, ordinal),
    CONSTRAINT memory_proposal_evidence_exact_key UNIQUE (proposal_id, item_id)
);

CREATE INDEX memory_proposal_evidence_revision
ON brain.memory_proposal_evidence (item_id, revision, proposal_id);

CREATE TABLE brain.memory_proposal_results (
    proposal_id uuid NOT NULL,
    ordinal smallint NOT NULL,
    item_id uuid NOT NULL,
    revision bigint NOT NULL CONSTRAINT memory_proposal_results_revision_check CHECK (revision >= 1),
    PRIMARY KEY (proposal_id, ordinal),
    CONSTRAINT memory_proposal_results_item_key UNIQUE (proposal_id, item_id),
    CONSTRAINT memory_proposal_results_step_fkey FOREIGN KEY (proposal_id, ordinal)
        REFERENCES brain.memory_proposal_steps(proposal_id, ordinal) ON DELETE CASCADE
);

CREATE INDEX memory_proposal_results_item_revision
ON brain.memory_proposal_results (item_id, revision, proposal_id);

CREATE FUNCTION brain.guard_memory_proposal_child_insert()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM brain.memory_proposals
        WHERE id = NEW.proposal_id AND state = 'pending' AND assembly_xid = pg_current_xact_id()
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'memory proposal payload is immutable';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER memory_proposal_step_insert_guard
BEFORE INSERT ON brain.memory_proposal_steps
FOR EACH ROW EXECUTE FUNCTION brain.guard_memory_proposal_child_insert();

CREATE TRIGGER memory_proposal_evidence_insert_guard
BEFORE INSERT ON brain.memory_proposal_evidence
FOR EACH ROW EXECUTE FUNCTION brain.guard_memory_proposal_child_insert();

CREATE FUNCTION brain.guard_memory_proposal_result_insert()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM brain.memory_proposals AS proposal
        JOIN brain.memory_proposal_steps AS step
          ON step.proposal_id = proposal.id AND step.ordinal = NEW.ordinal
        JOIN brain.scopes AS proposal_scope ON proposal_scope.id = proposal.scope_id
        JOIN brain.memory_items AS item ON item.id = NEW.item_id AND item.current_revision = NEW.revision
        JOIN brain.scopes AS item_scope ON item_scope.id = item.scope_id AND item_scope.project_id = proposal_scope.project_id
        JOIN brain.memory_revisions AS revision ON revision.item_id = NEW.item_id AND revision.revision = NEW.revision
        WHERE proposal.id = NEW.proposal_id
          AND proposal.state = 'approved'
          AND proposal.decided_xid = pg_current_xact_id()
          AND proposal.decided_by = revision.author_principal_id
          AND item.xmin = pg_current_xact_id()::xid
          AND revision.xmin = pg_current_xact_id()::xid
          AND ((step.operation = 'create' AND NEW.revision = 1 AND revision.operation = 'create'
                AND item.logical_key IS NOT DISTINCT FROM step.logical_key AND item.kind = step.kind AND item.trust = step.trust
                AND revision.document = convert_from(step.document, 'UTF8')::jsonb)
            OR (step.operation = 'update' AND NEW.item_id = step.item_id AND NEW.revision = step.target_revision + 1 AND revision.operation = 'update'
                AND item.logical_key IS NOT DISTINCT FROM step.logical_key AND item.kind = step.kind AND item.trust = step.trust
                AND revision.document = convert_from(step.document, 'UTF8')::jsonb)
            OR (step.operation = 'archive' AND NEW.item_id = step.item_id AND NEW.revision = step.target_revision + 1 AND revision.operation = 'archive'
                AND item.state = 'archived' AND EXISTS (
                    SELECT 1 FROM brain.memory_revisions AS prior
                    WHERE prior.item_id = step.item_id AND prior.revision = step.target_revision AND prior.document = revision.document
                )))
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'memory proposal result is invalid';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER memory_proposal_result_insert_guard
BEFORE INSERT ON brain.memory_proposal_results
FOR EACH ROW EXECUTE FUNCTION brain.guard_memory_proposal_result_insert();

CREATE FUNCTION brain.guard_memory_proposal_results_complete()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF (NEW.state = 'approved' AND (
            SELECT count(*) FROM brain.memory_proposal_results WHERE proposal_id = NEW.id
        ) <> (
            SELECT count(*) FROM brain.memory_proposal_steps WHERE proposal_id = NEW.id
        ))
       OR (NEW.state = 'rejected' AND EXISTS (
            SELECT 1 FROM brain.memory_proposal_results WHERE proposal_id = NEW.id
       )) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'memory proposal results are incomplete';
    END IF;
    RETURN NULL;
END
$function$;

CREATE CONSTRAINT TRIGGER memory_proposal_results_complete
AFTER UPDATE OF state ON brain.memory_proposals
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION brain.guard_memory_proposal_results_complete();

CREATE FUNCTION brain.guard_memory_proposal_update()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF OLD.state <> 'pending'
       OR NEW.id <> OLD.id
       OR NEW.scope_id <> OLD.scope_id
       OR NEW.action <> OLD.action
       OR NEW.proposed_by <> OLD.proposed_by
       OR NEW.created_at <> OLD.created_at
       OR NEW.payload_sha256 <> OLD.payload_sha256
       OR NEW.payload <> OLD.payload
       OR NEW.assembly_xid <> OLD.assembly_xid
       OR NEW.state NOT IN ('approved', 'rejected')
       OR NEW.decided_by IS NULL
       OR NEW.decided_at IS NULL
       OR NEW.decided_at <> transaction_timestamp()
       OR NEW.decided_xid <> pg_current_xact_id() THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'memory proposal transition is invalid';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER memory_proposal_transition_guard
BEFORE UPDATE ON brain.memory_proposals
FOR EACH ROW EXECUTE FUNCTION brain.guard_memory_proposal_update();

ALTER TABLE audit.events DROP CONSTRAINT events_action_check;
ALTER TABLE audit.events ADD CONSTRAINT events_action_check CHECK (action IN (
    'principal.create', 'project.create', 'grant.create', 'grant.delete',
    'job.enqueue', 'job.complete', 'job.retry', 'job.fail',
    'owner.bootstrap', 'enrollment.create', 'enrollment.redeem',
    'credential.rotate', 'credential.revoke',
    'legacy.register', 'legacy.exchange', 'legacy.retire', 'legacy.disable',
    'project.identity.attach', 'project.merge.preview', 'project.merge',
    'memory.create', 'memory.evidence_create', 'memory.update', 'memory.archive', 'memory.restore', 'memory.delete',
    'memory.secret_exception.create', 'memory.secret_exception.revoke',
    'memory.secret_rescan', 'memory.quarantine', 'memory.quarantine_release',
    'memory.proposal.create', 'memory.proposal.approve', 'memory.proposal.reject'
));

ALTER TABLE audit.events DROP CONSTRAINT events_target_kind_check;
ALTER TABLE audit.events ADD CONSTRAINT events_target_kind_check CHECK (target_kind IN (
    'principal', 'project', 'grant', 'job', 'enrollment', 'credential',
    'legacy_machine', 'project_identity', 'project_merge', 'memory_item', 'memory_proposal'
));

DO $block$
DECLARE
    target regclass;
BEGIN
    FOREACH target IN ARRAY ARRAY[
        'brain.memory_proposals'::regclass,
        'brain.memory_proposal_steps'::regclass,
        'brain.memory_proposal_evidence'::regclass,
        'brain.memory_proposal_results'::regclass
    ]
    LOOP
        EXECUTE format(
            'CREATE TRIGGER application_mutation_fence BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION jobs.guard_application_mutation()',
            target
        );
    END LOOP;
END
$block$;

REVOKE ALL ON brain.memory_proposals, brain.memory_proposal_steps, brain.memory_proposal_evidence, brain.memory_proposal_results FROM PUBLIC, punaro_app;
REVOKE ALL ON FUNCTION brain.guard_memory_proposal_update() FROM PUBLIC;
REVOKE ALL ON FUNCTION brain.guard_memory_proposal_child_insert() FROM PUBLIC;
REVOKE ALL ON FUNCTION brain.guard_memory_proposal_result_insert() FROM PUBLIC;
REVOKE ALL ON FUNCTION brain.guard_memory_proposal_results_complete() FROM PUBLIC;
GRANT SELECT ON brain.memory_proposals, brain.memory_proposal_steps, brain.memory_proposal_evidence, brain.memory_proposal_results TO punaro_app;
GRANT INSERT (scope_id, action, proposed_by, payload_sha256, payload) ON brain.memory_proposals TO punaro_app;
GRANT INSERT (proposal_id, ordinal, operation, item_id, target_revision, logical_key, kind, trust, document, archived)
    ON brain.memory_proposal_steps TO punaro_app;
GRANT INSERT (proposal_id, ordinal, item_id, revision) ON brain.memory_proposal_evidence TO punaro_app;
GRANT INSERT (proposal_id, ordinal, item_id, revision) ON brain.memory_proposal_results TO punaro_app;
GRANT UPDATE (state, decided_by, decided_at, decided_xid) ON brain.memory_proposals TO punaro_app;
