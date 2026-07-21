CREATE TABLE brain.scopes (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id uuid NOT NULL UNIQUE REFERENCES relay.projects(id),
    created_by uuid NOT NULL REFERENCES auth.principals(id),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp()
);

CREATE TABLE brain.memory_items (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id uuid NOT NULL REFERENCES brain.scopes(id),
    kind text NOT NULL CONSTRAINT memory_items_kind_check CHECK (
        kind ~ '^[a-z][a-z0-9_.:-]{0,63}$'
    ),
    state text NOT NULL DEFAULT 'active'
        CONSTRAINT memory_items_state_check CHECK (state IN ('active', 'archived')),
    trust text NOT NULL CONSTRAINT memory_items_trust_check CHECK (
        trust ~ '^[a-z][a-z0-9_.:-]{0,63}$'
    ),
    logical_key text CONSTRAINT memory_items_logical_key_check CHECK (
        logical_key IS NULL OR (
            char_length(logical_key) BETWEEN 1 AND 128
            AND octet_length(logical_key) <= 512
            AND logical_key !~ '[[:cntrl:]]'
        )
    ),
    current_revision bigint NOT NULL
        CONSTRAINT memory_items_current_revision_check CHECK (current_revision >= 1),
    created_by uuid NOT NULL REFERENCES auth.principals(id),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT memory_items_timestamp_check CHECK (updated_at >= created_at)
);

CREATE UNIQUE INDEX memory_items_scope_logical_key
ON brain.memory_items (scope_id, logical_key)
WHERE logical_key IS NOT NULL;

CREATE INDEX memory_items_scope_state
ON brain.memory_items (scope_id, state, id);

CREATE TABLE brain.memory_revisions (
    item_id uuid NOT NULL REFERENCES brain.memory_items(id) ON DELETE CASCADE,
    revision bigint NOT NULL CONSTRAINT memory_revisions_revision_check CHECK (revision >= 1),
    document jsonb NOT NULL CONSTRAINT memory_revisions_document_check CHECK (
        jsonb_typeof(document) = 'object'
        AND octet_length(document::text) <= 262144
    ),
    content_sha256 bytea NOT NULL
        CONSTRAINT memory_revisions_content_sha256_check CHECK (octet_length(content_sha256) = 32),
    author_principal_id uuid NOT NULL REFERENCES auth.principals(id),
    operation text NOT NULL
        CONSTRAINT memory_revisions_operation_check CHECK (operation IN ('create', 'update', 'archive', 'restore')),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (item_id, revision)
);

ALTER TABLE brain.memory_items
ADD CONSTRAINT memory_items_current_revision_fkey
FOREIGN KEY (id, current_revision)
REFERENCES brain.memory_revisions(item_id, revision)
DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE brain.memory_changes (
    timeline_id uuid NOT NULL,
    change_sequence bigint NOT NULL
        CONSTRAINT memory_changes_sequence_check CHECK (change_sequence >= 1),
    scope_id uuid NOT NULL REFERENCES brain.scopes(id),
    item_id uuid NOT NULL,
    operation text NOT NULL
        CONSTRAINT memory_changes_operation_check CHECK (operation IN ('create', 'update', 'archive', 'restore', 'delete')),
    revision bigint NOT NULL CONSTRAINT memory_changes_revision_check CHECK (revision >= 1),
    occurred_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (timeline_id, change_sequence)
);

CREATE INDEX memory_changes_scope_cursor
ON brain.memory_changes (scope_id, timeline_id, change_sequence, item_id);

CREATE TABLE brain.memory_tombstones (
    item_id uuid PRIMARY KEY,
    scope_id uuid NOT NULL REFERENCES brain.scopes(id),
    deleted_by uuid NOT NULL REFERENCES auth.principals(id),
    timeline_id uuid NOT NULL,
    change_sequence bigint NOT NULL
        CONSTRAINT memory_tombstones_sequence_check CHECK (change_sequence >= 1),
    deleted_at timestamptz NOT NULL DEFAULT statement_timestamp()
);

CREATE FUNCTION brain.purge_memory(
    requested_principal uuid,
    requested_project uuid,
    requested_item uuid,
    expected_revision bigint
)
RETURNS TABLE (scope_id uuid, revision bigint, timeline_id uuid, change_sequence bigint)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    active_project uuid;
    authority_id uuid;
    deleted_scope uuid;
    deleted_revision bigint;
    next_timeline uuid;
    next_sequence bigint;
BEGIN
    PERFORM jobs.assert_application_mutation();
    SELECT project.id INTO active_project
    FROM relay.projects AS project
    WHERE project.id = requested_project AND project.merged_into IS NULL
    FOR UPDATE;
    IF active_project IS NULL THEN
        RETURN;
    END IF;
    SELECT capability_grant.id INTO authority_id
    FROM auth.principals AS principal
    JOIN auth.capability_grants AS capability_grant
      ON capability_grant.principal_id = principal.id
    WHERE principal.id = requested_principal
      AND principal.disabled_at IS NULL
      AND capability_grant.revoked_at IS NULL
      AND capability_grant.capability = 'memory.purge'
      AND ((capability_grant.scope = 'project' AND capability_grant.project_id = requested_project)
           OR (capability_grant.scope = 'all_projects' AND capability_grant.project_id IS NULL))
    ORDER BY capability_grant.id
    LIMIT 1
    FOR SHARE OF principal, capability_grant;
    IF authority_id IS NULL THEN
        RETURN;
    END IF;
    SELECT item.scope_id, item.current_revision
    INTO deleted_scope, deleted_revision
    FROM brain.memory_items AS item
    JOIN brain.scopes AS scope ON scope.id = item.scope_id
    WHERE item.id = requested_item
      AND item.current_revision = expected_revision
      AND scope.project_id = requested_project
    FOR UPDATE OF item;
    IF deleted_scope IS NULL THEN
        RETURN;
    END IF;
    SELECT advanced.timeline_id, advanced.change_sequence
    INTO next_timeline, next_sequence
    FROM jobs.advance_change_sequence() AS advanced;
    INSERT INTO brain.memory_changes (
        timeline_id, change_sequence, scope_id, item_id, operation, revision
    ) VALUES (
        next_timeline, next_sequence, deleted_scope, requested_item, 'delete', deleted_revision
    );
    INSERT INTO brain.memory_tombstones (
        item_id, scope_id, deleted_by, timeline_id, change_sequence
    ) VALUES (
        requested_item, deleted_scope, requested_principal, next_timeline, next_sequence
    );
    INSERT INTO audit.events (
        principal_id, project_id, action, outcome, target_kind, target_id
    ) VALUES (
        requested_principal, requested_project, 'memory.delete', 'succeeded', 'memory_item', requested_item
    );
    UPDATE relay.projects
    SET content_generation = content_generation + 1
    WHERE id = active_project;
    DELETE FROM brain.memory_items AS item
    WHERE item.id = requested_item AND item.current_revision = deleted_revision;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'memory purge target changed';
    END IF;
    scope_id := deleted_scope;
    revision := deleted_revision;
    timeline_id := next_timeline;
    change_sequence := next_sequence;
    RETURN NEXT;
END
$function$;

ALTER TABLE audit.events DROP CONSTRAINT events_action_check;
ALTER TABLE audit.events ADD CONSTRAINT events_action_check CHECK (action IN (
    'principal.create', 'project.create', 'grant.create', 'grant.delete',
    'job.enqueue', 'job.complete', 'job.retry', 'job.fail',
    'owner.bootstrap', 'enrollment.create', 'enrollment.redeem',
    'credential.rotate', 'credential.revoke',
    'legacy.register', 'legacy.exchange', 'legacy.retire', 'legacy.disable',
    'project.identity.attach', 'project.merge.preview', 'project.merge',
    'memory.create', 'memory.update', 'memory.archive', 'memory.restore', 'memory.delete'
));

ALTER TABLE audit.events DROP CONSTRAINT events_target_kind_check;
ALTER TABLE audit.events ADD CONSTRAINT events_target_kind_check CHECK (target_kind IN (
    'principal', 'project', 'grant', 'job', 'enrollment', 'credential',
    'legacy_machine', 'project_identity', 'project_merge', 'memory_item'
));

DO $block$
DECLARE
    target regclass;
BEGIN
    FOREACH target IN ARRAY ARRAY[
        'brain.scopes'::regclass,
        'brain.memory_items'::regclass,
        'brain.memory_revisions'::regclass,
        'brain.memory_changes'::regclass,
        'brain.memory_tombstones'::regclass
    ]
    LOOP
        EXECUTE format(
            'CREATE TRIGGER application_mutation_fence BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION jobs.guard_application_mutation()',
            target
        );
    END LOOP;
END
$block$;

REVOKE ALL ON brain.scopes, brain.memory_items, brain.memory_revisions, brain.memory_changes, brain.memory_tombstones FROM PUBLIC, punaro_app;
REVOKE ALL ON FUNCTION brain.purge_memory(uuid,uuid,uuid,bigint) FROM PUBLIC;

GRANT USAGE ON SCHEMA brain TO punaro_app;
GRANT SELECT ON brain.scopes, brain.memory_items, brain.memory_revisions, brain.memory_changes TO punaro_app;
GRANT INSERT ON brain.scopes, brain.memory_items, brain.memory_revisions, brain.memory_changes TO punaro_app;
GRANT UPDATE (kind, state, trust, logical_key, current_revision, updated_at) ON brain.memory_items TO punaro_app;
GRANT EXECUTE ON FUNCTION brain.purge_memory(uuid,uuid,uuid,bigint) TO punaro_app;
REVOKE CREATE ON SCHEMA brain FROM punaro_app;
