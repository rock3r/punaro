ALTER TABLE relay.projects
ADD COLUMN identity_generation bigint NOT NULL DEFAULT 0 CHECK (identity_generation >= 0),
ADD COLUMN acl_generation bigint NOT NULL DEFAULT 0 CHECK (acl_generation >= 0),
ADD COLUMN content_generation bigint NOT NULL DEFAULT 0 CHECK (content_generation >= 0),
ADD COLUMN merged_into uuid REFERENCES relay.projects(id),
ADD COLUMN merged_at timestamptz,
ADD CHECK ((merged_into IS NULL) = (merged_at IS NULL)),
ADD CHECK (merged_into IS NULL OR merged_into <> id);

CREATE TABLE auth.project_acl_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    global_generation bigint NOT NULL DEFAULT 0 CHECK (global_generation >= 0)
);

INSERT INTO auth.project_acl_state (singleton) VALUES (true);

CREATE TABLE relay.project_identities (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id uuid NOT NULL REFERENCES relay.projects(id),
    kind text NOT NULL CONSTRAINT project_identities_kind_check CHECK (kind IN ('local_git', 'git_remote', 'operator_alias', 'workspace')),
    normalized_locator text NOT NULL
        CONSTRAINT project_identities_locator_min_check CHECK (char_length(normalized_locator) >= 1)
        CONSTRAINT project_identities_locator_max_check CHECK (char_length(normalized_locator) <= 2048)
        CONSTRAINT project_identities_locator_bytes_check CHECK (octet_length(normalized_locator) <= 8192)
        CONSTRAINT project_identities_locator_control_check CHECK (normalized_locator !~ '[[:cntrl:]]'),
    created_by uuid NOT NULL REFERENCES auth.principals(id),
    verified_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    UNIQUE (kind, normalized_locator)
);

CREATE INDEX project_identities_project
ON relay.project_identities (project_id, id);

CREATE TABLE relay.project_lookup_aliases (
    alias_project_id uuid PRIMARY KEY REFERENCES relay.projects(id),
    canonical_project_id uuid NOT NULL REFERENCES relay.projects(id),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CHECK (alias_project_id <> canonical_project_id)
);

CREATE INDEX project_lookup_aliases_canonical
ON relay.project_lookup_aliases (canonical_project_id, alias_project_id);

CREATE TABLE relay.project_merge_previews (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_principal_id uuid NOT NULL REFERENCES auth.principals(id),
    source_project_id uuid NOT NULL REFERENCES relay.projects(id),
    canonical_project_id uuid NOT NULL REFERENCES relay.projects(id),
    identity_id uuid NOT NULL REFERENCES relay.project_identities(id),
    source_identity_generation bigint NOT NULL CONSTRAINT project_merge_previews_source_identity_generation_check CHECK (source_identity_generation >= 0),
    source_acl_generation bigint NOT NULL CONSTRAINT project_merge_previews_source_acl_generation_check CHECK (source_acl_generation >= 0),
    source_content_generation bigint NOT NULL CONSTRAINT project_merge_previews_source_content_generation_check CHECK (source_content_generation >= 0),
    canonical_identity_generation bigint NOT NULL CONSTRAINT project_merge_previews_canonical_identity_generation_check CHECK (canonical_identity_generation >= 0),
    canonical_acl_generation bigint NOT NULL CONSTRAINT project_merge_previews_canonical_acl_generation_check CHECK (canonical_acl_generation >= 0),
    canonical_content_generation bigint NOT NULL CONSTRAINT project_merge_previews_canonical_content_generation_check CHECK (canonical_content_generation >= 0),
    global_acl_generation bigint NOT NULL CONSTRAINT project_merge_previews_global_acl_generation_check CHECK (global_acl_generation >= 0),
    identity_count integer NOT NULL
        CONSTRAINT project_merge_previews_identity_count_min_check CHECK (identity_count >= 1)
        CONSTRAINT project_merge_previews_identity_count_max_check CHECK (identity_count <= 100),
    grant_count integer NOT NULL
        CONSTRAINT project_merge_previews_grant_count_min_check CHECK (grant_count >= 0)
        CONSTRAINT project_merge_previews_grant_count_max_check CHECK (grant_count <= 1000),
    alias_count integer NOT NULL
        CONSTRAINT project_merge_previews_alias_count_min_check CHECK (alias_count >= 0)
        CONSTRAINT project_merge_previews_alias_count_max_check CHECK (alias_count <= 1000),
    newly_authorized_principal_ids uuid[] NOT NULL DEFAULT '{}'::uuid[] CONSTRAINT project_merge_previews_new_principals_check CHECK (cardinality(newly_authorized_principal_ids) <= 256),
    private_record_count integer NOT NULL DEFAULT 0
        CONSTRAINT project_merge_previews_private_count_min_check CHECK (private_record_count >= 0)
        CONSTRAINT project_merge_previews_private_count_max_check CHECK (private_record_count <= 1000),
    conflict_count integer NOT NULL DEFAULT 0
        CONSTRAINT project_merge_previews_conflict_count_min_check CHECK (conflict_count >= 0)
        CONSTRAINT project_merge_previews_conflict_count_max_check CHECK (conflict_count <= 1000),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    result jsonb CONSTRAINT project_merge_previews_result_check CHECK (result IS NULL OR octet_length(result::text) <= 4096),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT project_merge_previews_distinct_projects_check CHECK (source_project_id <> canonical_project_id),
    CONSTRAINT project_merge_previews_expiry_check CHECK (expires_at > created_at),
    CONSTRAINT project_merge_previews_consumption_check CHECK ((consumed_at IS NULL AND result IS NULL) OR (consumed_at IS NOT NULL AND result IS NOT NULL))
);

CREATE INDEX project_merge_previews_live_actor
ON relay.project_merge_previews (actor_principal_id, expires_at, id)
WHERE consumed_at IS NULL;

CREATE INDEX project_merge_previews_prune
ON relay.project_merge_previews (COALESCE(consumed_at, expires_at), id);

ALTER TABLE audit.events DROP CONSTRAINT events_action_check;
ALTER TABLE audit.events ADD CONSTRAINT events_action_check CHECK (action IN (
    'principal.create', 'project.create', 'grant.create', 'grant.delete',
    'job.enqueue', 'job.complete', 'job.retry', 'job.fail',
    'owner.bootstrap', 'enrollment.create', 'enrollment.redeem',
    'credential.rotate', 'credential.revoke',
    'legacy.register', 'legacy.exchange', 'legacy.retire', 'legacy.disable',
    'project.identity.attach', 'project.merge.preview', 'project.merge'
));

ALTER TABLE audit.events DROP CONSTRAINT events_target_kind_check;
ALTER TABLE audit.events ADD CONSTRAINT events_target_kind_check CHECK (target_kind IN (
    'principal', 'project', 'grant', 'job', 'enrollment', 'credential',
    'legacy_machine', 'project_identity', 'project_merge'
));

REVOKE INSERT, UPDATE ON relay.projects FROM punaro_app;
GRANT INSERT (display_name, created_by) ON relay.projects TO punaro_app;
GRANT UPDATE (identity_generation, acl_generation, content_generation, merged_into, merged_at) ON relay.projects TO punaro_app;

GRANT SELECT ON auth.project_acl_state TO punaro_app;
GRANT UPDATE (global_generation) ON auth.project_acl_state TO punaro_app;

GRANT SELECT ON relay.project_identities TO punaro_app;
GRANT INSERT (project_id, kind, normalized_locator, created_by) ON relay.project_identities TO punaro_app;
GRANT UPDATE (project_id) ON relay.project_identities TO punaro_app;

GRANT SELECT ON relay.project_lookup_aliases TO punaro_app;
GRANT INSERT (alias_project_id, canonical_project_id) ON relay.project_lookup_aliases TO punaro_app;
GRANT UPDATE (canonical_project_id) ON relay.project_lookup_aliases TO punaro_app;

GRANT SELECT, DELETE ON relay.project_merge_previews TO punaro_app;
GRANT INSERT (
    actor_principal_id, source_project_id, canonical_project_id, identity_id,
    source_identity_generation, source_acl_generation, source_content_generation,
    canonical_identity_generation, canonical_acl_generation, canonical_content_generation,
    global_acl_generation, identity_count, grant_count, alias_count,
    newly_authorized_principal_ids, expires_at
) ON relay.project_merge_previews TO punaro_app;
GRANT UPDATE (consumed_at, result) ON relay.project_merge_previews TO punaro_app;
