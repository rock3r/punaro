CREATE TABLE brain.secret_project_state (
    project_id uuid PRIMARY KEY REFERENCES relay.projects(id),
    exception_generation bigint NOT NULL DEFAULT 0
        CONSTRAINT secret_project_state_generation_check CHECK (exception_generation >= 0),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp()
);

CREATE TABLE brain.memory_secret_scans (
    item_id uuid PRIMARY KEY,
    revision bigint NOT NULL CONSTRAINT memory_secret_scans_revision_check CHECK (revision >= 1),
    rule_version bigint NOT NULL CONSTRAINT memory_secret_scans_rule_version_check CHECK (rule_version >= 1),
    rule_digest bytea NOT NULL CONSTRAINT memory_secret_scans_rule_digest_check CHECK (octet_length(rule_digest) = 32),
    exception_generation bigint NOT NULL CONSTRAINT memory_secret_scans_generation_check CHECK (exception_generation >= 0),
    outcome text NOT NULL CONSTRAINT memory_secret_scans_outcome_check CHECK (outcome IN ('clear', 'quarantined')),
    scanned_by uuid NOT NULL REFERENCES auth.principals(id),
    scanned_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT memory_secret_scans_revision_fkey FOREIGN KEY (item_id, revision)
        REFERENCES brain.memory_revisions(item_id, revision) ON DELETE CASCADE
);

CREATE TABLE brain.memory_quarantines (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    item_id uuid NOT NULL,
    detected_revision bigint NOT NULL CONSTRAINT memory_quarantines_revision_check CHECK (detected_revision >= 1),
    rule_version bigint NOT NULL CONSTRAINT memory_quarantines_rule_version_check CHECK (rule_version >= 1),
    rule_id text NOT NULL CONSTRAINT memory_quarantines_rule_id_check CHECK (
        rule_id IN ('private-key', 'bearer-token', 'credential-assignment', 'sensitive-field')
    ),
    field_path text NOT NULL CONSTRAINT memory_quarantines_field_path_check CHECK (
        octet_length(field_path) BETWEEN 1 AND 1024
    ),
    value_fingerprint bytea NOT NULL CONSTRAINT memory_quarantines_fingerprint_check CHECK (
        octet_length(value_fingerprint) = 32
    ),
    quarantined_by uuid NOT NULL REFERENCES auth.principals(id),
    quarantined_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    released_by uuid REFERENCES auth.principals(id),
    released_at timestamptz,
    CONSTRAINT memory_quarantines_revision_fkey FOREIGN KEY (item_id, detected_revision)
        REFERENCES brain.memory_revisions(item_id, revision) ON DELETE CASCADE,
    CONSTRAINT memory_quarantines_release_check CHECK (
        (released_at IS NULL AND released_by IS NULL)
        OR (released_at >= quarantined_at AND released_by IS NOT NULL)
    )
);

CREATE UNIQUE INDEX memory_quarantines_active_item
ON brain.memory_quarantines (item_id)
WHERE released_at IS NULL;

CREATE INDEX memory_quarantines_item_history
ON brain.memory_quarantines (item_id, quarantined_at, id);

ALTER TABLE brain.memory_changes DROP CONSTRAINT memory_changes_operation_check;
ALTER TABLE brain.memory_changes ADD CONSTRAINT memory_changes_operation_check CHECK (
    operation IN ('create', 'update', 'archive', 'restore', 'delete', 'quarantine', 'quarantine_release')
);

ALTER TABLE audit.events DROP CONSTRAINT events_action_check;
ALTER TABLE audit.events ADD CONSTRAINT events_action_check CHECK (action IN (
    'principal.create', 'project.create', 'grant.create', 'grant.delete',
    'job.enqueue', 'job.complete', 'job.retry', 'job.fail',
    'owner.bootstrap', 'enrollment.create', 'enrollment.redeem',
    'credential.rotate', 'credential.revoke',
    'legacy.register', 'legacy.exchange', 'legacy.retire', 'legacy.disable',
    'project.identity.attach', 'project.merge.preview', 'project.merge',
    'memory.create', 'memory.update', 'memory.archive', 'memory.restore', 'memory.delete',
    'memory.secret_exception.create', 'memory.secret_exception.revoke',
    'memory.secret_rescan', 'memory.quarantine', 'memory.quarantine_release'
));

DO $block$
DECLARE
    target regclass;
BEGIN
    FOREACH target IN ARRAY ARRAY[
        'brain.secret_project_state'::regclass,
        'brain.memory_secret_scans'::regclass,
        'brain.memory_quarantines'::regclass
    ]
    LOOP
        EXECUTE format(
            'CREATE TRIGGER application_mutation_fence BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION jobs.guard_application_mutation()',
            target
        );
    END LOOP;
END
$block$;

REVOKE ALL ON brain.secret_project_state, brain.memory_secret_scans, brain.memory_quarantines FROM PUBLIC, punaro_app;
GRANT SELECT ON brain.secret_project_state, brain.memory_secret_scans, brain.memory_quarantines TO punaro_app;
GRANT INSERT (project_id) ON brain.secret_project_state TO punaro_app;
GRANT UPDATE (exception_generation, updated_at) ON brain.secret_project_state TO punaro_app;
GRANT INSERT (item_id, revision, rule_version, rule_digest, exception_generation, outcome, scanned_by)
    ON brain.memory_secret_scans TO punaro_app;
GRANT UPDATE (revision, rule_version, rule_digest, exception_generation, outcome, scanned_by, scanned_at)
    ON brain.memory_secret_scans TO punaro_app;
GRANT INSERT (item_id, detected_revision, rule_version, rule_id, field_path, value_fingerprint, quarantined_by)
    ON brain.memory_quarantines TO punaro_app;
GRANT UPDATE (released_by, released_at) ON brain.memory_quarantines TO punaro_app;
