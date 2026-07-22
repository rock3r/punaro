CREATE TABLE brain.secret_guard_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    rule_version bigint NOT NULL CHECK (rule_version = 1),
    rule_digest bytea NOT NULL CHECK (octet_length(rule_digest) = 32),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp()
);

INSERT INTO brain.secret_guard_state (singleton, rule_version, rule_digest)
VALUES (true, 1, decode('39fb102e3a58faf1e5b7d0045caed1c2110da2f622102c088aeef16f775dfa22', 'hex'));

CREATE TABLE brain.secret_exceptions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id uuid NOT NULL REFERENCES relay.projects(id),
    rule_version bigint NOT NULL CHECK (rule_version = 1),
    rule_id text NOT NULL CHECK (rule_id IN ('private-key', 'bearer-token', 'credential-assignment', 'sensitive-field')),
    field_path text NOT NULL CHECK (octet_length(field_path) BETWEEN 1 AND 1024),
    value_fingerprint bytea NOT NULL CHECK (octet_length(value_fingerprint) = 32),
    approved_by uuid NOT NULL REFERENCES auth.principals(id),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    revoked_at timestamptz,
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE UNIQUE INDEX secret_exceptions_active_exact
ON brain.secret_exceptions (project_id, rule_version, rule_id, field_path, value_fingerprint)
WHERE revoked_at IS NULL;

ALTER TABLE audit.events DROP CONSTRAINT events_action_check;
ALTER TABLE audit.events ADD CONSTRAINT events_action_check CHECK (action IN (
    'principal.create', 'project.create', 'grant.create', 'grant.delete',
    'job.enqueue', 'job.complete', 'job.retry', 'job.fail',
    'owner.bootstrap', 'enrollment.create', 'enrollment.redeem',
    'credential.rotate', 'credential.revoke',
    'legacy.register', 'legacy.exchange', 'legacy.retire', 'legacy.disable',
    'project.identity.attach', 'project.merge.preview', 'project.merge',
    'memory.create', 'memory.update', 'memory.archive', 'memory.restore', 'memory.delete',
    'memory.secret_exception.create', 'memory.secret_exception.revoke'
));

CREATE TRIGGER application_mutation_fence
BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON brain.secret_guard_state
FOR EACH STATEMENT EXECUTE FUNCTION jobs.guard_application_mutation();

CREATE TRIGGER application_mutation_fence
BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON brain.secret_exceptions
FOR EACH STATEMENT EXECUTE FUNCTION jobs.guard_application_mutation();

REVOKE ALL ON brain.secret_guard_state, brain.secret_exceptions FROM PUBLIC, punaro_app;
GRANT SELECT ON brain.secret_guard_state, brain.secret_exceptions TO punaro_app;
GRANT INSERT (project_id, rule_version, rule_id, field_path, value_fingerprint, approved_by)
ON brain.secret_exceptions TO punaro_app;
GRANT UPDATE (revoked_at) ON brain.secret_exceptions TO punaro_app;
