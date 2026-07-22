CREATE TABLE brain.memory_evidence_expirations (
    item_id uuid PRIMARY KEY REFERENCES brain.memory_items(id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL,
    created_by uuid NOT NULL REFERENCES auth.principals(id),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT memory_evidence_expirations_future_check CHECK (expires_at > created_at)
);

CREATE INDEX memory_evidence_expirations_due
ON brain.memory_evidence_expirations (expires_at, item_id);

CREATE TRIGGER application_mutation_fence
BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON brain.memory_evidence_expirations
FOR EACH STATEMENT EXECUTE FUNCTION jobs.guard_application_mutation();

REVOKE ALL ON brain.memory_evidence_expirations FROM PUBLIC, punaro_app;
GRANT SELECT ON brain.memory_evidence_expirations TO punaro_app;
GRANT INSERT (item_id, expires_at, created_by) ON brain.memory_evidence_expirations TO punaro_app;
