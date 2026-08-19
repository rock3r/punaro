CREATE TABLE relay.mail_telegram_claim_idempotency (
    machine_id text NOT NULL,
    key text NOT NULL CHECK (char_length(key) >= 1 AND char_length(key) <= 128 AND octet_length(key) <= 512 AND key !~ '[[:cntrl:]]'),
    request_hash char(64) NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    conversation_id uuid NOT NULL REFERENCES relay.mail_conversations(id),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (machine_id, key)
);

INSERT INTO relay.mail_telegram_claim_idempotency(machine_id, key, request_hash, conversation_id, created_at)
SELECT requested_by_machine, idempotency_key, request_hash, conversation_id, created_at
FROM relay.mail_telegram_claims
ON CONFLICT (machine_id, key) DO NOTHING;

CREATE TRIGGER mail_telegram_claim_idempotency_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_telegram_claim_idempotency
FOR EACH STATEMENT EXECUTE FUNCTION relay.guard_mail_mutation();

REVOKE ALL ON relay.mail_telegram_claim_idempotency FROM PUBLIC;
GRANT SELECT, INSERT ON relay.mail_telegram_claim_idempotency TO punaro_app;
