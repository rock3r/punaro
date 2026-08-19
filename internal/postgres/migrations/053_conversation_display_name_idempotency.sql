CREATE TABLE relay.mail_conversation_display_name_idempotency (
    machine_id text NOT NULL,
    key text NOT NULL CHECK (char_length(key) >= 1 AND char_length(key) <= 128 AND octet_length(key) <= 512 AND key !~ '[[:cntrl:]]'),
    request_hash char(64) NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    conversation_id uuid NOT NULL REFERENCES relay.mail_conversations(id),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (machine_id, key)
);

CREATE TRIGGER mail_conversation_display_name_idempotency_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_conversation_display_name_idempotency
FOR EACH STATEMENT EXECUTE FUNCTION relay.guard_mail_mutation();

REVOKE ALL ON relay.mail_conversation_display_name_idempotency FROM PUBLIC;
GRANT SELECT, INSERT ON relay.mail_conversation_display_name_idempotency TO punaro_app;
