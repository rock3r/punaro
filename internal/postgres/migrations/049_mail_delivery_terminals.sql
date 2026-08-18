CREATE TABLE relay.mail_delivery_terminals (
    delivery_id uuid PRIMARY KEY REFERENCES relay.mail_deliveries(id) ON DELETE CASCADE,
    message_id uuid NOT NULL REFERENCES relay.mail_messages(id) ON DELETE CASCADE,
    conversation_id uuid NOT NULL REFERENCES relay.mail_conversations(id) ON DELETE CASCADE,
    recipient_id text NOT NULL CHECK (
        char_length(recipient_id) >= 1 AND char_length(recipient_id) <= 512
        AND octet_length(recipient_id) <= 2048
    ),
    sequence bigint NOT NULL CHECK (sequence >= 0),
    closed_reason text NOT NULL CHECK (closed_reason IN ('acked', 'expired', 'revoked')),
    lease_generation bigint NOT NULL CHECK (lease_generation >= 0),
    closed_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE INDEX mail_delivery_terminals_closed_at ON relay.mail_delivery_terminals (closed_at, delivery_id);

CREATE TRIGGER mail_delivery_terminals_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_delivery_terminals
FOR EACH STATEMENT EXECUTE FUNCTION relay.guard_mail_mutation();

REVOKE ALL ON relay.mail_delivery_terminals FROM PUBLIC;
GRANT SELECT, INSERT, DELETE ON relay.mail_delivery_terminals TO punaro_app;
