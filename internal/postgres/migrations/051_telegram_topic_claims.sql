-- Telegram claim reservation, built-in participant, and inbound metadata.
-- Claim complete is not member set; these tables stay off conversation_controls.

CREATE TABLE relay.mail_telegram_claims (
    conversation_id uuid PRIMARY KEY REFERENCES relay.mail_conversations(id),
    status text NOT NULL CHECK (status IN ('pending', 'complete')),
    requested_by_machine text NOT NULL CHECK (
        char_length(requested_by_machine) >= 1 AND char_length(requested_by_machine) <= 128
        AND octet_length(requested_by_machine) <= 512 AND requested_by_machine !~ '[[:cntrl:]]'
    ),
    requested_by_endpoint text NOT NULL CHECK (
        char_length(requested_by_endpoint) >= 1 AND char_length(requested_by_endpoint) <= 512
        AND octet_length(requested_by_endpoint) <= 2048 AND requested_by_endpoint !~ '[[:cntrl:]]'
    ),
    idempotency_key text NOT NULL CHECK (
        char_length(idempotency_key) >= 1 AND char_length(idempotency_key) <= 128
        AND octet_length(idempotency_key) <= 512 AND idempotency_key !~ '[[:cntrl:]]'
    ),
    request_hash char(64) NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    CHECK ((status = 'complete') = (completed_at IS NOT NULL))
);

CREATE TABLE relay.mail_telegram_participants (
    conversation_id uuid PRIMARY KEY REFERENCES relay.mail_conversations(id),
    label text NOT NULL CHECK (label = 'user-telegram'),
    created_at timestamptz NOT NULL
);

CREATE TABLE relay.mail_telegram_claim_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id uuid NOT NULL REFERENCES relay.mail_conversations(id),
    event text NOT NULL CHECK (event = 'complete'),
    actor_machine text NOT NULL CHECK (
        char_length(actor_machine) >= 1 AND char_length(actor_machine) <= 128
        AND octet_length(actor_machine) <= 512 AND actor_machine !~ '[[:cntrl:]]'
    ),
    actor_endpoint text NOT NULL CHECK (
        char_length(actor_endpoint) >= 1 AND char_length(actor_endpoint) <= 512
        AND octet_length(actor_endpoint) <= 2048 AND actor_endpoint !~ '[[:cntrl:]]'
    ),
    created_at timestamptz NOT NULL
);

ALTER TABLE relay.mail_messages
    ADD COLUMN from_participant text,
    ADD COLUMN in_reply_to_message_id text,
    ADD COLUMN in_reply_to_endpoint text,
    ADD COLUMN telegram_thread_id bigint;

ALTER TABLE relay.mail_messages
    ADD CONSTRAINT mail_messages_from_participant_check CHECK (
        from_participant IS NULL OR from_participant = 'user-telegram'
    );
ALTER TABLE relay.mail_messages
    ADD CONSTRAINT mail_messages_in_reply_to_message_id_check CHECK (
        in_reply_to_message_id IS NULL
        OR (
            char_length(in_reply_to_message_id) >= 1 AND char_length(in_reply_to_message_id) <= 128
            AND octet_length(in_reply_to_message_id) <= 512 AND in_reply_to_message_id !~ '[[:cntrl:]]'
        )
    );
ALTER TABLE relay.mail_messages
    ADD CONSTRAINT mail_messages_in_reply_to_endpoint_check CHECK (
        in_reply_to_endpoint IS NULL
        OR (
            char_length(in_reply_to_endpoint) >= 1 AND char_length(in_reply_to_endpoint) <= 512
            AND octet_length(in_reply_to_endpoint) <= 2048 AND in_reply_to_endpoint !~ '[[:cntrl:]]'
        )
    );
ALTER TABLE relay.mail_messages
    ADD CONSTRAINT mail_messages_telegram_thread_id_check CHECK (
        telegram_thread_id IS NULL OR telegram_thread_id > 0
    );

CREATE TRIGGER mail_telegram_claims_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_telegram_claims
FOR EACH STATEMENT EXECUTE FUNCTION relay.guard_mail_mutation();
CREATE TRIGGER mail_telegram_participants_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_telegram_participants
FOR EACH STATEMENT EXECUTE FUNCTION relay.guard_mail_mutation();
CREATE TRIGGER mail_telegram_claim_events_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_telegram_claim_events
FOR EACH STATEMENT EXECUTE FUNCTION relay.guard_mail_mutation();

GRANT SELECT, INSERT ON relay.mail_telegram_claims TO punaro_app;
GRANT UPDATE (status, completed_at) ON relay.mail_telegram_claims TO punaro_app;
GRANT SELECT, INSERT ON relay.mail_telegram_participants TO punaro_app;
GRANT SELECT, INSERT ON relay.mail_telegram_claim_events TO punaro_app;
