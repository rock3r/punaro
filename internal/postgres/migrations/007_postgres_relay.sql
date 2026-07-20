CREATE TABLE relay.mail_endpoints (
    endpoint text PRIMARY KEY CHECK (
        char_length(endpoint) >= 1 AND char_length(endpoint) <= 512
        AND octet_length(endpoint) <= 2048
        AND endpoint !~ '[[:cntrl:]]'
    ),
    machine_id text NOT NULL CHECK (
        char_length(machine_id) >= 1 AND char_length(machine_id) <= 128
        AND octet_length(machine_id) <= 512
        AND machine_id !~ '[[:cntrl:]]'
    ),
    lease_until timestamptz NOT NULL,
    ownership_generation bigint NOT NULL DEFAULT 1 CHECK (ownership_generation > 0),
    consumer_id text CHECK (consumer_id IS NULL OR (char_length(consumer_id) >= 1 AND char_length(consumer_id) <= 128 AND octet_length(consumer_id) <= 512 AND consumer_id !~ '[[:cntrl:]]')),
    consumer_generation bigint NOT NULL DEFAULT 0 CHECK (consumer_generation >= 0),
    consumer_lease_until timestamptz,
    CHECK ((consumer_id IS NULL) = (consumer_lease_until IS NULL))
);

CREATE INDEX mail_endpoints_machine
ON relay.mail_endpoints (machine_id, lease_until, endpoint);

CREATE TABLE relay.mail_conversations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    next_sequence bigint NOT NULL DEFAULT 0 CHECK (next_sequence >= 0),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp()
);

CREATE TABLE relay.mail_memberships (
    conversation_id uuid NOT NULL REFERENCES relay.mail_conversations(id),
    endpoint text NOT NULL REFERENCES relay.mail_endpoints(endpoint),
    capabilities smallint NOT NULL CHECK (capabilities BETWEEN 1 AND 7),
    PRIMARY KEY (conversation_id, endpoint)
);

CREATE TABLE relay.mail_messages (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id uuid NOT NULL REFERENCES relay.mail_conversations(id),
    sequence bigint NOT NULL CHECK (sequence > 0),
    from_endpoint text NOT NULL REFERENCES relay.mail_endpoints(endpoint),
    body text NOT NULL CHECK (octet_length(body) <= 32768),
    created_at timestamptz NOT NULL,
    UNIQUE (conversation_id, sequence)
);

CREATE TABLE relay.mail_deliveries (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id uuid NOT NULL REFERENCES relay.mail_messages(id),
    recipient_endpoint text NOT NULL REFERENCES relay.mail_endpoints(endpoint),
    lease_machine_id text,
    lease_token uuid,
    lease_generation bigint NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
    ownership_generation bigint,
    consumer_generation bigint,
    lease_until timestamptz,
    acked_at timestamptz,
    UNIQUE (message_id, recipient_endpoint),
    CHECK (
        (lease_machine_id IS NULL AND lease_token IS NULL AND ownership_generation IS NULL AND consumer_generation IS NULL AND lease_until IS NULL)
        OR
        (lease_machine_id IS NOT NULL AND lease_token IS NOT NULL AND ownership_generation IS NOT NULL AND consumer_generation IS NOT NULL AND lease_until IS NOT NULL)
    )
);

CREATE INDEX mail_deliveries_pending
ON relay.mail_deliveries (recipient_endpoint, acked_at, lease_until, id);

CREATE TABLE relay.mail_recipient_cursors (
    recipient_endpoint text NOT NULL REFERENCES relay.mail_endpoints(endpoint),
    conversation_id uuid NOT NULL REFERENCES relay.mail_conversations(id),
    sequence bigint NOT NULL DEFAULT 0 CHECK (sequence >= 0),
    PRIMARY KEY (recipient_endpoint, conversation_id)
);

CREATE TABLE relay.mail_message_idempotency (
    machine_id text NOT NULL,
    key text NOT NULL CHECK (char_length(key) >= 1 AND char_length(key) <= 128 AND octet_length(key) <= 512 AND key !~ '[[:cntrl:]]'),
    request_hash char(64) NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    message_id uuid NOT NULL UNIQUE REFERENCES relay.mail_messages(id),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (machine_id, key)
);

CREATE TABLE relay.mail_conversation_idempotency (
    machine_id text NOT NULL,
    key text NOT NULL CHECK (char_length(key) >= 1 AND char_length(key) <= 128 AND octet_length(key) <= 512 AND key !~ '[[:cntrl:]]'),
    request_hash char(64) NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    conversation_id uuid NOT NULL UNIQUE REFERENCES relay.mail_conversations(id),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (machine_id, key)
);

CREATE TABLE relay.mail_request_nonces (
    machine_id text NOT NULL,
    nonce text NOT NULL CHECK (char_length(nonce) >= 1 AND char_length(nonce) <= 128 AND octet_length(nonce) <= 512 AND nonce !~ '[[:cntrl:]]'),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (machine_id, nonce)
);

CREATE INDEX mail_request_nonces_expiry
ON relay.mail_request_nonces (expires_at, machine_id, nonce);

CREATE FUNCTION relay.consume_mail_request_nonce(
    requested_machine_id text,
    requested_nonce text,
    requested_now timestamptz,
    requested_expires_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF requested_machine_id IS NULL OR char_length(requested_machine_id) < 1 OR char_length(requested_machine_id) > 128
       OR octet_length(requested_machine_id) > 512 OR requested_machine_id ~ '[[:cntrl:]]'
       OR requested_nonce IS NULL OR char_length(requested_nonce) < 1 OR char_length(requested_nonce) > 128
       OR octet_length(requested_nonce) > 512 OR requested_nonce ~ '[[:cntrl:]]'
       OR requested_now IS NULL OR requested_expires_at IS NULL
       OR requested_expires_at <= requested_now THEN
        RETURN false;
    END IF;
    DELETE FROM relay.mail_request_nonces
    WHERE (machine_id, nonce) IN (
        SELECT machine_id, nonce FROM relay.mail_request_nonces
        WHERE expires_at <= requested_now
        ORDER BY expires_at, machine_id, nonce
        LIMIT 256
        FOR UPDATE SKIP LOCKED
    );
    INSERT INTO relay.mail_request_nonces(machine_id, nonce, expires_at)
    VALUES (requested_machine_id, requested_nonce, requested_expires_at)
    ON CONFLICT DO NOTHING;
    RETURN FOUND;
END
$function$;

CREATE TRIGGER mail_endpoints_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_endpoints
FOR EACH STATEMENT EXECUTE FUNCTION jobs.guard_application_mutation();
CREATE TRIGGER mail_conversations_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_conversations
FOR EACH STATEMENT EXECUTE FUNCTION jobs.guard_application_mutation();
CREATE TRIGGER mail_memberships_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_memberships
FOR EACH STATEMENT EXECUTE FUNCTION jobs.guard_application_mutation();
CREATE TRIGGER mail_messages_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_messages
FOR EACH STATEMENT EXECUTE FUNCTION jobs.guard_application_mutation();
CREATE TRIGGER mail_deliveries_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_deliveries
FOR EACH STATEMENT EXECUTE FUNCTION jobs.guard_application_mutation();
CREATE TRIGGER mail_recipient_cursors_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_recipient_cursors
FOR EACH STATEMENT EXECUTE FUNCTION jobs.guard_application_mutation();
CREATE TRIGGER mail_message_idempotency_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_message_idempotency
FOR EACH STATEMENT EXECUTE FUNCTION jobs.guard_application_mutation();
CREATE TRIGGER mail_conversation_idempotency_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_conversation_idempotency
FOR EACH STATEMENT EXECUTE FUNCTION jobs.guard_application_mutation();
CREATE TRIGGER mail_request_nonces_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_request_nonces
FOR EACH STATEMENT EXECUTE FUNCTION jobs.guard_application_mutation();

REVOKE ALL ON FUNCTION relay.consume_mail_request_nonce(text, text, timestamptz, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION relay.consume_mail_request_nonce(text, text, timestamptz, timestamptz) TO punaro_app;

GRANT SELECT, INSERT ON relay.mail_endpoints TO punaro_app;
GRANT UPDATE (machine_id, lease_until, ownership_generation, consumer_id, consumer_generation, consumer_lease_until) ON relay.mail_endpoints TO punaro_app;
GRANT SELECT, INSERT ON relay.mail_conversations TO punaro_app;
GRANT UPDATE (next_sequence) ON relay.mail_conversations TO punaro_app;
GRANT SELECT, INSERT ON relay.mail_memberships TO punaro_app;
GRANT SELECT, INSERT ON relay.mail_messages TO punaro_app;
GRANT SELECT, INSERT ON relay.mail_deliveries TO punaro_app;
GRANT UPDATE (lease_machine_id, lease_token, lease_generation, ownership_generation, consumer_generation, lease_until, acked_at) ON relay.mail_deliveries TO punaro_app;
GRANT SELECT, INSERT ON relay.mail_recipient_cursors TO punaro_app;
GRANT UPDATE (sequence) ON relay.mail_recipient_cursors TO punaro_app;
GRANT SELECT, INSERT ON relay.mail_message_idempotency TO punaro_app;
GRANT SELECT, INSERT ON relay.mail_conversation_idempotency TO punaro_app;
