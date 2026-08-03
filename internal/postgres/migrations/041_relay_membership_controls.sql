CREATE TABLE relay.mail_conversation_controls (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id uuid NOT NULL REFERENCES relay.mail_conversations(id),
    actor_endpoint text NOT NULL,
    operation text NOT NULL CHECK (operation IN ('upsert_member','remove_member')),
    member_endpoint text NOT NULL,
    member_capabilities smallint NOT NULL CHECK (member_capabilities BETWEEN 0 AND 7),
    created_at timestamptz NOT NULL
);

CREATE TABLE relay.mail_conversation_control_idempotency (
    machine_id text NOT NULL,
    key text NOT NULL CHECK (char_length(key) >= 1 AND char_length(key) <= 128 AND octet_length(key) <= 512 AND key !~ '[[:cntrl:]]'),
    request_hash char(64) NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    control_id uuid NOT NULL UNIQUE REFERENCES relay.mail_conversation_controls(id),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (machine_id, key)
);

CREATE TRIGGER mail_conversation_controls_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_conversation_controls
FOR EACH STATEMENT EXECUTE FUNCTION relay.guard_mail_mutation();
CREATE TRIGGER mail_conversation_control_idempotency_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_conversation_control_idempotency
FOR EACH STATEMENT EXECUTE FUNCTION relay.guard_mail_mutation();

REVOKE ALL ON relay.mail_conversation_controls, relay.mail_conversation_control_idempotency FROM PUBLIC;
GRANT SELECT, INSERT ON relay.mail_conversation_controls, relay.mail_conversation_control_idempotency TO punaro_app;
GRANT UPDATE (capabilities), DELETE ON relay.mail_memberships TO punaro_app;
