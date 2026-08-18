CREATE TABLE relay.mail_direct_conversations (
    role_low text NOT NULL REFERENCES relay.mail_roles(role),
    role_high text NOT NULL REFERENCES relay.mail_roles(role),
    conversation_id uuid NOT NULL REFERENCES relay.mail_conversations(id),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (role_low, role_high),
    CONSTRAINT mail_direct_conversations_role_order_check CHECK (role_low < role_high),
    CONSTRAINT mail_direct_conversations_conversation_id_key UNIQUE (conversation_id)
);

CREATE TABLE relay.mail_message_from_roles (
    message_id uuid PRIMARY KEY REFERENCES relay.mail_messages(id),
    from_role text NOT NULL REFERENCES relay.mail_roles(role)
);

CREATE TABLE relay.mail_direct_message_idempotency (
    machine_id text NOT NULL,
    key text NOT NULL CHECK (char_length(key) >= 1 AND char_length(key) <= 128 AND octet_length(key) <= 512 AND key !~ '[[:cntrl:]]'),
    request_hash char(64) NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    from_role text NOT NULL,
    to_role text NOT NULL,
    conversation_id uuid NOT NULL REFERENCES relay.mail_conversations(id),
    message_id uuid NOT NULL REFERENCES relay.mail_messages(id),
    sequence bigint NOT NULL CHECK (sequence >= 1),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (machine_id, key)
);

CREATE TRIGGER mail_direct_conversations_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_direct_conversations
FOR EACH STATEMENT EXECUTE FUNCTION relay.guard_mail_mutation();
CREATE TRIGGER mail_message_from_roles_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_message_from_roles
FOR EACH STATEMENT EXECUTE FUNCTION relay.guard_mail_mutation();
CREATE TRIGGER mail_direct_message_idempotency_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_direct_message_idempotency
FOR EACH STATEMENT EXECUTE FUNCTION relay.guard_mail_mutation();

REVOKE ALL ON relay.mail_direct_conversations, relay.mail_message_from_roles, relay.mail_direct_message_idempotency FROM PUBLIC;
GRANT SELECT, INSERT ON relay.mail_direct_conversations, relay.mail_message_from_roles, relay.mail_direct_message_idempotency TO punaro_app;

ALTER TABLE relay.mail_cutover_staging DROP CONSTRAINT mail_cutover_staging_table_name_check;
ALTER TABLE relay.mail_cutover_staging ADD CONSTRAINT mail_cutover_staging_table_name_check CHECK (table_name IN ('mail_endpoints','mail_conversations','mail_memberships','mail_roles','mail_role_memberships','mail_role_bindings','mail_messages','mail_deliveries','mail_recipient_cursors','mail_message_idempotency','mail_conversation_idempotency','mail_conversation_controls','mail_conversation_control_idempotency','mail_request_nonces','mail_role_profiles','mail_role_profile_idempotency','mail_rate_buckets','mail_direct_conversations','mail_message_from_roles','mail_direct_message_idempotency'));
ALTER TABLE relay.mail_cutover_checkpoints DROP CONSTRAINT mail_cutover_checkpoints_table_name_check;
ALTER TABLE relay.mail_cutover_checkpoints ADD CONSTRAINT mail_cutover_checkpoints_table_name_check CHECK (table_name IN ('mail_endpoints','mail_conversations','mail_memberships','mail_roles','mail_role_memberships','mail_role_bindings','mail_messages','mail_deliveries','mail_recipient_cursors','mail_message_idempotency','mail_conversation_idempotency','mail_conversation_controls','mail_conversation_control_idempotency','mail_request_nonces','mail_role_profiles','mail_role_profile_idempotency','mail_rate_buckets','mail_direct_conversations','mail_message_from_roles','mail_direct_message_idempotency'));
