CREATE TABLE relay.mail_rate_buckets (
    kind text NOT NULL CHECK (kind IN ('sender', 'conversation')),
    bucket_key text NOT NULL CHECK (
        char_length(bucket_key) >= 1 AND char_length(bucket_key) <= 512
        AND octet_length(bucket_key) <= 2048
        AND bucket_key !~ '[[:cntrl:]]'
    ),
    tokens bigint NOT NULL CHECK (tokens >= 0),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (kind, bucket_key)
);

CREATE TRIGGER mail_rate_buckets_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_rate_buckets
FOR EACH STATEMENT EXECUTE FUNCTION relay.guard_mail_mutation();

REVOKE ALL ON relay.mail_rate_buckets FROM PUBLIC;
GRANT SELECT, INSERT ON relay.mail_rate_buckets TO punaro_app;
GRANT UPDATE (tokens, updated_at) ON relay.mail_rate_buckets TO punaro_app;

ALTER TABLE relay.mail_cutover_staging DROP CONSTRAINT mail_cutover_staging_table_name_check;
ALTER TABLE relay.mail_cutover_staging ADD CONSTRAINT mail_cutover_staging_table_name_check CHECK (table_name IN ('mail_endpoints','mail_conversations','mail_memberships','mail_roles','mail_role_memberships','mail_role_bindings','mail_messages','mail_deliveries','mail_recipient_cursors','mail_message_idempotency','mail_conversation_idempotency','mail_conversation_controls','mail_conversation_control_idempotency','mail_request_nonces','mail_role_profiles','mail_role_profile_idempotency','mail_rate_buckets'));
ALTER TABLE relay.mail_cutover_checkpoints DROP CONSTRAINT mail_cutover_checkpoints_table_name_check;
ALTER TABLE relay.mail_cutover_checkpoints ADD CONSTRAINT mail_cutover_checkpoints_table_name_check CHECK (table_name IN ('mail_endpoints','mail_conversations','mail_memberships','mail_roles','mail_role_memberships','mail_role_bindings','mail_messages','mail_deliveries','mail_recipient_cursors','mail_message_idempotency','mail_conversation_idempotency','mail_conversation_controls','mail_conversation_control_idempotency','mail_request_nonces','mail_role_profiles','mail_role_profile_idempotency','mail_rate_buckets'));
