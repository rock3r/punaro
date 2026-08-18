CREATE TABLE relay.mail_pending_capacity (
    scope text NOT NULL,
    scope_key text NOT NULL,
    pending_count bigint NOT NULL,
    pending_bytes bigint NOT NULL,
    PRIMARY KEY (scope, scope_key),
    CONSTRAINT mail_pending_capacity_scope_check CHECK (scope IN ('installation', 'recipient')),
    CONSTRAINT mail_pending_capacity_pending_count_check CHECK (pending_count >= 0),
    CONSTRAINT mail_pending_capacity_pending_bytes_check CHECK (pending_bytes >= 0),
    CONSTRAINT mail_pending_capacity_shape_check CHECK (
        (scope = 'installation' AND scope_key = '')
        OR (
            scope = 'recipient'
            AND char_length(scope_key) >= 1
            AND (
                (
                    char_length(scope_key) <= 512
                    AND octet_length(scope_key) <= 2048
                    AND scope_key !~ '[[:cntrl:]]'
                )
                OR (
                    substr(scope_key, 1, 6) = chr(30) || 'role:'
                    AND char_length(substr(scope_key, 7)) >= 1
                    AND char_length(substr(scope_key, 7)) <= 512
                    AND octet_length(substr(scope_key, 7)) <= 2048
                    AND substr(scope_key, 7) !~ '[[:cntrl:]]'
                )
            )
        )
    )
);

INSERT INTO relay.mail_pending_capacity(scope, scope_key, pending_count, pending_bytes)
SELECT 'installation', '', COUNT(*), COALESCE(SUM(octet_length(message.body)), 0)
FROM relay.mail_deliveries AS delivery
JOIN relay.mail_messages AS message ON message.id = delivery.message_id
WHERE delivery.acked_at IS NULL
HAVING COUNT(*) > 0;

INSERT INTO relay.mail_pending_capacity(scope, scope_key, pending_count, pending_bytes)
SELECT 'recipient', delivery.recipient_endpoint, COUNT(*), COALESCE(SUM(octet_length(message.body)), 0)
FROM relay.mail_deliveries AS delivery
JOIN relay.mail_messages AS message ON message.id = delivery.message_id
WHERE delivery.acked_at IS NULL
GROUP BY delivery.recipient_endpoint;

CREATE TRIGGER mail_pending_capacity_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_pending_capacity
FOR EACH STATEMENT EXECUTE FUNCTION relay.guard_mail_mutation();

REVOKE ALL ON relay.mail_pending_capacity FROM PUBLIC;
GRANT SELECT, INSERT ON relay.mail_pending_capacity TO punaro_app;
GRANT UPDATE (pending_count, pending_bytes) ON relay.mail_pending_capacity TO punaro_app;

ALTER TABLE relay.mail_cutover_staging DROP CONSTRAINT mail_cutover_staging_table_name_check;
ALTER TABLE relay.mail_cutover_staging ADD CONSTRAINT mail_cutover_staging_table_name_check CHECK (table_name IN ('mail_endpoints','mail_conversations','mail_memberships','mail_roles','mail_role_memberships','mail_role_bindings','mail_messages','mail_deliveries','mail_recipient_cursors','mail_message_idempotency','mail_conversation_idempotency','mail_conversation_controls','mail_conversation_control_idempotency','mail_request_nonces','mail_role_profiles','mail_role_profile_idempotency','mail_rate_buckets','mail_direct_conversations','mail_message_from_roles','mail_direct_message_idempotency','mail_pending_capacity'));
ALTER TABLE relay.mail_cutover_checkpoints DROP CONSTRAINT mail_cutover_checkpoints_table_name_check;
ALTER TABLE relay.mail_cutover_checkpoints ADD CONSTRAINT mail_cutover_checkpoints_table_name_check CHECK (table_name IN ('mail_endpoints','mail_conversations','mail_memberships','mail_roles','mail_role_memberships','mail_role_bindings','mail_messages','mail_deliveries','mail_recipient_cursors','mail_message_idempotency','mail_conversation_idempotency','mail_conversation_controls','mail_conversation_control_idempotency','mail_request_nonces','mail_role_profiles','mail_role_profile_idempotency','mail_rate_buckets','mail_direct_conversations','mail_message_from_roles','mail_direct_message_idempotency','mail_pending_capacity'));
