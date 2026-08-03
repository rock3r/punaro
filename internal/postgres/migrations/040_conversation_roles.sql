ALTER TABLE relay.mail_memberships
    ADD COLUMN role text NOT NULL DEFAULT '' CHECK (
        (role = '') OR (
            char_length(role) >= 1 AND char_length(role) <= 64
            AND octet_length(role) <= 256 AND btrim(role) = role
            AND role !~ '[[:cntrl:]]'
        )
    );

ALTER TABLE relay.mail_messages
    ADD COLUMN target_role text NOT NULL DEFAULT '' CHECK (
        (target_role = '') OR (
            char_length(target_role) >= 1 AND char_length(target_role) <= 64
            AND octet_length(target_role) <= 256 AND btrim(target_role) = target_role
            AND target_role !~ '[[:cntrl:]]'
        )
    );

CREATE INDEX mail_memberships_role_active
ON relay.mail_memberships (conversation_id, role, endpoint)
WHERE (capabilities & 2) <> 0;

-- Rebinding an unacknowledged delivery must retain the endpoint evidence for
-- attachments already bound to that delivery. The application checks this
-- function before a rebind; an attachment recipient can move only within the
-- same stable principal.
ALTER TABLE attachment.recipient_grant_endpoints
    DROP CONSTRAINT recipient_grant_endpoints_delivery_fkey,
    ADD CONSTRAINT recipient_grant_endpoints_delivery_fkey
        FOREIGN KEY (message_id, recipient_endpoint)
        REFERENCES relay.mail_deliveries(message_id, recipient_endpoint)
        ON UPDATE CASCADE;

CREATE FUNCTION attachment.recipient_rebind_allowed(
    previous_endpoint text,
    replacement_endpoint text,
    requested_conversation uuid
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT COALESCE(bool_and(
        previous_binding.principal_id IS NOT NULL
        AND replacement_binding.principal_id IS NOT NULL
        AND previous_binding.principal_id = replacement_binding.principal_id
    ), true)
    FROM relay.mail_deliveries AS delivery
    JOIN relay.mail_messages AS message ON message.id = delivery.message_id
    JOIN attachment.message_artifacts AS artifact ON artifact.message_id = message.id
    LEFT JOIN attachment.endpoint_principals AS previous_binding ON previous_binding.endpoint = previous_endpoint
    LEFT JOIN attachment.endpoint_principals AS replacement_binding ON replacement_binding.endpoint = replacement_endpoint
    WHERE delivery.recipient_endpoint = previous_endpoint
      AND delivery.acked_at IS NULL
      AND message.conversation_id = requested_conversation
$function$;

GRANT UPDATE (endpoint, capabilities, role) ON relay.mail_memberships TO punaro_app;
GRANT UPDATE (recipient_endpoint) ON relay.mail_deliveries TO punaro_app;
GRANT DELETE ON relay.mail_recipient_cursors TO punaro_app;
REVOKE ALL ON FUNCTION attachment.recipient_rebind_allowed(text,text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION attachment.recipient_rebind_allowed(text,text,uuid) TO punaro_app;
