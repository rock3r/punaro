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
-- attachments already bound to that delivery. The recipient principal remains
-- unchanged, so this carries no attachment authorization to a new principal.
ALTER TABLE attachment.recipient_grant_endpoints
    DROP CONSTRAINT recipient_grant_endpoints_delivery_fkey,
    ADD CONSTRAINT recipient_grant_endpoints_delivery_fkey
        FOREIGN KEY (message_id, recipient_endpoint)
        REFERENCES relay.mail_deliveries(message_id, recipient_endpoint)
        ON UPDATE CASCADE;

GRANT UPDATE (endpoint, capabilities, role) ON relay.mail_memberships TO punaro_app;
GRANT UPDATE (recipient_endpoint) ON relay.mail_deliveries TO punaro_app;
GRANT DELETE ON relay.mail_recipient_cursors TO punaro_app;
