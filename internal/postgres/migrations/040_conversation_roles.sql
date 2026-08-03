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

GRANT UPDATE (endpoint, capabilities, role) ON relay.mail_memberships TO punaro_app;
