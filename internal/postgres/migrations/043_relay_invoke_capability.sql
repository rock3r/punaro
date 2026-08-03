ALTER TABLE relay.mail_memberships
    DROP CONSTRAINT mail_memberships_capabilities_check,
    ADD CONSTRAINT mail_memberships_capabilities_check CHECK (capabilities BETWEEN 1 AND 15);

ALTER TABLE relay.mail_conversation_controls
    DROP CONSTRAINT mail_conversation_controls_member_capabilities_check,
    ADD CONSTRAINT mail_conversation_controls_member_capabilities_check CHECK (member_capabilities BETWEEN 0 AND 15);
