-- `to_role` is an immutable optional recipient selector. The application
-- validates it against the same conversation's receive-capable role membership
-- before allocating a sequence or inserting a delivery; this column preserves
-- the accepted routing intent for audit, retry, and recovery.
ALTER TABLE relay.mail_messages
    ADD COLUMN to_role text;

ALTER TABLE relay.mail_messages
    ADD CONSTRAINT mail_messages_to_role_check CHECK (
        to_role IS NULL OR (
            char_length(to_role) >= 1 AND char_length(to_role) <= 512
            AND octet_length(to_role) <= 2048 AND to_role !~ '[[:cntrl:]]'
        )
    );
