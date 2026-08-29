ALTER TABLE relay.mail_conversations
    ADD COLUMN display_name text;

ALTER TABLE relay.mail_conversations
    ADD CONSTRAINT mail_conversations_display_name_check CHECK (
        display_name IS NULL
        OR (
            char_length(display_name) >= 1
            AND char_length(display_name) <= 128
            AND octet_length(display_name) <= 512
            AND display_name !~ '[[:cntrl:]]'
        )
    );

GRANT UPDATE (display_name) ON relay.mail_conversations TO punaro_app;
