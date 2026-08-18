CREATE TABLE relay.mail_role_profiles (
    role text PRIMARY KEY REFERENCES relay.mail_roles(role),
    display_name text CHECK (
        display_name IS NULL OR (
            char_length(display_name) >= 1 AND char_length(display_name) <= 128
            AND octet_length(display_name) <= 128
            AND display_name !~ '[[:cntrl:]]'
            AND display_name = btrim(display_name)
        )
    ),
    direct_addressable boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL
);

CREATE TABLE relay.mail_role_profile_idempotency (
    machine_id text NOT NULL,
    key text NOT NULL CHECK (char_length(key) >= 1 AND char_length(key) <= 128 AND octet_length(key) <= 512 AND key !~ '[[:cntrl:]]'),
    request_hash char(64) NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    role text NOT NULL REFERENCES relay.mail_role_profiles(role),
    display_name text CHECK (
        display_name IS NULL OR (
            char_length(display_name) >= 1 AND char_length(display_name) <= 128
            AND octet_length(display_name) <= 128
            AND display_name !~ '[[:cntrl:]]'
            AND display_name = btrim(display_name)
        )
    ),
    direct_addressable boolean NOT NULL,
    updated_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (machine_id, key)
);

CREATE TRIGGER mail_role_profiles_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_role_profiles
FOR EACH STATEMENT EXECUTE FUNCTION relay.guard_mail_mutation();
CREATE TRIGGER mail_role_profile_idempotency_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_role_profile_idempotency
FOR EACH STATEMENT EXECUTE FUNCTION relay.guard_mail_mutation();

REVOKE ALL ON relay.mail_role_profiles, relay.mail_role_profile_idempotency FROM PUBLIC;
GRANT SELECT, INSERT ON relay.mail_role_profiles TO punaro_app;
GRANT UPDATE (display_name, direct_addressable, updated_at) ON relay.mail_role_profiles TO punaro_app;
GRANT SELECT, INSERT ON relay.mail_role_profile_idempotency TO punaro_app;

ALTER TABLE relay.mail_cutover_staging DROP CONSTRAINT mail_cutover_staging_table_name_check;
ALTER TABLE relay.mail_cutover_staging ADD CONSTRAINT mail_cutover_staging_table_name_check CHECK (table_name IN ('mail_endpoints','mail_conversations','mail_memberships','mail_roles','mail_role_memberships','mail_role_bindings','mail_messages','mail_deliveries','mail_recipient_cursors','mail_message_idempotency','mail_conversation_idempotency','mail_conversation_controls','mail_conversation_control_idempotency','mail_request_nonces','mail_role_profiles','mail_role_profile_idempotency'));
ALTER TABLE relay.mail_cutover_checkpoints DROP CONSTRAINT mail_cutover_checkpoints_table_name_check;
ALTER TABLE relay.mail_cutover_checkpoints ADD CONSTRAINT mail_cutover_checkpoints_table_name_check CHECK (table_name IN ('mail_endpoints','mail_conversations','mail_memberships','mail_roles','mail_role_memberships','mail_role_bindings','mail_messages','mail_deliveries','mail_recipient_cursors','mail_message_idempotency','mail_conversation_idempotency','mail_conversation_controls','mail_conversation_control_idempotency','mail_request_nonces','mail_role_profiles','mail_role_profile_idempotency'));
