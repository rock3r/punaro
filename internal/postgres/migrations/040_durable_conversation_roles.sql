-- Durable conversation roles deliberately live outside the endpoint namespace.
-- A binding proves that an owner machine currently controls one particular
-- endpoint generation; delivery/cursor recipient identities use role:<name>.
CREATE TABLE relay.mail_roles (
    role text PRIMARY KEY CHECK (
        char_length(role) >= 1 AND char_length(role) <= 512
        AND octet_length(role) <= 2048 AND role !~ '[[:cntrl:]]'
    ),
    machine_id text NOT NULL CHECK (
        char_length(machine_id) >= 1 AND char_length(machine_id) <= 128
        AND octet_length(machine_id) <= 512 AND machine_id !~ '[[:cntrl:]]'
    )
);

CREATE TABLE relay.mail_role_memberships (
    conversation_id uuid NOT NULL REFERENCES relay.mail_conversations(id),
    role text NOT NULL REFERENCES relay.mail_roles(role),
    capabilities smallint NOT NULL CHECK (capabilities BETWEEN 1 AND 7),
    PRIMARY KEY (conversation_id, role)
);

CREATE TABLE relay.mail_role_bindings (
    role text PRIMARY KEY REFERENCES relay.mail_roles(role),
    session_endpoint text NOT NULL REFERENCES relay.mail_endpoints(endpoint),
    machine_id text NOT NULL,
    ownership_generation bigint NOT NULL CHECK (ownership_generation > 0),
    lease_until timestamptz NOT NULL
);

CREATE INDEX mail_role_bindings_session
ON relay.mail_role_bindings (machine_id, session_endpoint, lease_until, role);

-- These recipient columns are polymorphic: a legacy endpoint or a durable
-- role:<name> identity. The relay is their only writer and validates each
-- identity transactionally before insertion.
ALTER TABLE relay.mail_deliveries
    DROP CONSTRAINT mail_deliveries_recipient_endpoint_fkey;
ALTER TABLE relay.mail_recipient_cursors
    DROP CONSTRAINT mail_recipient_cursors_recipient_endpoint_fkey;

CREATE TRIGGER mail_roles_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_roles
FOR EACH STATEMENT EXECUTE FUNCTION relay.guard_mail_mutation();
CREATE TRIGGER mail_role_memberships_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_role_memberships
FOR EACH STATEMENT EXECUTE FUNCTION relay.guard_mail_mutation();
CREATE TRIGGER mail_role_bindings_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_role_bindings
FOR EACH STATEMENT EXECUTE FUNCTION relay.guard_mail_mutation();

GRANT SELECT, INSERT ON relay.mail_roles TO punaro_app;
GRANT SELECT, INSERT ON relay.mail_role_memberships TO punaro_app;
GRANT SELECT, INSERT, UPDATE (session_endpoint, machine_id, ownership_generation, lease_until) ON relay.mail_role_bindings TO punaro_app;

ALTER TABLE relay.mail_cutover_staging DROP CONSTRAINT mail_cutover_staging_table_name_check;
ALTER TABLE relay.mail_cutover_staging ADD CONSTRAINT mail_cutover_staging_table_name_check CHECK (table_name IN ('mail_endpoints','mail_conversations','mail_memberships','mail_roles','mail_role_memberships','mail_role_bindings','mail_messages','mail_deliveries','mail_recipient_cursors','mail_message_idempotency','mail_conversation_idempotency','mail_request_nonces'));
ALTER TABLE relay.mail_cutover_checkpoints DROP CONSTRAINT mail_cutover_checkpoints_table_name_check;
ALTER TABLE relay.mail_cutover_checkpoints ADD CONSTRAINT mail_cutover_checkpoints_table_name_check CHECK (table_name IN ('mail_endpoints','mail_conversations','mail_memberships','mail_roles','mail_role_memberships','mail_role_bindings','mail_messages','mail_deliveries','mail_recipient_cursors','mail_message_idempotency','mail_conversation_idempotency','mail_request_nonces'));
