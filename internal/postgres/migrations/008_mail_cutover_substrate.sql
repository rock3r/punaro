CREATE TABLE relay.mail_cutover_epochs (
    epoch_id uuid CONSTRAINT mail_cutover_epochs_pkey PRIMARY KEY,
    source_id uuid NOT NULL,
    target_identity char(64) NOT NULL CONSTRAINT mail_cutover_epochs_target_identity_check CHECK (target_identity ~ '^[0-9a-f]{64}$'),
    source_fingerprint char(64) NOT NULL CONSTRAINT mail_cutover_epochs_source_fingerprint_check CHECK (source_fingerprint ~ '^[0-9a-f]{64}$'),
    source_manifest text NOT NULL CONSTRAINT mail_cutover_epochs_source_manifest_check CHECK (jsonb_typeof(source_manifest::jsonb) = 'object' AND octet_length(source_manifest) <= 8192),
    manifest_sha256 char(64) NOT NULL CONSTRAINT mail_cutover_epochs_manifest_sha256_check CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$'),
    phase text NOT NULL CONSTRAINT mail_cutover_epochs_phase_check CHECK (phase IN ('importing','verified','active','aborted')),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    verified_at timestamptz,
    activated_at timestamptz,
    aborted_at timestamptz,
    CONSTRAINT mail_cutover_epochs_verified_at_check CHECK ((phase IN ('verified','active')) = (verified_at IS NOT NULL)),
    CONSTRAINT mail_cutover_epochs_activated_at_check CHECK ((phase = 'active') = (activated_at IS NOT NULL)),
    CONSTRAINT mail_cutover_epochs_aborted_at_check CHECK ((phase = 'aborted') = (aborted_at IS NOT NULL))
);

CREATE UNIQUE INDEX mail_cutover_epochs_one_authority
ON relay.mail_cutover_epochs ((true))
WHERE phase IN ('importing','verified','active');

CREATE TABLE relay.mail_cutover_staging (
    epoch_id uuid NOT NULL CONSTRAINT mail_cutover_staging_epoch_fkey REFERENCES relay.mail_cutover_epochs(epoch_id),
    table_name text NOT NULL CONSTRAINT mail_cutover_staging_table_name_check CHECK (table_name IN ('mail_endpoints','mail_conversations','mail_memberships','mail_messages','mail_deliveries','mail_recipient_cursors','mail_message_idempotency','mail_conversation_idempotency','mail_request_nonces')),
    row_key text NOT NULL CONSTRAINT mail_cutover_staging_row_key_check CHECK (octet_length(row_key) BETWEEN 1 AND 4096),
    payload jsonb NOT NULL CONSTRAINT mail_cutover_staging_payload_check CHECK (jsonb_typeof(payload) = 'object' AND octet_length(payload::text) <= 65536),
    row_sha256 char(64) NOT NULL CONSTRAINT mail_cutover_staging_row_sha256_check CHECK (row_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT mail_cutover_staging_pkey PRIMARY KEY (epoch_id, table_name, row_key)
);

CREATE TABLE relay.mail_cutover_checkpoints (
    epoch_id uuid NOT NULL CONSTRAINT mail_cutover_checkpoints_epoch_fkey REFERENCES relay.mail_cutover_epochs(epoch_id),
    table_name text NOT NULL CONSTRAINT mail_cutover_checkpoints_table_name_check CHECK (table_name IN ('mail_endpoints','mail_conversations','mail_memberships','mail_messages','mail_deliveries','mail_recipient_cursors','mail_message_idempotency','mail_conversation_idempotency','mail_request_nonces')),
    last_key text CONSTRAINT mail_cutover_checkpoints_last_key_check CHECK (last_key IS NULL OR octet_length(last_key) BETWEEN 1 AND 4096),
    row_count bigint NOT NULL DEFAULT 0 CONSTRAINT mail_cutover_checkpoints_row_count_check CHECK (row_count >= 0),
    rolling_sha256 char(64) NOT NULL CONSTRAINT mail_cutover_checkpoints_rolling_sha256_check CHECK (rolling_sha256 ~ '^[0-9a-f]{64}$'),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT mail_cutover_checkpoints_pkey PRIMARY KEY (epoch_id, table_name)
);

CREATE FUNCTION relay.guard_mail_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    PERFORM jobs.assert_application_mutation();
    PERFORM pg_advisory_xact_lock_shared(5788618938430605644);
    IF session_user = 'punaro_app' AND EXISTS (
        SELECT 1 FROM relay.mail_cutover_epochs WHERE phase IN ('importing','verified')
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55P03', MESSAGE = 'punaro maintenance in progress';
    END IF;
    RETURN NULL;
END
$function$;

DO $do$
DECLARE
    target regclass;
    trigger_name text;
BEGIN
    FOR target, trigger_name IN VALUES
        ('relay.mail_endpoints'::regclass, 'mail_endpoints_mutation_guard'),
        ('relay.mail_conversations'::regclass, 'mail_conversations_mutation_guard'),
        ('relay.mail_memberships'::regclass, 'mail_memberships_mutation_guard'),
        ('relay.mail_messages'::regclass, 'mail_messages_mutation_guard'),
        ('relay.mail_deliveries'::regclass, 'mail_deliveries_mutation_guard'),
        ('relay.mail_recipient_cursors'::regclass, 'mail_recipient_cursors_mutation_guard'),
        ('relay.mail_message_idempotency'::regclass, 'mail_message_idempotency_mutation_guard'),
        ('relay.mail_conversation_idempotency'::regclass, 'mail_conversation_idempotency_mutation_guard'),
        ('relay.mail_request_nonces'::regclass, 'mail_request_nonces_mutation_guard')
    LOOP
        EXECUTE format('DROP TRIGGER %I ON %s', trigger_name, target);
        EXECUTE format('CREATE TRIGGER %I BEFORE INSERT OR UPDATE OR DELETE ON %s FOR EACH STATEMENT EXECUTE FUNCTION relay.guard_mail_mutation()', trigger_name, target);
    END LOOP;
END
$do$;

REVOKE ALL ON relay.mail_cutover_epochs, relay.mail_cutover_staging, relay.mail_cutover_checkpoints FROM PUBLIC, punaro_app;
GRANT SELECT ON relay.mail_cutover_epochs TO punaro_app;
REVOKE ALL ON FUNCTION relay.guard_mail_mutation() FROM PUBLIC, punaro_app;
