ALTER TABLE relay.mail_cutover_staging
    DROP CONSTRAINT mail_cutover_staging_payload_check;

ALTER TABLE relay.mail_cutover_staging
    ADD CONSTRAINT mail_cutover_staging_payload_check
    CHECK (jsonb_typeof(payload) = 'object' AND octet_length(payload::text) <= 262144);
