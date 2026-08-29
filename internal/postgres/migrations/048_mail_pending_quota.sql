CREATE TABLE relay.mail_pending_recipients (
    recipient_endpoint text PRIMARY KEY CHECK (
        char_length(recipient_endpoint) >= 1 AND char_length(recipient_endpoint) <= 512
        AND octet_length(recipient_endpoint) <= 2048
    ),
    pending_count bigint NOT NULL CHECK (pending_count >= 0),
    pending_bytes bigint NOT NULL CHECK (pending_bytes >= 0)
);

CREATE TABLE relay.mail_pending_install (
    singleton integer PRIMARY KEY CHECK (singleton = 1),
    pending_count bigint NOT NULL CHECK (pending_count >= 0),
    pending_bytes bigint NOT NULL CHECK (pending_bytes >= 0)
);

INSERT INTO relay.mail_pending_recipients(recipient_endpoint, pending_count, pending_bytes)
SELECT delivery.recipient_endpoint, count(*), COALESCE(sum(octet_length(message.body)), 0)
FROM relay.mail_deliveries AS delivery
JOIN relay.mail_messages AS message ON message.id = delivery.message_id
WHERE delivery.acked_at IS NULL
GROUP BY delivery.recipient_endpoint
ON CONFLICT (recipient_endpoint) DO NOTHING;

INSERT INTO relay.mail_pending_install(singleton, pending_count, pending_bytes)
SELECT 1, counted, bytes FROM (
    SELECT count(*) AS counted, COALESCE(sum(octet_length(message.body)), 0) AS bytes
    FROM relay.mail_deliveries AS delivery
    JOIN relay.mail_messages AS message ON message.id = delivery.message_id
    WHERE delivery.acked_at IS NULL
) AS pending
WHERE counted > 0
ON CONFLICT (singleton) DO NOTHING;

CREATE TRIGGER mail_pending_recipients_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_pending_recipients
FOR EACH STATEMENT EXECUTE FUNCTION relay.guard_mail_mutation();

CREATE TRIGGER mail_pending_install_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_pending_install
FOR EACH STATEMENT EXECUTE FUNCTION relay.guard_mail_mutation();

REVOKE ALL ON relay.mail_pending_recipients FROM PUBLIC;
REVOKE ALL ON relay.mail_pending_install FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON relay.mail_pending_recipients TO punaro_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON relay.mail_pending_install TO punaro_app;
