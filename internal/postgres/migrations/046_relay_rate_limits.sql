-- Durable sender-machine and conversation token buckets. Restart must not
-- restore capacity; exact committed retries never charge these rows.
CREATE TABLE relay.mail_rate_buckets (
    scope text NOT NULL CHECK (scope IN ('sender_machine', 'conversation')),
    bucket_key text NOT NULL CHECK (
        char_length(bucket_key) >= 1 AND char_length(bucket_key) <= 512
        AND octet_length(bucket_key) <= 2048
        AND bucket_key !~ '[[:cntrl:]]'
    ),
    tokens_milli bigint NOT NULL CHECK (tokens_milli >= 0),
    last_refill_at timestamptz NOT NULL,
    PRIMARY KEY (scope, bucket_key)
);

CREATE TRIGGER mail_rate_buckets_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_rate_buckets
FOR EACH STATEMENT EXECUTE FUNCTION relay.guard_mail_mutation();

REVOKE ALL ON relay.mail_rate_buckets FROM PUBLIC;
GRANT SELECT, INSERT ON relay.mail_rate_buckets TO punaro_app;
GRANT UPDATE (tokens_milli, last_refill_at) ON relay.mail_rate_buckets TO punaro_app;
