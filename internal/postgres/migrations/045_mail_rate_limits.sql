CREATE TABLE relay.mail_rate_buckets (
    kind text NOT NULL CHECK (kind IN ('sender', 'conversation')),
    bucket_key text NOT NULL CHECK (
        char_length(bucket_key) >= 1 AND char_length(bucket_key) <= 512
        AND octet_length(bucket_key) <= 2048
        AND bucket_key !~ '[[:cntrl:]]'
    ),
    tokens bigint NOT NULL CHECK (tokens >= 0),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (kind, bucket_key)
);

CREATE TRIGGER mail_rate_buckets_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_rate_buckets
FOR EACH STATEMENT EXECUTE FUNCTION relay.guard_mail_mutation();

REVOKE ALL ON relay.mail_rate_buckets FROM PUBLIC;
GRANT SELECT, INSERT ON relay.mail_rate_buckets TO punaro_app;
GRANT UPDATE (tokens, updated_at) ON relay.mail_rate_buckets TO punaro_app;
