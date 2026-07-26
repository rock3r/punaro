CREATE TABLE brain.embedding_generations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    model text NOT NULL CHECK (model ~ '^[a-z][a-z0-9_.:-]{0,63}$'),
    model_revision text NOT NULL CHECK (model_revision ~ '^[a-z0-9][a-z0-9_.:-]{0,63}$'),
    dimensions integer NOT NULL CHECK (dimensions BETWEEN 1 AND 4096),
    state text NOT NULL DEFAULT 'active' CHECK (state = 'active'),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    UNIQUE (model, model_revision, dimensions)
);

CREATE UNIQUE INDEX embedding_generations_one_active
ON brain.embedding_generations ((true));

CREATE FUNCTION brain.reject_embedding_generation_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'embedding generations are immutable';
END
$function$;

CREATE TRIGGER embedding_generation_immutable
BEFORE UPDATE OR DELETE ON brain.embedding_generations
FOR EACH ROW EXECUTE FUNCTION brain.reject_embedding_generation_mutation();

CREATE TABLE brain.embedding_jobs (
    generation_id uuid NOT NULL REFERENCES brain.embedding_generations(id),
    item_id uuid NOT NULL REFERENCES brain.memory_items(id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision >= 1),
    content_sha256 bytea NOT NULL CHECK (octet_length(content_sha256) = 32),
    state text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'running', 'succeeded', 'failed')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 25),
    lease_holder uuid,
    lease_token uuid,
    lease_generation bigint NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
    lease_until timestamptz,
    last_error_code text CHECK (last_error_code IS NULL OR last_error_code ~ '^[a-z][a-z0-9_.:-]{0,127}$'),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    completed_at timestamptz,
    PRIMARY KEY (generation_id, item_id),
    FOREIGN KEY (item_id, revision) REFERENCES brain.memory_revisions(item_id, revision) ON DELETE CASCADE,
    CHECK (
        (state = 'queued' AND lease_holder IS NULL AND lease_token IS NULL AND lease_until IS NULL AND completed_at IS NULL)
        OR (state = 'running' AND lease_holder IS NOT NULL AND lease_token IS NOT NULL AND lease_until IS NOT NULL AND completed_at IS NULL)
        OR (state IN ('succeeded', 'failed') AND lease_holder IS NULL AND lease_token IS NULL AND lease_until IS NULL AND completed_at IS NOT NULL)
    )
);

CREATE INDEX embedding_jobs_claim_order
ON brain.embedding_jobs (generation_id, created_at, item_id)
WHERE state = 'queued';

CREATE INDEX embedding_jobs_expired_lease
ON brain.embedding_jobs (generation_id, lease_until, item_id)
WHERE state = 'running';

CREATE FUNCTION brain.queue_embedding_revision()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    INSERT INTO brain.embedding_jobs (generation_id, item_id, revision, content_sha256)
    SELECT generation.id, NEW.item_id, NEW.revision, NEW.content_sha256
    FROM brain.embedding_generations AS generation
    WHERE generation.state = 'active'
    ON CONFLICT (generation_id, item_id) DO UPDATE
    SET revision = EXCLUDED.revision,
        content_sha256 = EXCLUDED.content_sha256,
        state = 'queued',
        attempts = 0,
        lease_holder = NULL,
        lease_token = NULL,
        lease_generation = brain.embedding_jobs.lease_generation + 1,
        lease_until = NULL,
        last_error_code = NULL,
        updated_at = statement_timestamp(),
        completed_at = NULL;
    RETURN NEW;
END
$function$;

CREATE TRIGGER memory_revision_embedding_queue
AFTER INSERT ON brain.memory_revisions
FOR EACH ROW EXECUTE FUNCTION brain.queue_embedding_revision();

REVOKE ALL ON brain.embedding_generations, brain.embedding_jobs FROM PUBLIC, punaro_app;
REVOKE ALL ON FUNCTION brain.reject_embedding_generation_mutation(), brain.queue_embedding_revision() FROM PUBLIC;
GRANT SELECT ON brain.embedding_generations, brain.embedding_jobs TO punaro_app;
