ALTER TABLE brain.embedding_generations
ADD COLUMN start_change_sequence bigint;

ALTER TABLE brain.embedding_generations
DROP CONSTRAINT embedding_generations_model_model_revision_dimensions_key;

ALTER TABLE brain.embedding_generations
DROP CONSTRAINT embedding_generations_state_check;

ALTER TABLE brain.embedding_generations
ADD CONSTRAINT embedding_generations_state_check CHECK (
    (state = 'active' AND start_change_sequence IS NULL)
    OR (state = 'building' AND start_change_sequence >= 0)
);

DROP INDEX brain.embedding_generations_one_active;

CREATE UNIQUE INDEX embedding_generations_one_active
ON brain.embedding_generations ((true))
WHERE state = 'active';

CREATE UNIQUE INDEX embedding_generations_one_building
ON brain.embedding_generations ((true))
WHERE state = 'building';

CREATE OR REPLACE FUNCTION brain.queue_embedding_revision()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    PERFORM pg_advisory_xact_lock_shared(5788618938515408205);
    INSERT INTO brain.embedding_jobs (generation_id, item_id, revision, content_sha256)
    SELECT generation.id, NEW.item_id, NEW.revision, NEW.content_sha256
    FROM brain.embedding_generations AS generation
    WHERE generation.state IN ('active', 'building')
    ON CONFLICT (generation_id, item_id) DO UPDATE
    SET revision = EXCLUDED.revision,
        content_sha256 = EXCLUDED.content_sha256,
        state = 'queued', attempts = 0,
        lease_holder = NULL, lease_token = NULL,
        lease_generation = brain.embedding_jobs.lease_generation + 1,
        lease_until = NULL, available_at = statement_timestamp(),
        last_error_code = NULL, updated_at = statement_timestamp(), completed_at = NULL;
    RETURN NEW;
END
$function$;

CREATE FUNCTION brain.start_embedding_generation(requested_model text, requested_model_revision text, requested_dimensions integer)
RETURNS TABLE (generation_id uuid, start_change_sequence bigint)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    captured_sequence bigint;
    new_generation_id uuid;
BEGIN
    PERFORM jobs.assert_application_mutation();
    IF requested_model IS NULL OR requested_model_revision IS NULL OR requested_dimensions IS NULL
       OR requested_model !~ '^[a-z][a-z0-9_.:-]{0,63}$'
       OR requested_model_revision !~ '^[a-z0-9][a-z0-9_.:-]{0,63}$'
       OR requested_dimensions < 1 OR requested_dimensions > 4096 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid embedding generation';
    END IF;
    PERFORM pg_advisory_xact_lock(5788618938515408205);
    PERFORM 1 FROM jobs.server_state WHERE singleton FOR UPDATE;
    IF NOT EXISTS (SELECT 1 FROM brain.embedding_generations WHERE state = 'active') THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'active embedding generation is required';
    END IF;
    IF EXISTS (SELECT 1 FROM brain.embedding_generations WHERE state = 'building') THEN
        RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'embedding generation rebuild already exists';
    END IF;
    SELECT change_sequence INTO captured_sequence
    FROM jobs.server_state
    WHERE singleton;
    INSERT INTO brain.embedding_generations (model, model_revision, dimensions, state, start_change_sequence)
    VALUES (requested_model, requested_model_revision, requested_dimensions, 'building', captured_sequence)
    RETURNING id INTO new_generation_id;
    generation_id := new_generation_id;
    start_change_sequence := captured_sequence;
    RETURN NEXT;
END
$function$;

REVOKE ALL ON FUNCTION brain.start_embedding_generation(text,text,integer) FROM PUBLIC, punaro_app;
