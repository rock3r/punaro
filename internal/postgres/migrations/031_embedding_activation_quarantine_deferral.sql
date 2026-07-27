CREATE OR REPLACE FUNCTION brain.activate_embedding_generation(requested_generation uuid)
RETURNS TABLE (generation_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    prior_generation uuid;
BEGIN
    PERFORM jobs.assert_application_mutation();
    IF requested_generation IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid embedding generation activation';
    END IF;
    PERFORM pg_advisory_xact_lock(5788618938515408205);
    PERFORM 1 FROM jobs.server_state WHERE singleton FOR UPDATE;
    SELECT generation.id INTO prior_generation FROM brain.embedding_generations AS generation WHERE generation.state = 'active' FOR UPDATE;
    IF prior_generation IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'active embedding generation is required';
    END IF;
    PERFORM 1 FROM brain.embedding_generations AS generation JOIN brain.embedding_rebuild_progress AS progress ON progress.generation_id = generation.id
    WHERE generation.id = requested_generation AND generation.state = 'building' AND progress.complete FOR UPDATE OF generation, progress;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'embedding rebuild generation is not complete';
    END IF;
    IF EXISTS (
        SELECT 1 FROM brain.embedding_jobs AS job
        WHERE job.generation_id = requested_generation AND job.state <> 'succeeded'
          AND (job.state <> 'queued' OR NOT EXISTS (SELECT 1 FROM brain.memory_quarantines AS quarantine WHERE quarantine.item_id=job.item_id AND quarantine.released_at IS NULL))
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'embedding rebuild generation is not caught up';
    END IF;
    PERFORM set_config('punaro.embedding_activation_old_generation', prior_generation::text, true);
    PERFORM 1 FROM brain.embedding_jobs AS job WHERE job.generation_id = prior_generation FOR UPDATE;
    DELETE FROM brain.embedding_chunks AS chunk WHERE chunk.generation_id = prior_generation;
    DELETE FROM brain.embedding_jobs AS job WHERE job.generation_id = prior_generation;
    PERFORM set_config('punaro.embedding_activation_generation', prior_generation::text, true);
    DELETE FROM brain.embedding_generations WHERE id = prior_generation;
    DELETE FROM brain.embedding_rebuild_progress AS progress WHERE progress.generation_id = requested_generation;
    PERFORM set_config('punaro.embedding_activation_generation', requested_generation::text, true);
    UPDATE brain.embedding_generations SET state = 'active', start_change_sequence = NULL, start_timeline_id = NULL WHERE id = requested_generation;
    generation_id := requested_generation;
    RETURN NEXT;
END
$function$;
