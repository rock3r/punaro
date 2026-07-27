CREATE OR REPLACE FUNCTION brain.reject_embedding_generation_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF session_user = 'punaro_owner'
       AND current_setting('punaro.embedding_activation_generation', true) = OLD.id::text
       AND ((TG_OP = 'DELETE' AND OLD.state = 'active')
            OR (TG_OP = 'UPDATE' AND OLD.state = 'building' AND NEW.state = 'active'
                AND NEW.start_change_sequence IS NULL AND NEW.start_timeline_id IS NULL)) THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'embedding generations are immutable';
END
$function$;

DROP TRIGGER application_mutation_fence ON brain.embedding_chunks;

CREATE TRIGGER application_mutation_fence
BEFORE INSERT OR UPDATE OR TRUNCATE ON brain.embedding_chunks
FOR EACH STATEMENT EXECUTE FUNCTION jobs.guard_application_mutation();

CREATE FUNCTION brain.guard_embedding_chunk_delete()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF session_user = 'punaro_owner'
       AND current_setting('punaro.embedding_activation_old_generation', true) = OLD.generation_id::text THEN
        RETURN OLD;
    END IF;
    IF session_user = 'punaro_owner'
       AND EXISTS (
        SELECT 1 FROM jobs.update_transactions
        WHERE update_id::text = current_setting('punaro.update_id', true)
          AND phase = 'migration_started'
       ) THEN
        RETURN OLD;
    END IF;
    IF session_user = 'punaro_owner'
       AND EXISTS (
        SELECT 1
        FROM jobs.update_transactions AS txn
        JOIN jobs.restore_events AS event
          ON event.backup_id::text = current_setting('punaro.restore_backup_id', true)
         AND event.installation_id = txn.installation_id
         AND event.previous_timeline_id = txn.timeline_id
        JOIN jobs.server_state AS state
          ON state.singleton
         AND state.installation_id = event.installation_id
         AND state.timeline_id = event.previous_timeline_id
         AND state.change_sequence = event.restored_change_sequence
        WHERE txn.update_id::text = current_setting('punaro.restore_update_id', true)
          AND txn.phase = 'writers_stopped'
       ) THEN
        RETURN OLD;
    END IF;
    PERFORM jobs.assert_application_mutation();
    RETURN OLD;
END
$function$;

CREATE TRIGGER embedding_chunks_delete_fence
BEFORE DELETE ON brain.embedding_chunks
FOR EACH ROW EXECUTE FUNCTION brain.guard_embedding_chunk_delete();

CREATE FUNCTION brain.activate_embedding_generation(requested_generation uuid)
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
    SELECT generation.id INTO prior_generation
    FROM brain.embedding_generations AS generation
    WHERE generation.state = 'active'
    FOR UPDATE;
    IF prior_generation IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'active embedding generation is required';
    END IF;
    PERFORM 1
    FROM brain.embedding_generations AS generation
    JOIN brain.embedding_rebuild_progress AS progress ON progress.generation_id = generation.id
    WHERE generation.id = requested_generation AND generation.state = 'building' AND progress.complete
    FOR UPDATE OF generation, progress;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'embedding rebuild generation is not complete';
    END IF;
    IF EXISTS (
        SELECT 1 FROM brain.embedding_jobs AS job
        WHERE job.generation_id = requested_generation AND job.state <> 'succeeded'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'embedding rebuild generation is not caught up';
    END IF;
    PERFORM set_config('punaro.embedding_activation_old_generation', prior_generation::text, true);
    DELETE FROM brain.embedding_chunks AS chunk WHERE chunk.generation_id = prior_generation;
    DELETE FROM brain.embedding_jobs AS job WHERE job.generation_id = prior_generation;
    PERFORM set_config('punaro.embedding_activation_generation', prior_generation::text, true);
    DELETE FROM brain.embedding_generations WHERE id = prior_generation;
    DELETE FROM brain.embedding_rebuild_progress AS progress WHERE progress.generation_id = requested_generation;
    PERFORM set_config('punaro.embedding_activation_generation', requested_generation::text, true);
    UPDATE brain.embedding_generations
    SET state = 'active', start_change_sequence = NULL, start_timeline_id = NULL
    WHERE id = requested_generation;
    generation_id := requested_generation;
    RETURN NEXT;
END
$function$;

REVOKE ALL ON FUNCTION brain.guard_embedding_chunk_delete() FROM PUBLIC, punaro_app;
REVOKE ALL ON FUNCTION brain.activate_embedding_generation(uuid) FROM PUBLIC, punaro_app;
