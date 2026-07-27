CREATE FUNCTION brain.release_memory_quarantine(requested_item uuid, requested_principal uuid)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    was_released boolean;
BEGIN
    PERFORM jobs.assert_application_mutation();
    IF requested_item IS NULL OR requested_principal IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid memory quarantine release';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(requested_item::text, 801337));
    WITH released AS MATERIALIZED (
        UPDATE brain.memory_quarantines
        SET released_by=requested_principal,released_at=statement_timestamp()
        WHERE item_id=requested_item AND released_at IS NULL
        RETURNING item_id,quarantined_at
    ), requeued AS (
        UPDATE brain.embedding_jobs AS job
        SET state='queued', attempts=job.attempts-1,
            lease_holder=NULL, lease_token=NULL, lease_until=NULL,
            available_at=statement_timestamp(), last_error_code='quarantined', completed_at=NULL, updated_at=statement_timestamp()
        FROM released
        WHERE job.item_id=released.item_id AND job.state='running' AND job.attempts>0
          AND job.lease_until <= statement_timestamp()
    )
    SELECT EXISTS (SELECT 1 FROM released) INTO was_released;
    RETURN was_released;
END
$function$;

REVOKE ALL ON FUNCTION brain.release_memory_quarantine(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION brain.release_memory_quarantine(uuid,uuid) TO punaro_app;
