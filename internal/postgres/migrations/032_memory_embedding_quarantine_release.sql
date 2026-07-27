CREATE FUNCTION brain.requeue_expired_quarantined_embedding_jobs()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    PERFORM jobs.assert_application_mutation();
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.item_id::text, 801337));
    UPDATE brain.embedding_jobs AS job
    SET state='queued', attempts=job.attempts-1,
        lease_holder=NULL, lease_token=NULL, lease_until=NULL,
        available_at=statement_timestamp(), last_error_code='quarantined', completed_at=NULL, updated_at=statement_timestamp()
    WHERE job.item_id=NEW.item_id AND job.state='running' AND job.attempts>0
      AND job.lease_until <= statement_timestamp();
    RETURN NEW;
END
$function$;

CREATE TRIGGER memory_quarantine_embedding_release
AFTER UPDATE OF released_at ON brain.memory_quarantines
FOR EACH ROW WHEN (OLD.released_at IS NULL AND NEW.released_at IS NOT NULL)
EXECUTE FUNCTION brain.requeue_expired_quarantined_embedding_jobs();

REVOKE ALL ON FUNCTION brain.requeue_expired_quarantined_embedding_jobs() FROM PUBLIC, punaro_app;
GRANT EXECUTE ON FUNCTION brain.requeue_expired_quarantined_embedding_jobs() TO punaro_owner;
