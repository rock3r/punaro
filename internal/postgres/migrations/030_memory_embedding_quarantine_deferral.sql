CREATE OR REPLACE FUNCTION brain.claim_embedding_jobs(requested_holder uuid, requested_limit integer, requested_lease_micros bigint)
RETURNS TABLE(generation_id uuid, item_id uuid, revision bigint, content_sha256 bytea, attempts integer, lease_holder uuid, lease_token uuid, lease_generation bigint, lease_until timestamptz)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    PERFORM jobs.assert_application_mutation();
    IF requested_holder IS NULL OR requested_limit IS NULL OR requested_lease_micros IS NULL
       OR requested_limit < 1 OR requested_limit > 32 OR requested_lease_micros < 5000000 OR requested_lease_micros > 300000000 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid embedding claim request';
    END IF;
    RETURN QUERY WITH quarantined_expired AS MATERIALIZED (
        SELECT job.generation_id, job.item_id
        FROM brain.embedding_jobs AS job
        WHERE job.state='running' AND job.lease_until <= statement_timestamp() AND job.attempts > 0
          AND EXISTS (SELECT 1 FROM brain.memory_quarantines AS quarantine WHERE quarantine.item_id=job.item_id AND quarantine.released_at IS NULL)
        ORDER BY job.lease_until, job.created_at, job.item_id
        FOR UPDATE SKIP LOCKED
        LIMIT requested_limit
    ), deferred AS (
        UPDATE brain.embedding_jobs AS job
        SET state='queued', attempts=job.attempts-1, lease_holder=NULL, lease_token=NULL, lease_until=NULL,
            available_at=statement_timestamp(), last_error_code='quarantined', completed_at=NULL, updated_at=statement_timestamp()
        FROM quarantined_expired
        WHERE job.generation_id=quarantined_expired.generation_id AND job.item_id=quarantined_expired.item_id
    ), expired_terminal AS MATERIALIZED (
        SELECT job.generation_id, job.item_id
        FROM brain.embedding_jobs AS job
        WHERE job.state='running' AND job.lease_until <= statement_timestamp() AND job.attempts >= 25
        ORDER BY job.lease_until, job.created_at, job.item_id
        FOR UPDATE SKIP LOCKED
        LIMIT requested_limit
    ), locked_terminal AS MATERIALIZED (
        SELECT expired_terminal.generation_id, expired_terminal.item_id
        FROM expired_terminal
        WHERE pg_try_advisory_xact_lock(hashtextextended(expired_terminal.item_id::text, 801337))
    ), exhausted AS MATERIALIZED (
        SELECT locked_terminal.generation_id, locked_terminal.item_id
        FROM locked_terminal
        WHERE NOT EXISTS (SELECT 1 FROM brain.memory_quarantines AS quarantine WHERE quarantine.item_id=locked_terminal.item_id AND quarantine.released_at IS NULL)
    ), failed AS (
        UPDATE brain.embedding_jobs AS job
        SET state='failed', lease_holder=NULL, lease_token=NULL, lease_until=NULL,
            last_error_code='attempts_exhausted', completed_at=statement_timestamp(), updated_at=statement_timestamp()
        FROM exhausted
        WHERE job.generation_id=exhausted.generation_id AND job.item_id=exhausted.item_id
    ), candidates AS MATERIALIZED (
        SELECT job.generation_id, job.item_id
        FROM brain.embedding_jobs AS job
        WHERE job.attempts < 25 AND ((job.state='queued' AND job.available_at <= statement_timestamp()) OR (job.state='running' AND job.lease_until <= statement_timestamp()))
          AND NOT EXISTS (SELECT 1 FROM brain.memory_quarantines AS quarantine WHERE quarantine.item_id=job.item_id AND quarantine.released_at IS NULL)
        ORDER BY COALESCE(job.lease_until, job.available_at), job.created_at, job.item_id
        FOR UPDATE SKIP LOCKED
        LIMIT requested_limit
    )
    UPDATE brain.embedding_jobs AS job
    SET state='running', attempts=job.attempts+1, lease_holder=requested_holder, lease_token=gen_random_uuid(),
        lease_generation=job.lease_generation+1, lease_until=statement_timestamp() + (requested_lease_micros * interval '1 microsecond'),
        last_error_code=NULL, completed_at=NULL, updated_at=statement_timestamp()
    FROM candidates
    WHERE job.generation_id=candidates.generation_id AND job.item_id=candidates.item_id
    RETURNING job.generation_id,job.item_id,job.revision,job.content_sha256,job.attempts,job.lease_holder,job.lease_token,job.lease_generation,job.lease_until;
END
$function$;

CREATE OR REPLACE FUNCTION brain.retry_embedding_job(requested_generation uuid, requested_item uuid, requested_revision bigint, requested_sha256 bytea, requested_token uuid, requested_lease_generation bigint, requested_delay_micros bigint, requested_error_code text)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    PERFORM jobs.assert_application_mutation();
    IF requested_generation IS NULL OR requested_item IS NULL OR requested_revision IS NULL OR requested_sha256 IS NULL
       OR requested_token IS NULL OR requested_lease_generation IS NULL OR requested_delay_micros IS NULL OR requested_error_code IS NULL
       OR requested_revision < 1 OR octet_length(requested_sha256) <> 32 OR requested_lease_generation < 1
       OR requested_delay_micros < 0 OR requested_delay_micros > 3600000000
       OR requested_error_code !~ '^[a-z][a-z0-9_.:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid embedding retry request';
    END IF;
    UPDATE brain.embedding_jobs
    SET state=CASE WHEN attempts >= 25 AND NOT (requested_error_code='quarantined' AND EXISTS (SELECT 1 FROM brain.memory_quarantines AS quarantine WHERE quarantine.item_id=brain.embedding_jobs.item_id AND quarantine.released_at IS NULL)) THEN 'failed' ELSE 'queued' END,
        attempts=CASE WHEN requested_error_code='quarantined' AND EXISTS (SELECT 1 FROM brain.memory_quarantines AS quarantine WHERE quarantine.item_id=brain.embedding_jobs.item_id AND quarantine.released_at IS NULL) THEN attempts-1 ELSE attempts END,
        available_at=CASE WHEN attempts >= 25 AND NOT (requested_error_code='quarantined' AND EXISTS (SELECT 1 FROM brain.memory_quarantines AS quarantine WHERE quarantine.item_id=brain.embedding_jobs.item_id AND quarantine.released_at IS NULL)) THEN available_at ELSE statement_timestamp() + (requested_delay_micros * interval '1 microsecond') END,
        lease_holder=NULL, lease_token=NULL, lease_until=NULL,
        last_error_code=requested_error_code,
        completed_at=CASE WHEN attempts >= 25 AND NOT (requested_error_code='quarantined' AND EXISTS (SELECT 1 FROM brain.memory_quarantines AS quarantine WHERE quarantine.item_id=brain.embedding_jobs.item_id AND quarantine.released_at IS NULL)) THEN statement_timestamp() ELSE NULL END,
        updated_at=statement_timestamp()
    WHERE generation_id=requested_generation AND item_id=requested_item AND revision=requested_revision
      AND content_sha256=requested_sha256 AND state='running' AND lease_token=requested_token
      AND lease_generation=requested_lease_generation AND lease_until > statement_timestamp();
    RETURN FOUND;
END
$function$;
