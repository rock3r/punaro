CREATE EXTENSION IF NOT EXISTS vector;

-- v25-v28 output intentionally carried only chunk coordinates. They are
-- derived state, so requeue completed or interrupted work rather than ever
-- treating a coordinate-only success as a semantic result.
DELETE FROM brain.embedding_chunks;

UPDATE brain.embedding_jobs
SET state='queued', attempts=0, lease_holder=NULL, lease_token=NULL,
    lease_generation=lease_generation+1, lease_until=NULL,
    available_at=statement_timestamp(), last_error_code=NULL,
    completed_at=NULL, updated_at=statement_timestamp()
WHERE state IN ('running','succeeded');

ALTER TABLE brain.embedding_chunks
ADD COLUMN embedding vector NOT NULL;

CREATE OR REPLACE FUNCTION brain.publish_embedding_job(requested_generation uuid, requested_item uuid, requested_revision bigint, requested_sha256 bytea, requested_token uuid, requested_lease_generation bigint, requested_chunks jsonb)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    chunk_count integer;
BEGIN
    PERFORM jobs.assert_application_mutation();
    IF requested_generation IS NULL OR requested_item IS NULL OR requested_revision IS NULL OR requested_sha256 IS NULL
       OR requested_token IS NULL OR requested_lease_generation IS NULL OR requested_chunks IS NULL
       OR requested_revision < 1 OR octet_length(requested_sha256) <> 32 OR requested_lease_generation < 1
       OR jsonb_typeof(requested_chunks) <> 'array' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid embedding publication';
    END IF;
    chunk_count := jsonb_array_length(requested_chunks);
    IF chunk_count < 1 OR chunk_count > 64 OR EXISTS (
        SELECT 1
        FROM jsonb_to_recordset(requested_chunks) AS chunk(ordinal integer, content_sha256 text, start_offset integer, end_offset integer, embedding jsonb)
        WHERE ordinal IS NULL OR content_sha256 IS NULL OR start_offset IS NULL OR end_offset IS NULL OR embedding IS NULL
           OR ordinal < 0 OR ordinal >= chunk_count OR content_sha256 !~ '^[0-9a-f]{64}$'
           OR start_offset < 0 OR end_offset <= start_offset OR end_offset > 262144
           OR jsonb_typeof(embedding) <> 'array'
           OR EXISTS (SELECT 1 FROM jsonb_array_elements(embedding) AS value WHERE jsonb_typeof(value) <> 'number')
    ) OR EXISTS (
        SELECT 1 FROM jsonb_to_recordset(requested_chunks) AS chunk(ordinal integer, content_sha256 text, start_offset integer, end_offset integer, embedding jsonb)
        GROUP BY ordinal HAVING count(*) <> 1
    ) OR EXISTS (
        SELECT 1 FROM generate_series(0, chunk_count - 1) AS expected(ordinal)
        LEFT JOIN jsonb_to_recordset(requested_chunks) AS chunk(ordinal integer, content_sha256 text, start_offset integer, end_offset integer, embedding jsonb) USING (ordinal)
        WHERE chunk.ordinal IS NULL
    ) OR EXISTS (
        SELECT 1 FROM (
            SELECT start_offset,lag(end_offset) OVER (ORDER BY ordinal) AS previous_end
            FROM jsonb_to_recordset(requested_chunks) AS chunk(ordinal integer, content_sha256 text, start_offset integer, end_offset integer, embedding jsonb)
        ) AS ordered WHERE start_offset < previous_end
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid embedding publication';
    END IF;
    WITH locked AS MATERIALIZED (
        SELECT job.generation_id,job.item_id,job.revision,generation.dimensions
        FROM brain.embedding_jobs AS job
        JOIN brain.embedding_generations AS generation ON generation.id=job.generation_id
        JOIN brain.memory_items AS item ON item.id=job.item_id AND item.current_revision=job.revision
        WHERE job.generation_id=requested_generation AND job.item_id=requested_item AND job.revision=requested_revision
          AND job.content_sha256=requested_sha256 AND job.state='running' AND job.lease_token=requested_token
          AND job.lease_generation=requested_lease_generation AND job.lease_until > statement_timestamp()
        FOR UPDATE OF job
    ), input AS MATERIALIZED (
        SELECT chunk.ordinal,chunk.content_sha256,chunk.start_offset,chunk.end_offset,chunk.embedding
        FROM jsonb_to_recordset(requested_chunks) AS chunk(ordinal smallint, content_sha256 text, start_offset integer, end_offset integer, embedding jsonb)
    ), checked AS MATERIALIZED (
        SELECT input.* FROM input CROSS JOIN locked
        WHERE jsonb_array_length(input.embedding)=locked.dimensions
    ), cleared AS (
        DELETE FROM brain.embedding_chunks AS chunk USING locked
        WHERE chunk.generation_id=locked.generation_id AND chunk.item_id=locked.item_id AND chunk.revision=locked.revision
    ), inserted AS (
        INSERT INTO brain.embedding_chunks(generation_id,item_id,revision,ordinal,content_sha256,start_offset,end_offset,embedding)
        SELECT locked.generation_id,locked.item_id,locked.revision,checked.ordinal,decode(checked.content_sha256,'hex'),checked.start_offset,checked.end_offset,checked.embedding::text::public.vector
        FROM locked CROSS JOIN checked
        RETURNING 1
    )
    UPDATE brain.embedding_jobs AS job
    SET state='succeeded', lease_holder=NULL, lease_token=NULL, lease_until=NULL,
        last_error_code=NULL, completed_at=statement_timestamp(), updated_at=statement_timestamp()
    FROM locked
    WHERE job.generation_id=locked.generation_id AND job.item_id=locked.item_id
      AND (SELECT count(*) FROM inserted)=chunk_count;
    RETURN FOUND;
END
$function$;
