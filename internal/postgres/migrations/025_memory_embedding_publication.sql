CREATE TABLE brain.embedding_chunks (
    generation_id uuid NOT NULL REFERENCES brain.embedding_generations(id),
    item_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision >= 1),
    ordinal smallint NOT NULL CHECK (ordinal BETWEEN 0 AND 63),
    content_sha256 bytea NOT NULL CHECK (octet_length(content_sha256) = 32),
    start_offset integer NOT NULL CHECK (start_offset >= 0),
    end_offset integer NOT NULL CHECK (end_offset > start_offset AND end_offset <= 262144),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (generation_id, item_id, revision, ordinal),
    FOREIGN KEY (item_id, revision) REFERENCES brain.memory_revisions(item_id, revision) ON DELETE CASCADE
);

CREATE FUNCTION brain.publish_embedding_job(requested_generation uuid, requested_item uuid, requested_revision bigint, requested_sha256 bytea, requested_token uuid, requested_lease_generation bigint, requested_chunks jsonb)
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
        FROM jsonb_to_recordset(requested_chunks) AS chunk(ordinal integer, content_sha256 text, start_offset integer, end_offset integer)
        WHERE ordinal IS NULL OR content_sha256 IS NULL OR start_offset IS NULL OR end_offset IS NULL
           OR ordinal < 0 OR ordinal >= chunk_count OR content_sha256 !~ '^[0-9a-f]{64}$'
           OR start_offset < 0 OR end_offset <= start_offset OR end_offset > 262144
    ) OR EXISTS (
        SELECT 1 FROM jsonb_to_recordset(requested_chunks) AS chunk(ordinal integer, content_sha256 text, start_offset integer, end_offset integer)
        GROUP BY ordinal HAVING count(*) <> 1
    ) OR EXISTS (
        SELECT 1 FROM generate_series(0, chunk_count - 1) AS expected(ordinal)
        LEFT JOIN jsonb_to_recordset(requested_chunks) AS chunk(ordinal integer, content_sha256 text, start_offset integer, end_offset integer) USING (ordinal)
        WHERE chunk.ordinal IS NULL
    ) OR EXISTS (
        SELECT 1 FROM (
            SELECT start_offset,lag(end_offset) OVER (ORDER BY ordinal) AS previous_end
            FROM jsonb_to_recordset(requested_chunks) AS chunk(ordinal integer, content_sha256 text, start_offset integer, end_offset integer)
        ) AS ordered WHERE start_offset < previous_end
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid embedding publication';
    END IF;
    WITH locked AS MATERIALIZED (
        SELECT job.generation_id,job.item_id,job.revision
        FROM brain.embedding_jobs AS job
        JOIN brain.memory_items AS item ON item.id=job.item_id AND item.current_revision=job.revision
        WHERE job.generation_id=requested_generation AND job.item_id=requested_item AND job.revision=requested_revision
          AND job.content_sha256=requested_sha256 AND job.state='running' AND job.lease_token=requested_token
          AND job.lease_generation=requested_lease_generation AND job.lease_until > statement_timestamp()
        FOR UPDATE OF job
    ), cleared AS (
        DELETE FROM brain.embedding_chunks AS chunk USING locked
        WHERE chunk.generation_id=locked.generation_id AND chunk.item_id=locked.item_id AND chunk.revision=locked.revision
    ), inserted AS (
        INSERT INTO brain.embedding_chunks(generation_id,item_id,revision,ordinal,content_sha256,start_offset,end_offset)
        SELECT locked.generation_id,locked.item_id,locked.revision,chunk.ordinal,decode(chunk.content_sha256,'hex'),chunk.start_offset,chunk.end_offset
        FROM locked CROSS JOIN jsonb_to_recordset(requested_chunks) AS chunk(ordinal smallint, content_sha256 text, start_offset integer, end_offset integer)
    )
    UPDATE brain.embedding_jobs AS job
    SET state='succeeded', lease_holder=NULL, lease_token=NULL, lease_until=NULL,
        last_error_code=NULL, completed_at=statement_timestamp(), updated_at=statement_timestamp()
    FROM locked
    WHERE job.generation_id=locked.generation_id AND job.item_id=locked.item_id;
    RETURN FOUND;
END
$function$;

DO $block$
BEGIN
    EXECUTE 'CREATE TRIGGER application_mutation_fence BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON brain.embedding_chunks FOR EACH STATEMENT EXECUTE FUNCTION jobs.guard_application_mutation()';
END
$block$;

REVOKE ALL ON brain.embedding_chunks FROM PUBLIC, punaro_app;
REVOKE ALL ON FUNCTION brain.publish_embedding_job(uuid,uuid,bigint,bytea,uuid,bigint,jsonb) FROM PUBLIC;
GRANT SELECT ON brain.embedding_chunks TO punaro_app;
GRANT EXECUTE ON FUNCTION brain.publish_embedding_job(uuid,uuid,bigint,bytea,uuid,bigint,jsonb) TO punaro_app;
