ALTER TABLE brain.embedding_generations
ADD COLUMN start_timeline_id uuid;

-- A v26 building generation has no durable timeline identity, so its sequence
-- watermark cannot be interpreted after restore or promotion. It is derived
-- work only: discard it atomically before accepting timeline-bound rebuilds.
ALTER TABLE brain.embedding_generations DISABLE TRIGGER USER;
DELETE FROM brain.embedding_chunks
WHERE generation_id IN (SELECT id FROM brain.embedding_generations WHERE state = 'building');
DELETE FROM brain.embedding_jobs
WHERE generation_id IN (SELECT id FROM brain.embedding_generations WHERE state = 'building');
DELETE FROM brain.embedding_generations WHERE state = 'building';
ALTER TABLE brain.embedding_generations ENABLE TRIGGER USER;

CREATE TABLE brain.embedding_rebuild_progress (
    generation_id uuid PRIMARY KEY REFERENCES brain.embedding_generations(id) ON DELETE CASCADE,
    timeline_id uuid NOT NULL,
    timeline_watermark bigint NOT NULL CHECK (timeline_watermark >= 0),
    cursor_change_sequence bigint NOT NULL DEFAULT 0 CHECK (cursor_change_sequence >= 0),
    reported_progress bigint NOT NULL DEFAULT 0 CHECK (reported_progress >= 0),
    complete boolean NOT NULL DEFAULT false
);

CREATE OR REPLACE FUNCTION brain.start_embedding_generation(requested_model text, requested_model_revision text, requested_dimensions integer)
RETURNS TABLE (generation_id uuid, start_change_sequence bigint)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    captured_sequence bigint;
    captured_timeline uuid;
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
    SELECT timeline_id,change_sequence INTO captured_timeline,captured_sequence FROM jobs.server_state WHERE singleton;
    INSERT INTO brain.embedding_generations (model,model_revision,dimensions,state,start_change_sequence,start_timeline_id)
    VALUES (requested_model,requested_model_revision,requested_dimensions,'building',captured_sequence,captured_timeline)
    RETURNING id INTO new_generation_id;
    INSERT INTO brain.embedding_rebuild_progress(generation_id,timeline_id,timeline_watermark) VALUES (new_generation_id,captured_timeline,captured_sequence);
    generation_id := new_generation_id;
    start_change_sequence := captured_sequence;
    RETURN NEXT;
END
$function$;

CREATE FUNCTION brain.enqueue_embedding_rebuild_batch(requested_generation uuid, requested_limit integer)
RETURNS TABLE (enqueued integer, cursor_change_sequence bigint, complete boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    watermark bigint;
    scanned integer;
    changed integer;
    next_cursor bigint;
    done boolean;
    next_timeline uuid;
    next_timeline_watermark bigint;
BEGIN
    PERFORM jobs.assert_application_mutation();
    IF requested_generation IS NULL OR requested_limit IS NULL OR requested_limit < 1 OR requested_limit > 128 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid embedding rebuild batch';
    END IF;
    SELECT generation.start_change_sequence,progress.complete
    INTO watermark,done
    FROM brain.embedding_rebuild_progress AS progress
    JOIN brain.embedding_generations AS generation ON generation.id=progress.generation_id
    WHERE progress.generation_id=requested_generation AND generation.state='building'
    FOR UPDATE OF progress;
    IF watermark IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'embedding rebuild generation is unavailable';
    END IF;
    IF done THEN
        SELECT progress.reported_progress INTO cursor_change_sequence
        FROM brain.embedding_rebuild_progress AS progress
        WHERE progress.generation_id=requested_generation;
        enqueued := 0; complete := true; RETURN NEXT; RETURN;
    END IF;
    WITH changes AS MATERIALIZED (
        SELECT change.change_sequence,change.item_id,change.revision
        FROM brain.embedding_rebuild_progress AS progress
        JOIN brain.memory_changes AS change ON change.timeline_id=progress.timeline_id
          AND change.change_sequence>progress.cursor_change_sequence AND change.change_sequence<=progress.timeline_watermark
        ORDER BY change.change_sequence
        LIMIT requested_limit
    ), candidates AS MATERIALIZED (
        SELECT changes.change_sequence,item.id AS item_id,changes.revision,revision.content_sha256
        FROM changes
        JOIN brain.memory_items AS item ON item.id=changes.item_id AND item.current_revision=changes.revision
        JOIN brain.memory_revisions AS revision ON revision.item_id=changes.item_id AND revision.revision=changes.revision
    ), queued AS (
        INSERT INTO brain.embedding_jobs(generation_id,item_id,revision,content_sha256)
        SELECT requested_generation,item_id,revision,content_sha256 FROM candidates
        ON CONFLICT (generation_id,item_id) DO UPDATE SET revision=EXCLUDED.revision,content_sha256=EXCLUDED.content_sha256,state='queued',attempts=0,lease_holder=NULL,lease_token=NULL,lease_generation=brain.embedding_jobs.lease_generation+1,lease_until=NULL,available_at=statement_timestamp(),last_error_code=NULL,updated_at=statement_timestamp(),completed_at=NULL
        WHERE brain.embedding_jobs.revision<EXCLUDED.revision
        RETURNING 1
    ), advanced AS (
        SELECT count(*)::integer AS scanned,COALESCE(max(changes.change_sequence),
            (SELECT progress.timeline_watermark FROM brain.embedding_rebuild_progress AS progress WHERE progress.generation_id=requested_generation)) AS next_cursor
        FROM changes
    ), applied AS (
        SELECT count(*) AS changed FROM queued
    )
    SELECT advanced.scanned,applied.changed,advanced.next_cursor,advanced.scanned<requested_limit INTO scanned,changed,next_cursor,done FROM advanced CROSS JOIN applied;
    IF done THEN
        SELECT event.previous_timeline_id,event.restored_change_sequence INTO next_timeline,next_timeline_watermark
        FROM jobs.restore_events AS event
        JOIN brain.embedding_rebuild_progress AS progress ON event.restored_timeline_id=progress.timeline_id
        WHERE progress.generation_id=requested_generation;
        IF next_timeline IS NOT NULL THEN
            UPDATE brain.embedding_rebuild_progress SET timeline_id=next_timeline,timeline_watermark=next_timeline_watermark,cursor_change_sequence=0,reported_progress=reported_progress+GREATEST(scanned,1) WHERE generation_id=requested_generation;
            done := false;
        ELSE
            UPDATE brain.embedding_rebuild_progress SET cursor_change_sequence=next_cursor,reported_progress=reported_progress+GREATEST(scanned,1),complete=true WHERE generation_id=requested_generation;
        END IF;
    ELSE
        UPDATE brain.embedding_rebuild_progress SET cursor_change_sequence=next_cursor,reported_progress=reported_progress+GREATEST(scanned,1) WHERE generation_id=requested_generation;
    END IF;
    SELECT progress.reported_progress INTO cursor_change_sequence FROM brain.embedding_rebuild_progress AS progress WHERE progress.generation_id=requested_generation;
    enqueued := changed; complete := done; RETURN NEXT;
END
$function$;

REVOKE ALL ON brain.embedding_rebuild_progress FROM PUBLIC, punaro_app;
REVOKE ALL ON FUNCTION brain.enqueue_embedding_rebuild_batch(uuid,integer) FROM PUBLIC, punaro_app;
