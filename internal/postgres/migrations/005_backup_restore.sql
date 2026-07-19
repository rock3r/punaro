CREATE TABLE attachment.ready_blob_manifest (
    storage_path text PRIMARY KEY,
    size_bytes bigint NOT NULL CHECK (size_bytes >= 0 AND size_bytes <= 17179869184),
    sha256 char(64) NOT NULL UNIQUE CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    ready_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CHECK (storage_path <> '' AND char_length(storage_path) <= 1024 AND octet_length(storage_path) <= 4096
           AND storage_path !~ '[[:cntrl:]]' AND storage_path !~ '(^|/)\.\.?(/|$)' AND storage_path !~ '^/' AND storage_path !~ '\\')
);

CREATE TABLE jobs.backup_gc_fences (
    fence_id uuid PRIMARY KEY,
    installation_id uuid NOT NULL,
    timeline_id uuid NOT NULL,
    snapshot_id text,
    acquired_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    expires_at timestamptz NOT NULL,
    released_at timestamptz,
    verified boolean,
    CHECK (expires_at > acquired_at),
    CHECK (snapshot_id IS NULL OR (char_length(snapshot_id) BETWEEN 1 AND 200 AND snapshot_id ~ '^[0-9A-Z-]+$')),
    CHECK ((released_at IS NULL) = (verified IS NULL)),
    CHECK (released_at IS NULL OR released_at >= acquired_at)
);

CREATE UNIQUE INDEX backup_gc_fences_active
ON jobs.backup_gc_fences (installation_id)
WHERE released_at IS NULL;

CREATE TABLE jobs.restore_events (
    restore_id uuid PRIMARY KEY,
    backup_id uuid NOT NULL UNIQUE,
    installation_id uuid NOT NULL,
    previous_timeline_id uuid NOT NULL,
    restored_timeline_id uuid NOT NULL UNIQUE,
    restored_change_sequence bigint NOT NULL CHECK (restored_change_sequence >= 0),
    restored_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CHECK (previous_timeline_id <> restored_timeline_id)
);

CREATE FUNCTION jobs.acquire_backup_gc_fence(lifetime interval)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    token uuid := gen_random_uuid();
BEGIN
    IF lifetime < interval '1 minute' OR lifetime > interval '1 hour' THEN
        RAISE EXCEPTION 'backup fence lifetime is invalid';
    END IF;
    UPDATE jobs.backup_gc_fences
    SET released_at = statement_timestamp(), verified = false
    WHERE released_at IS NULL AND expires_at <= statement_timestamp();
    DELETE FROM jobs.backup_gc_fences
    WHERE fence_id IN (
        SELECT fence_id FROM jobs.backup_gc_fences
        WHERE released_at IS NOT NULL
        ORDER BY released_at DESC, fence_id DESC
        OFFSET 1024
    );
    INSERT INTO jobs.backup_gc_fences (fence_id, installation_id, timeline_id, expires_at)
    SELECT token, installation_id, timeline_id, statement_timestamp() + lifetime
    FROM jobs.server_state WHERE singleton;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'installation state is unavailable';
    END IF;
    RETURN token;
END
$function$;

CREATE FUNCTION jobs.bind_backup_snapshot(token uuid, exported_snapshot text)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    UPDATE jobs.backup_gc_fences AS fence
    SET snapshot_id = exported_snapshot
    FROM jobs.server_state AS state
    WHERE fence.fence_id = token
      AND fence.released_at IS NULL
      AND fence.expires_at > statement_timestamp()
      AND fence.snapshot_id IS NULL
      AND state.singleton
      AND state.installation_id = fence.installation_id
      AND state.timeline_id = fence.timeline_id
      AND char_length(exported_snapshot) BETWEEN 1 AND 200
      AND exported_snapshot ~ '^[0-9A-Z-]+$'
    RETURNING true
$function$;

CREATE FUNCTION jobs.renew_backup_gc_fence(token uuid, exported_snapshot text, lifetime interval)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF lifetime < interval '1 minute' OR lifetime > interval '1 hour' THEN
        RETURN false;
    END IF;
    UPDATE jobs.backup_gc_fences AS fence
    SET expires_at = statement_timestamp() + lifetime
    FROM jobs.server_state AS state
    WHERE fence.fence_id = token
      AND fence.snapshot_id = exported_snapshot
      AND fence.released_at IS NULL
      AND fence.expires_at > statement_timestamp()
      AND state.singleton
      AND state.installation_id = fence.installation_id
      AND state.timeline_id = fence.timeline_id;
    RETURN FOUND;
END
$function$;

CREATE FUNCTION jobs.cancel_unbound_backup_gc_fence(token uuid)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    UPDATE jobs.backup_gc_fences
    SET released_at = statement_timestamp(), verified = false
    WHERE fence_id = token
      AND snapshot_id IS NULL
      AND released_at IS NULL
    RETURNING true
$function$;

CREATE FUNCTION jobs.release_backup_gc_fence(token uuid, exported_snapshot text, copy_verified boolean)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    UPDATE jobs.backup_gc_fences
    SET released_at = statement_timestamp(), verified = copy_verified
    WHERE fence_id = token
      AND snapshot_id = exported_snapshot
      AND released_at IS NULL
      AND (NOT copy_verified OR expires_at > statement_timestamp())
    RETURNING true
$function$;

CREATE FUNCTION jobs.physical_blob_gc_permitted()
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT NOT EXISTS (
        SELECT 1 FROM jobs.backup_gc_fences
        WHERE released_at IS NULL AND expires_at > statement_timestamp()
    )
$function$;

CREATE FUNCTION jobs.rotate_restored_timeline(
    requested_backup_id uuid,
    expected_installation_id uuid,
    expected_timeline_id uuid,
    expected_change_sequence bigint
)
RETURNS TABLE (installation_id uuid, timeline_id uuid, change_sequence bigint)
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
DECLARE
    next_timeline uuid;
BEGIN
    SELECT state.timeline_id
    INTO next_timeline
    FROM jobs.server_state AS state
    JOIN jobs.restore_events AS event
      ON event.installation_id = state.installation_id
     AND event.restored_timeline_id = state.timeline_id
     AND event.restored_change_sequence = state.change_sequence
    WHERE state.singleton
      AND event.backup_id = requested_backup_id
      AND event.installation_id = expected_installation_id
      AND event.previous_timeline_id = expected_timeline_id
      AND event.restored_change_sequence = expected_change_sequence;
    IF FOUND THEN
        RETURN QUERY
        SELECT state.installation_id, state.timeline_id, state.change_sequence
        FROM jobs.server_state AS state WHERE state.singleton;
        RETURN;
    END IF;
    next_timeline := gen_random_uuid();
    UPDATE jobs.server_state AS state
    SET timeline_id = next_timeline,
        timeline_started_at = statement_timestamp()
    WHERE state.singleton
      AND state.installation_id = expected_installation_id
      AND state.timeline_id = expected_timeline_id
      AND state.change_sequence = expected_change_sequence;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'restored state does not match the verified backup';
    END IF;
    INSERT INTO jobs.restore_events (
        restore_id, backup_id, installation_id, previous_timeline_id,
        restored_timeline_id, restored_change_sequence
    ) VALUES (
        gen_random_uuid(), requested_backup_id, expected_installation_id,
        expected_timeline_id, next_timeline, expected_change_sequence
    );
    RETURN QUERY
    SELECT state.installation_id, state.timeline_id, state.change_sequence
    FROM jobs.server_state AS state WHERE state.singleton;
END
$function$;

REVOKE ALL ON attachment.ready_blob_manifest, jobs.backup_gc_fences, jobs.restore_events FROM PUBLIC, punaro_app;
GRANT SELECT ON attachment.ready_blob_manifest TO punaro_app;

REVOKE ALL ON FUNCTION jobs.acquire_backup_gc_fence(interval) FROM PUBLIC;
REVOKE ALL ON FUNCTION jobs.bind_backup_snapshot(uuid, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION jobs.renew_backup_gc_fence(uuid, text, interval) FROM PUBLIC;
REVOKE ALL ON FUNCTION jobs.cancel_unbound_backup_gc_fence(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION jobs.release_backup_gc_fence(uuid, text, boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION jobs.physical_blob_gc_permitted() FROM PUBLIC;
REVOKE ALL ON FUNCTION jobs.rotate_restored_timeline(uuid, uuid, uuid, bigint) FROM PUBLIC, punaro_app;

GRANT EXECUTE ON FUNCTION jobs.physical_blob_gc_permitted() TO punaro_app;
