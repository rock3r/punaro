ALTER TABLE attachment.ready_blob_manifest
    DROP CONSTRAINT ready_blob_manifest_sha256_key;

CREATE TABLE attachment.uploads (
    artifact_id uuid CONSTRAINT uploads_pkey PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id uuid NOT NULL CONSTRAINT uploads_project_id_fkey REFERENCES relay.projects(id),
    principal_id uuid NOT NULL CONSTRAINT uploads_principal_id_fkey REFERENCES auth.principals(id),
    timeline_id uuid NOT NULL,
    idempotency_key uuid NOT NULL CONSTRAINT uploads_idempotency_key_key UNIQUE,
    request_sha256 char(64) NOT NULL CONSTRAINT uploads_request_sha256_check CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    size_bytes bigint NOT NULL CONSTRAINT uploads_size_bytes_check CHECK (size_bytes BETWEEN 1 AND 17179869184),
    sha256 char(64) NOT NULL CONSTRAINT uploads_sha256_check CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    display_name text NOT NULL CONSTRAINT uploads_display_name_check CHECK (
        char_length(display_name) BETWEEN 1 AND 255
        AND octet_length(display_name) <= 1020
        AND display_name !~ '[[:cntrl:]]'
    ),
    media_type text NOT NULL CONSTRAINT uploads_media_type_check CHECK (
        char_length(media_type) BETWEEN 1 AND 127
        AND octet_length(media_type) <= 508
        AND media_type ~ '^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$'
    ),
    state text NOT NULL DEFAULT 'reserved' CONSTRAINT uploads_state_check CHECK (state IN ('reserved','reaping','ready','corrupt','expired')),
    attempt_generation bigint NOT NULL DEFAULT 0 CONSTRAINT uploads_attempt_generation_check CHECK (attempt_generation >= 0),
    claim_token uuid,
    claim_until timestamptz,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    expires_at timestamptz NOT NULL,
    ready_at timestamptz,
    CONSTRAINT uploads_expiry_check CHECK (expires_at > created_at),
    CONSTRAINT uploads_claim_check CHECK (
        (claim_token IS NULL AND claim_until IS NULL)
        OR (state = 'reserved' AND claim_token IS NOT NULL AND claim_until IS NOT NULL AND claim_until <= expires_at)
        OR (state = 'reaping' AND claim_token IS NOT NULL AND claim_until IS NULL)
    ),
    CONSTRAINT uploads_ready_check CHECK (
        (state IN ('reserved','reaping') AND ready_at IS NULL)
        OR (state IN ('ready','corrupt') AND ready_at IS NOT NULL)
        OR (state = 'expired' AND ready_at IS NULL AND claim_token IS NULL AND claim_until IS NULL)
    )
);

CREATE INDEX uploads_project_state
ON attachment.uploads (project_id, state, artifact_id);

CREATE INDEX uploads_reconcile_order
ON attachment.uploads (state, expires_at, artifact_id);

CREATE TABLE attachment.ready_artifacts (
    artifact_id uuid CONSTRAINT ready_artifacts_pkey PRIMARY KEY
        CONSTRAINT ready_artifacts_artifact_id_fkey REFERENCES attachment.uploads(artifact_id),
    storage_path text NOT NULL CONSTRAINT ready_artifacts_storage_path_key UNIQUE
        CONSTRAINT ready_artifacts_storage_path_fkey REFERENCES attachment.ready_blob_manifest(storage_path),
    published_at timestamptz NOT NULL DEFAULT statement_timestamp()
);

CREATE TABLE attachment.global_quota (
    singleton boolean CONSTRAINT global_quota_pkey PRIMARY KEY DEFAULT true CONSTRAINT global_quota_singleton_check CHECK (singleton),
    max_artifact_bytes bigint NOT NULL DEFAULT 67108864 CONSTRAINT global_quota_max_artifact_bytes_check CHECK (max_artifact_bytes BETWEEN 1 AND 17179869184),
    max_total_bytes bigint NOT NULL DEFAULT 17179869184 CONSTRAINT global_quota_max_total_bytes_check CHECK (max_total_bytes BETWEEN max_artifact_bytes AND 1099511627776),
    max_active_uploads integer NOT NULL DEFAULT 1024 CONSTRAINT global_quota_max_active_uploads_check CHECK (max_active_uploads BETWEEN 1 AND 100000),
    default_project_bytes bigint NOT NULL DEFAULT 4294967296 CONSTRAINT global_quota_default_project_bytes_check CHECK (default_project_bytes BETWEEN max_artifact_bytes AND max_total_bytes),
    default_project_uploads integer NOT NULL DEFAULT 256 CONSTRAINT global_quota_default_project_uploads_check CHECK (default_project_uploads BETWEEN 1 AND max_active_uploads),
    default_principal_bytes bigint NOT NULL DEFAULT 2147483648 CONSTRAINT global_quota_default_principal_bytes_check CHECK (default_principal_bytes BETWEEN max_artifact_bytes AND max_total_bytes),
    default_principal_uploads integer NOT NULL DEFAULT 64 CONSTRAINT global_quota_default_principal_uploads_check CHECK (default_principal_uploads BETWEEN 1 AND max_active_uploads),
    reserved_bytes bigint NOT NULL DEFAULT 0 CONSTRAINT global_quota_reserved_bytes_check CHECK (reserved_bytes >= 0),
    used_bytes bigint NOT NULL DEFAULT 0 CONSTRAINT global_quota_used_bytes_check CHECK (used_bytes >= 0),
    reserved_uploads integer NOT NULL DEFAULT 0 CONSTRAINT global_quota_reserved_uploads_check CHECK (reserved_uploads >= 0),
    ready_artifacts integer NOT NULL DEFAULT 0 CONSTRAINT global_quota_ready_artifacts_check CHECK (ready_artifacts >= 0),
    CONSTRAINT global_quota_capacity_check CHECK (reserved_bytes + used_bytes <= max_total_bytes AND reserved_uploads <= max_active_uploads)
);

INSERT INTO attachment.global_quota (singleton) VALUES (true);

CREATE TABLE attachment.project_quotas (
    project_id uuid CONSTRAINT project_quotas_pkey PRIMARY KEY CONSTRAINT project_quotas_project_id_fkey REFERENCES relay.projects(id),
    max_bytes bigint NOT NULL CONSTRAINT project_quotas_max_bytes_check CHECK (max_bytes BETWEEN 1 AND 1099511627776),
    max_active_uploads integer NOT NULL CONSTRAINT project_quotas_max_active_uploads_check CHECK (max_active_uploads BETWEEN 1 AND 100000),
    reserved_bytes bigint NOT NULL DEFAULT 0 CONSTRAINT project_quotas_reserved_bytes_check CHECK (reserved_bytes >= 0),
    used_bytes bigint NOT NULL DEFAULT 0 CONSTRAINT project_quotas_used_bytes_check CHECK (used_bytes >= 0),
    reserved_uploads integer NOT NULL DEFAULT 0 CONSTRAINT project_quotas_reserved_uploads_check CHECK (reserved_uploads >= 0),
    ready_artifacts integer NOT NULL DEFAULT 0 CONSTRAINT project_quotas_ready_artifacts_check CHECK (ready_artifacts >= 0),
    CONSTRAINT project_quotas_capacity_check CHECK (reserved_bytes + used_bytes <= max_bytes AND reserved_uploads <= max_active_uploads)
);

CREATE TABLE attachment.principal_quotas (
    principal_id uuid CONSTRAINT principal_quotas_pkey PRIMARY KEY CONSTRAINT principal_quotas_principal_id_fkey REFERENCES auth.principals(id),
    max_bytes bigint NOT NULL CONSTRAINT principal_quotas_max_bytes_check CHECK (max_bytes BETWEEN 1 AND 1099511627776),
    max_active_uploads integer NOT NULL CONSTRAINT principal_quotas_max_active_uploads_check CHECK (max_active_uploads BETWEEN 1 AND 100000),
    reserved_bytes bigint NOT NULL DEFAULT 0 CONSTRAINT principal_quotas_reserved_bytes_check CHECK (reserved_bytes >= 0),
    used_bytes bigint NOT NULL DEFAULT 0 CONSTRAINT principal_quotas_used_bytes_check CHECK (used_bytes >= 0),
    reserved_uploads integer NOT NULL DEFAULT 0 CONSTRAINT principal_quotas_reserved_uploads_check CHECK (reserved_uploads >= 0),
    ready_artifacts integer NOT NULL DEFAULT 0 CONSTRAINT principal_quotas_ready_artifacts_check CHECK (ready_artifacts >= 0),
    CONSTRAINT principal_quotas_capacity_check CHECK (reserved_bytes + used_bytes <= max_bytes AND reserved_uploads <= max_active_uploads)
);

CREATE FUNCTION attachment.reserve_upload(
    requested_principal uuid,
    requested_project uuid,
    request_key uuid,
    request_hash bytea,
    requested_size bigint,
    requested_sha256 text,
    requested_display_name text,
    requested_media_type text,
    requested_lifetime interval
)
RETURNS TABLE (
    artifact_id uuid,
    project_id uuid,
    principal_id uuid,
    timeline_id uuid,
    size_bytes bigint,
    sha256 text,
    display_name text,
    media_type text,
    state text,
    attempt_generation bigint,
    expires_at timestamptz,
    ready_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    canonical_project uuid;
    current_timeline uuid;
    existing_principal uuid;
    existing_operation text;
    existing_hash bytea;
    existing_status text;
    existing_resource uuid;
    inserted integer;
    grant_id uuid;
    created_artifact uuid;
    project_limit_bytes bigint;
    project_limit_uploads integer;
    principal_limit_bytes bigint;
    principal_limit_uploads integer;
BEGIN
    PERFORM jobs.assert_application_mutation();
    IF octet_length(request_hash) <> 32
       OR requested_size < 1
       OR requested_sha256 !~ '^[0-9a-f]{64}$'
       OR requested_lifetime < interval '5 minutes'
       OR requested_lifetime > interval '1 hour' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid attachment reservation';
    END IF;

    SELECT active.id INTO canonical_project
    FROM relay.projects AS requested
    LEFT JOIN relay.project_lookup_aliases AS alias ON alias.alias_project_id = requested.id
    JOIN relay.projects AS active ON active.id = COALESCE(alias.canonical_project_id, requested.id)
    WHERE requested.id = requested_project AND active.merged_into IS NULL
      AND ((requested.merged_into IS NULL AND alias.alias_project_id IS NULL)
           OR requested.merged_into = alias.canonical_project_id)
    FOR UPDATE OF active;
    IF canonical_project IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'attachment reservation is not authorized';
    END IF;

    SELECT capability_grant.id INTO grant_id
    FROM auth.principals AS principal
    JOIN auth.capability_grants AS capability_grant ON capability_grant.principal_id = principal.id
    WHERE principal.id = requested_principal AND principal.disabled_at IS NULL
      AND capability_grant.revoked_at IS NULL AND capability_grant.capability = 'attachment.upload'
      AND ((capability_grant.scope = 'project' AND capability_grant.project_id = canonical_project)
           OR (capability_grant.scope = 'all_projects' AND capability_grant.project_id IS NULL))
    ORDER BY capability_grant.id LIMIT 1
    FOR SHARE OF principal, capability_grant;
    IF grant_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'attachment reservation is not authorized';
    END IF;

    INSERT INTO relay.idempotency_records (key, principal_id, operation, request_hash, status)
    VALUES (request_key, requested_principal, 'attachment.reserve', request_hash, 'pending')
    ON CONFLICT (key) DO NOTHING;
    GET DIAGNOSTICS inserted = ROW_COUNT;

    SELECT record.principal_id, record.operation, record.request_hash, record.status, record.resource_id
    INTO existing_principal, existing_operation, existing_hash, existing_status, existing_resource
    FROM relay.idempotency_records AS record
    WHERE record.key = request_key
    FOR UPDATE;

    IF existing_principal IS DISTINCT FROM requested_principal
       OR existing_operation IS DISTINCT FROM 'attachment.reserve'
       OR existing_hash IS DISTINCT FROM request_hash THEN
        RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'attachment reservation conflicts with prior request';
    END IF;

    IF inserted = 0 THEN
        IF existing_status <> 'succeeded' OR existing_resource IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = '55P03', MESSAGE = 'attachment reservation is incomplete';
        END IF;
        RETURN QUERY
        SELECT upload.artifact_id, upload.project_id, upload.principal_id, upload.timeline_id,
               upload.size_bytes, upload.sha256::text, upload.display_name, upload.media_type,
               upload.state, upload.attempt_generation, upload.expires_at, upload.ready_at
        FROM attachment.uploads AS upload
        WHERE upload.artifact_id = existing_resource AND upload.project_id = canonical_project
          AND upload.principal_id = requested_principal;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'attachment reservation result is stale';
        END IF;
        RETURN;
    END IF;

    SELECT state.timeline_id INTO current_timeline
    FROM jobs.server_state AS state WHERE state.singleton FOR SHARE;

    SELECT quota.default_project_bytes, quota.default_project_uploads,
           quota.default_principal_bytes, quota.default_principal_uploads
    INTO project_limit_bytes, project_limit_uploads, principal_limit_bytes, principal_limit_uploads
    FROM attachment.global_quota AS quota WHERE quota.singleton FOR UPDATE;
    IF requested_size > (SELECT quota.max_artifact_bytes FROM attachment.global_quota AS quota WHERE quota.singleton) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'attachment exceeds configured artifact limit';
    END IF;

    INSERT INTO attachment.project_quotas (project_id, max_bytes, max_active_uploads)
    VALUES (canonical_project, project_limit_bytes, project_limit_uploads)
    ON CONFLICT ON CONSTRAINT project_quotas_pkey DO NOTHING;
    PERFORM 1 FROM attachment.project_quotas AS project_quota
    WHERE project_quota.project_id = canonical_project FOR UPDATE;

    INSERT INTO attachment.principal_quotas (principal_id, max_bytes, max_active_uploads)
    VALUES (requested_principal, principal_limit_bytes, principal_limit_uploads)
    ON CONFLICT ON CONSTRAINT principal_quotas_pkey DO NOTHING;
    PERFORM 1 FROM attachment.principal_quotas AS principal_quota
    WHERE principal_quota.principal_id = requested_principal FOR UPDATE;

    UPDATE attachment.global_quota AS global_quota
    SET reserved_bytes = global_quota.reserved_bytes + requested_size,
        reserved_uploads = global_quota.reserved_uploads + 1
    WHERE global_quota.singleton
      AND global_quota.reserved_bytes + global_quota.used_bytes + requested_size <= global_quota.max_total_bytes
      AND global_quota.reserved_uploads + 1 <= global_quota.max_active_uploads;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '54000', MESSAGE = 'attachment global quota is exhausted';
    END IF;
    UPDATE attachment.project_quotas AS project_quota
    SET reserved_bytes = project_quota.reserved_bytes + requested_size,
        reserved_uploads = project_quota.reserved_uploads + 1
    WHERE project_quota.project_id = canonical_project
      AND project_quota.reserved_bytes + project_quota.used_bytes + requested_size <= project_quota.max_bytes
      AND project_quota.reserved_uploads + 1 <= project_quota.max_active_uploads;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '54000', MESSAGE = 'attachment project quota is exhausted';
    END IF;
    UPDATE attachment.principal_quotas AS principal_quota
    SET reserved_bytes = principal_quota.reserved_bytes + requested_size,
        reserved_uploads = principal_quota.reserved_uploads + 1
    WHERE principal_quota.principal_id = requested_principal
      AND principal_quota.reserved_bytes + principal_quota.used_bytes + requested_size <= principal_quota.max_bytes
      AND principal_quota.reserved_uploads + 1 <= principal_quota.max_active_uploads;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '54000', MESSAGE = 'attachment principal quota is exhausted';
    END IF;

    INSERT INTO attachment.uploads (
        project_id, principal_id, timeline_id, idempotency_key, request_sha256,
        size_bytes, sha256, display_name, media_type, expires_at
    ) VALUES (
        canonical_project, requested_principal, current_timeline, request_key, encode(request_hash, 'hex'),
        requested_size, requested_sha256, requested_display_name, requested_media_type,
        statement_timestamp() + requested_lifetime
    ) RETURNING uploads.artifact_id INTO created_artifact;

    UPDATE relay.idempotency_records
    SET status = 'succeeded', resource_id = created_artifact,
        result = jsonb_build_object('version', 1), completed_at = statement_timestamp()
    WHERE key = request_key AND status = 'pending';
    UPDATE relay.projects SET content_generation = content_generation + 1 WHERE id = canonical_project;
    PERFORM jobs.advance_change_sequence();

    RETURN QUERY
    SELECT upload.artifact_id, upload.project_id, upload.principal_id, upload.timeline_id,
           upload.size_bytes, upload.sha256::text, upload.display_name, upload.media_type,
           upload.state, upload.attempt_generation, upload.expires_at, upload.ready_at
    FROM attachment.uploads AS upload WHERE upload.artifact_id = created_artifact;
END
$function$;

CREATE FUNCTION attachment.claim_upload(
    requested_principal uuid,
    requested_artifact uuid,
    requested_lifetime interval
)
RETURNS TABLE (
    artifact_id uuid,
    project_id uuid,
    principal_id uuid,
    timeline_id uuid,
    size_bytes bigint,
    sha256 text,
    state text,
    attempt_generation bigint,
    claim_token uuid,
    claim_until timestamptz,
    expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    upload attachment.uploads%ROWTYPE;
    current_timeline uuid;
    grant_id uuid;
BEGIN
    PERFORM jobs.assert_application_mutation();
    IF requested_lifetime < interval '30 seconds' OR requested_lifetime > interval '10 minutes' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid attachment upload claim';
    END IF;
    SELECT candidate.* INTO upload
    FROM attachment.uploads AS candidate
    WHERE candidate.artifact_id = requested_artifact FOR UPDATE;
    IF NOT FOUND OR upload.principal_id <> requested_principal OR upload.state <> 'reserved' THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'attachment upload claim is not authorized';
    END IF;
    SELECT server.timeline_id INTO current_timeline
    FROM jobs.server_state AS server WHERE server.singleton FOR SHARE;
    IF upload.timeline_id <> current_timeline OR upload.expires_at <= statement_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'attachment reservation is stale';
    END IF;
    PERFORM 1 FROM relay.projects WHERE id = upload.project_id AND merged_into IS NULL FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'attachment project is unavailable';
    END IF;
    SELECT capability_grant.id INTO grant_id
    FROM auth.principals AS principal
    JOIN auth.capability_grants AS capability_grant ON capability_grant.principal_id = principal.id
    WHERE principal.id = requested_principal AND principal.disabled_at IS NULL
      AND capability_grant.revoked_at IS NULL AND capability_grant.capability = 'attachment.upload'
      AND ((capability_grant.scope = 'project' AND capability_grant.project_id = upload.project_id)
           OR (capability_grant.scope = 'all_projects' AND capability_grant.project_id IS NULL))
    ORDER BY capability_grant.id LIMIT 1 FOR SHARE OF principal, capability_grant;
    IF grant_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'attachment upload claim is not authorized';
    END IF;
    IF upload.claim_until IS NOT NULL AND upload.claim_until > statement_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE = '55P03', MESSAGE = 'attachment upload is already claimed';
    END IF;
    UPDATE attachment.uploads AS claimed_upload
    SET attempt_generation = claimed_upload.attempt_generation + 1,
        claim_token = gen_random_uuid(),
        claim_until = LEAST(statement_timestamp() + requested_lifetime, claimed_upload.expires_at)
    WHERE claimed_upload.artifact_id = requested_artifact
    RETURNING claimed_upload.artifact_id, claimed_upload.project_id, claimed_upload.principal_id, claimed_upload.timeline_id,
              claimed_upload.size_bytes, claimed_upload.sha256::text, claimed_upload.state, claimed_upload.attempt_generation,
              claimed_upload.claim_token, claimed_upload.claim_until, claimed_upload.expires_at
    INTO artifact_id, project_id, principal_id, timeline_id, size_bytes, sha256, state,
         attempt_generation, claim_token, claim_until, expires_at;
    RETURN NEXT;
END
$function$;

CREATE FUNCTION attachment.publish_upload(
    requested_principal uuid,
    requested_artifact uuid,
    requested_generation bigint,
    requested_claim_token uuid,
    requested_storage_path text,
    requested_size bigint,
    requested_sha256 text
)
RETURNS TABLE (artifact_id uuid, project_id uuid, storage_path text, size_bytes bigint, sha256 text, state text, ready_at timestamptz)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    upload attachment.uploads%ROWTYPE;
    current_timeline uuid;
    grant_id uuid;
    existing_path text;
    existing_size bigint;
    existing_sha text;
BEGIN
    PERFORM jobs.assert_application_mutation();
    SELECT candidate.* INTO upload
    FROM attachment.uploads AS candidate
    WHERE candidate.artifact_id = requested_artifact FOR UPDATE;
    IF NOT FOUND OR upload.principal_id <> requested_principal THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'attachment publication is not authorized';
    END IF;
    PERFORM 1 FROM relay.projects WHERE id = upload.project_id AND merged_into IS NULL FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'attachment project is unavailable';
    END IF;
    SELECT capability_grant.id INTO grant_id
    FROM auth.principals AS principal
    JOIN auth.capability_grants AS capability_grant ON capability_grant.principal_id = principal.id
    WHERE principal.id = requested_principal AND principal.disabled_at IS NULL
      AND capability_grant.revoked_at IS NULL AND capability_grant.capability = 'attachment.upload'
      AND ((capability_grant.scope = 'project' AND capability_grant.project_id = upload.project_id)
           OR (capability_grant.scope = 'all_projects' AND capability_grant.project_id IS NULL))
    ORDER BY capability_grant.id LIMIT 1 FOR SHARE OF principal, capability_grant;
    IF grant_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'attachment publication is not authorized';
    END IF;
    IF upload.state = 'ready' THEN
        SELECT ready.storage_path, manifest.size_bytes, manifest.sha256::text
        INTO existing_path, existing_size, existing_sha
        FROM attachment.ready_artifacts AS ready
        JOIN attachment.ready_blob_manifest AS manifest ON manifest.storage_path = ready.storage_path
        WHERE ready.artifact_id = upload.artifact_id;
        IF existing_path = requested_storage_path AND existing_size = requested_size AND existing_sha = requested_sha256 THEN
            RETURN QUERY SELECT upload.artifact_id, upload.project_id, existing_path, existing_size, existing_sha, upload.state, upload.ready_at;
            RETURN;
        END IF;
        RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'immutable attachment publication conflicts with prior result';
    END IF;
    SELECT server.timeline_id INTO current_timeline
    FROM jobs.server_state AS server WHERE server.singleton FOR SHARE;
    IF upload.state <> 'reserved' OR upload.timeline_id <> current_timeline
       OR upload.expires_at <= statement_timestamp()
       OR upload.attempt_generation <> requested_generation
       OR upload.claim_token IS DISTINCT FROM requested_claim_token
       OR upload.claim_until <= statement_timestamp()
       OR upload.size_bytes <> requested_size OR upload.sha256::text <> requested_sha256
       OR requested_storage_path <> ('ready/' || requested_artifact::text || '.blob') THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'attachment publication claim is stale';
    END IF;
    PERFORM 1 FROM attachment.global_quota AS global_quota WHERE global_quota.singleton FOR UPDATE;
    PERFORM 1 FROM attachment.project_quotas AS project_quota
    WHERE project_quota.project_id = upload.project_id FOR UPDATE;
    PERFORM 1 FROM attachment.principal_quotas AS principal_quota
    WHERE principal_quota.principal_id = upload.principal_id FOR UPDATE;

    INSERT INTO attachment.ready_blob_manifest (storage_path, size_bytes, sha256)
    VALUES (requested_storage_path, requested_size, requested_sha256);
    INSERT INTO attachment.ready_artifacts (artifact_id, storage_path)
    VALUES (requested_artifact, requested_storage_path);
    UPDATE attachment.uploads
    SET state = 'ready', claim_token = NULL, claim_until = NULL, ready_at = statement_timestamp()
    WHERE uploads.artifact_id = requested_artifact;
    UPDATE attachment.global_quota AS global_quota
    SET reserved_bytes = global_quota.reserved_bytes - requested_size,
        used_bytes = global_quota.used_bytes + requested_size,
        reserved_uploads = global_quota.reserved_uploads - 1,
        ready_artifacts = global_quota.ready_artifacts + 1
    WHERE global_quota.singleton AND global_quota.reserved_bytes >= requested_size
      AND global_quota.reserved_uploads >= 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'attachment global quota is inconsistent';
    END IF;
    UPDATE attachment.project_quotas AS project_quota
    SET reserved_bytes = project_quota.reserved_bytes - requested_size,
        used_bytes = project_quota.used_bytes + requested_size,
        reserved_uploads = project_quota.reserved_uploads - 1,
        ready_artifacts = project_quota.ready_artifacts + 1
    WHERE project_quota.project_id = upload.project_id
      AND project_quota.reserved_bytes >= requested_size AND project_quota.reserved_uploads >= 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'attachment project quota is inconsistent';
    END IF;
    UPDATE attachment.principal_quotas AS principal_quota
    SET reserved_bytes = principal_quota.reserved_bytes - requested_size,
        used_bytes = principal_quota.used_bytes + requested_size,
        reserved_uploads = principal_quota.reserved_uploads - 1,
        ready_artifacts = principal_quota.ready_artifacts + 1
    WHERE principal_quota.principal_id = upload.principal_id
      AND principal_quota.reserved_bytes >= requested_size AND principal_quota.reserved_uploads >= 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'attachment principal quota is inconsistent';
    END IF;
    UPDATE relay.projects SET content_generation = content_generation + 1 WHERE id = upload.project_id;
    PERFORM jobs.advance_change_sequence();
    RETURN QUERY
    SELECT current_upload.artifact_id, current_upload.project_id, ready.storage_path,
           manifest.size_bytes, manifest.sha256::text, current_upload.state, current_upload.ready_at
    FROM attachment.uploads AS current_upload
    JOIN attachment.ready_artifacts AS ready ON ready.artifact_id = current_upload.artifact_id
    JOIN attachment.ready_blob_manifest AS manifest ON manifest.storage_path = ready.storage_path
    WHERE current_upload.artifact_id = requested_artifact;
END
$function$;

CREATE FUNCTION attachment.begin_reap_upload(requested_artifact uuid)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    upload attachment.uploads%ROWTYPE;
    current_timeline uuid;
    cleanup_token uuid;
BEGIN
    PERFORM jobs.assert_application_mutation();
    SELECT * INTO upload FROM attachment.uploads WHERE uploads.artifact_id = requested_artifact FOR UPDATE;
    IF NOT FOUND OR upload.state <> 'reserved' THEN
        RETURN NULL;
    END IF;
    SELECT timeline_id INTO current_timeline FROM jobs.server_state WHERE singleton FOR SHARE;
    IF upload.expires_at > statement_timestamp() AND upload.timeline_id = current_timeline THEN
        RETURN NULL;
    END IF;
    cleanup_token := gen_random_uuid();
    UPDATE attachment.uploads
    SET state = 'reaping', claim_token = cleanup_token, claim_until = NULL
    WHERE uploads.artifact_id = requested_artifact;
    RETURN cleanup_token;
END
$function$;

CREATE FUNCTION attachment.release_expired_upload(requested_artifact uuid, requested_cleanup_token uuid)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    upload attachment.uploads%ROWTYPE;
BEGIN
    PERFORM jobs.assert_application_mutation();
    SELECT * INTO upload FROM attachment.uploads WHERE uploads.artifact_id = requested_artifact FOR UPDATE;
    IF NOT FOUND OR upload.state = 'expired' THEN
        RETURN false;
    END IF;
    IF upload.state <> 'reaping' OR upload.claim_token IS DISTINCT FROM requested_cleanup_token THEN
        RETURN false;
    END IF;
    PERFORM 1 FROM attachment.global_quota WHERE singleton FOR UPDATE;
    PERFORM 1 FROM attachment.project_quotas WHERE project_id = upload.project_id FOR UPDATE;
    PERFORM 1 FROM attachment.principal_quotas WHERE principal_id = upload.principal_id FOR UPDATE;
    UPDATE attachment.global_quota SET reserved_bytes = reserved_bytes - upload.size_bytes, reserved_uploads = reserved_uploads - 1
    WHERE singleton AND reserved_bytes >= upload.size_bytes AND reserved_uploads >= 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'attachment global quota is inconsistent';
    END IF;
    UPDATE attachment.project_quotas SET reserved_bytes = reserved_bytes - upload.size_bytes, reserved_uploads = reserved_uploads - 1
    WHERE project_id = upload.project_id AND reserved_bytes >= upload.size_bytes AND reserved_uploads >= 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'attachment project quota is inconsistent';
    END IF;
    UPDATE attachment.principal_quotas SET reserved_bytes = reserved_bytes - upload.size_bytes, reserved_uploads = reserved_uploads - 1
    WHERE principal_id = upload.principal_id AND reserved_bytes >= upload.size_bytes AND reserved_uploads >= 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'attachment principal quota is inconsistent';
    END IF;
    UPDATE attachment.uploads SET state = 'expired', claim_token = NULL, claim_until = NULL WHERE uploads.artifact_id = requested_artifact;
    UPDATE relay.projects SET content_generation = content_generation + 1 WHERE id = upload.project_id AND merged_into IS NULL;
    PERFORM jobs.advance_change_sequence();
    RETURN true;
END
$function$;

CREATE FUNCTION attachment.mark_corrupt(requested_artifact uuid)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    affected_project uuid;
    affected_path text;
BEGIN
    PERFORM jobs.assert_application_mutation();
    UPDATE attachment.uploads SET state = 'corrupt'
    WHERE artifact_id = requested_artifact AND state = 'ready'
    RETURNING project_id INTO affected_project;
    IF FOUND THEN
        DELETE FROM attachment.ready_artifacts
        WHERE artifact_id = requested_artifact
        RETURNING storage_path INTO affected_path;
        IF affected_path IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'attachment READY projection is inconsistent';
        END IF;
        DELETE FROM attachment.ready_blob_manifest WHERE storage_path = affected_path;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'attachment READY manifest is inconsistent';
        END IF;
        UPDATE relay.projects SET content_generation = content_generation + 1
        WHERE id = affected_project AND merged_into IS NULL;
        PERFORM jobs.advance_change_sequence();
        RETURN true;
    END IF;
    RETURN false;
END
$function$;

CREATE FUNCTION attachment.reconcile_candidates(
    requested_after_state text,
    requested_after_expires timestamptz,
    requested_after_artifact uuid,
    requested_limit integer
)
RETURNS TABLE (
    artifact_id uuid,
    project_id uuid,
    principal_id uuid,
    timeline_id uuid,
    size_bytes bigint,
    sha256 text,
    state text,
    attempt_generation bigint,
    cleanup_token uuid,
    claim_until timestamptz,
    expires_at timestamptz,
    storage_path text,
    current_timeline boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog
AS $function$
BEGIN
    IF requested_limit < 1 OR requested_limit > 100
       OR ((requested_after_state IS NULL) <> (requested_after_expires IS NULL))
       OR ((requested_after_state IS NULL) <> (requested_after_artifact IS NULL))
       OR (requested_after_state IS NOT NULL AND requested_after_state NOT IN ('corrupt','ready','reaping','reserved')) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid attachment reconciliation batch';
    END IF;
    RETURN QUERY
    SELECT upload.artifact_id, upload.project_id, upload.principal_id, upload.timeline_id,
           upload.size_bytes, upload.sha256::text, upload.state, upload.attempt_generation,
           CASE WHEN upload.state = 'reaping' THEN upload.claim_token ELSE NULL END,
           upload.claim_until, upload.expires_at, ready.storage_path,
           upload.timeline_id = server.timeline_id
    FROM attachment.uploads AS upload
    CROSS JOIN jobs.server_state AS server
    LEFT JOIN attachment.ready_artifacts AS ready ON ready.artifact_id = upload.artifact_id
    WHERE server.singleton AND upload.state IN ('reserved','reaping','ready','corrupt')
      AND (
          requested_after_state IS NULL
          OR (upload.state, upload.expires_at, upload.artifact_id)
             > (requested_after_state, requested_after_expires, requested_after_artifact)
      )
    ORDER BY upload.state, upload.expires_at, upload.artifact_id
    LIMIT requested_limit;
END
$function$;

CREATE FUNCTION attachment.project_has_records(requested_principal uuid, requested_project uuid)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog
AS $function$
DECLARE
    allowed boolean;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM auth.principals AS principal
        JOIN auth.capability_grants AS capability_grant ON capability_grant.principal_id = principal.id
        WHERE principal.id = requested_principal AND principal.disabled_at IS NULL
          AND capability_grant.revoked_at IS NULL AND capability_grant.capability = 'project.administer'
          AND ((capability_grant.scope = 'project' AND capability_grant.project_id = requested_project)
               OR (capability_grant.scope = 'all_projects' AND capability_grant.project_id IS NULL))
    ) INTO allowed;
    IF NOT allowed THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'attachment project state is not authorized';
    END IF;
    RETURN EXISTS (
        SELECT 1 FROM attachment.uploads
        WHERE project_id = requested_project AND state IN ('reserved','reaping','ready','corrupt')
    );
END
$function$;

REVOKE ALL ON attachment.uploads, attachment.ready_artifacts, attachment.global_quota,
    attachment.project_quotas, attachment.principal_quotas FROM PUBLIC, punaro_app;

REVOKE ALL ON FUNCTION attachment.reserve_upload(uuid,uuid,uuid,bytea,bigint,text,text,text,interval) FROM PUBLIC;
REVOKE ALL ON FUNCTION attachment.claim_upload(uuid,uuid,interval) FROM PUBLIC;
REVOKE ALL ON FUNCTION attachment.publish_upload(uuid,uuid,bigint,uuid,text,bigint,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION attachment.begin_reap_upload(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION attachment.release_expired_upload(uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION attachment.mark_corrupt(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION attachment.reconcile_candidates(text,timestamp with time zone,uuid,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION attachment.project_has_records(uuid,uuid) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION attachment.reserve_upload(uuid,uuid,uuid,bytea,bigint,text,text,text,interval) TO punaro_app;
GRANT EXECUTE ON FUNCTION attachment.claim_upload(uuid,uuid,interval) TO punaro_app;
GRANT EXECUTE ON FUNCTION attachment.publish_upload(uuid,uuid,bigint,uuid,text,bigint,text) TO punaro_app;
GRANT EXECUTE ON FUNCTION attachment.begin_reap_upload(uuid) TO punaro_app;
GRANT EXECUTE ON FUNCTION attachment.release_expired_upload(uuid,uuid) TO punaro_app;
GRANT EXECUTE ON FUNCTION attachment.mark_corrupt(uuid) TO punaro_app;
GRANT EXECUTE ON FUNCTION attachment.reconcile_candidates(text,timestamp with time zone,uuid,integer) TO punaro_app;
GRANT EXECUTE ON FUNCTION attachment.project_has_records(uuid,uuid) TO punaro_app;
