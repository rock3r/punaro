CREATE TABLE attachment.deletions (
    artifact_id uuid CONSTRAINT deletions_pkey PRIMARY KEY,
    project_id uuid NOT NULL,
    owner_principal_id uuid NOT NULL,
    storage_path text NOT NULL CONSTRAINT deletions_storage_path_key UNIQUE,
    size_bytes bigint NOT NULL CONSTRAINT deletions_size_bytes_check CHECK (size_bytes BETWEEN 1 AND 17179869184),
    sha256 char(64) NOT NULL CONSTRAINT deletions_sha256_check CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    state text NOT NULL CONSTRAINT deletions_state_check CHECK (state IN ('tombstoned','gc_claimed','deleted')),
    tombstoned_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    gc_after timestamptz NOT NULL,
    gc_generation bigint NOT NULL DEFAULT 0 CONSTRAINT deletions_gc_generation_check CHECK (gc_generation >= 0),
    gc_token uuid,
    gc_lease_until timestamptz,
    deleted_at timestamptz,
    CONSTRAINT deletions_storage_path_check CHECK (storage_path = 'ready/' || artifact_id::text || '.blob'),
    CONSTRAINT deletions_gc_after_check CHECK (gc_after >= tombstoned_at),
    CONSTRAINT deletions_lifecycle_check CHECK (
        (state = 'tombstoned' AND gc_token IS NULL AND gc_lease_until IS NULL AND deleted_at IS NULL)
        OR (state = 'gc_claimed' AND gc_token IS NOT NULL AND gc_lease_until IS NOT NULL AND deleted_at IS NULL)
        OR (state = 'deleted' AND gc_token IS NOT NULL AND gc_lease_until IS NULL AND deleted_at IS NOT NULL)
    )
);

CREATE INDEX deletions_gc_order
ON attachment.deletions (state, gc_after, artifact_id);

INSERT INTO attachment.deletions (
    artifact_id, project_id, owner_principal_id, storage_path,
    size_bytes, sha256, state, gc_after
)
SELECT upload.artifact_id, upload.project_id, upload.principal_id,
       'ready/' || upload.artifact_id::text || '.blob',
       upload.size_bytes, upload.sha256, 'tombstoned',
       statement_timestamp() + interval '24 hours'
FROM attachment.uploads AS upload
WHERE upload.state = 'corrupt' AND upload.ready_at IS NOT NULL;

DELETE FROM attachment.recipient_grant_endpoints AS endpoint
USING attachment.recipient_grants AS recipient, attachment.uploads AS upload
WHERE endpoint.artifact_id = recipient.artifact_id
  AND endpoint.recipient_principal_id = recipient.recipient_principal_id
  AND recipient.artifact_id = upload.artifact_id
  AND upload.state = 'corrupt';
DELETE FROM attachment.recipient_grants AS recipient
USING attachment.uploads AS upload
WHERE recipient.artifact_id = upload.artifact_id
  AND upload.state = 'corrupt';

CREATE FUNCTION attachment.tombstone_artifact(
    requested_principal uuid,
    requested_lookup uuid,
    requested_generation bigint,
    requested_artifact uuid,
    request_key uuid,
    request_hash bytea
)
RETURNS TABLE (
    artifact_id uuid,
    project_id uuid,
    storage_path text,
    size_bytes bigint,
    sha256 text,
    state text,
    gc_generation bigint,
    gc_after timestamptz,
    deleted_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
SET search_path = pg_catalog
AS $function$
DECLARE
    candidate_project uuid;
    canonical_project uuid;
    upload attachment.uploads%ROWTYPE;
    existing_deletion attachment.deletions%ROWTYPE;
    authority_id uuid;
    grant_id uuid;
    existing_principal uuid;
    existing_operation text;
    existing_hash bytea;
    existing_status text;
    existing_resource uuid;
    inserted integer;
    ready_path text;
    changed boolean := false;
BEGIN
    PERFORM jobs.assert_application_mutation();
    IF octet_length(request_hash) <> 32 OR requested_generation < 1 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid attachment deletion';
    END IF;
    SELECT candidate.project_id INTO candidate_project
    FROM attachment.uploads AS candidate
    WHERE candidate.artifact_id = requested_artifact;
    IF NOT FOUND THEN
        SELECT deletion.project_id INTO candidate_project
        FROM attachment.deletions AS deletion
        WHERE deletion.artifact_id = requested_artifact;
    END IF;
    IF candidate_project IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'attachment deletion is not authorized';
    END IF;
    SELECT active.id INTO canonical_project
    FROM relay.projects AS requested
    LEFT JOIN relay.project_lookup_aliases AS alias ON alias.alias_project_id = requested.id
    JOIN relay.projects AS active ON active.id = COALESCE(alias.canonical_project_id, requested.id)
    WHERE requested.id = candidate_project AND active.merged_into IS NULL
      AND ((requested.merged_into IS NULL AND alias.alias_project_id IS NULL)
           OR requested.merged_into = alias.canonical_project_id)
    FOR UPDATE OF active;
    IF canonical_project IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'attachment deletion is not authorized';
    END IF;
    SELECT principal.id INTO authority_id
    FROM auth.principals AS principal
    JOIN auth.device_credentials AS credential ON credential.principal_id = principal.id
    WHERE principal.id = requested_principal AND principal.disabled_at IS NULL
      AND credential.lookup_id = requested_lookup AND credential.revoked_at IS NULL
      AND credential.generation = requested_generation
      AND (credential.expires_at IS NULL OR credential.expires_at > statement_timestamp())
    FOR SHARE OF principal, credential;
    IF authority_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'attachment deletion is not authorized';
    END IF;
    SELECT capability_grant.id INTO grant_id
    FROM auth.capability_grants AS capability_grant
    WHERE capability_grant.principal_id = requested_principal
      AND capability_grant.revoked_at IS NULL
      AND capability_grant.capability = 'attachment.delete'
      AND ((capability_grant.scope = 'project' AND capability_grant.project_id = canonical_project)
           OR (capability_grant.scope = 'all_projects' AND capability_grant.project_id IS NULL))
    ORDER BY capability_grant.id LIMIT 1 FOR SHARE;
    IF grant_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'attachment deletion is not authorized';
    END IF;

    INSERT INTO relay.idempotency_records (key, principal_id, operation, request_hash, status)
    VALUES (request_key, requested_principal, 'attachment.delete', request_hash, 'pending')
    ON CONFLICT (key) DO NOTHING;
    GET DIAGNOSTICS inserted = ROW_COUNT;
    SELECT record.principal_id, record.operation, record.request_hash, record.status, record.resource_id
    INTO existing_principal, existing_operation, existing_hash, existing_status, existing_resource
    FROM relay.idempotency_records AS record
    WHERE record.key = request_key FOR UPDATE;
    IF existing_principal IS DISTINCT FROM requested_principal
       OR existing_operation IS DISTINCT FROM 'attachment.delete'
       OR existing_hash IS DISTINCT FROM request_hash THEN
        RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'attachment deletion conflicts with prior request';
    END IF;
    IF inserted = 0 THEN
        IF existing_status <> 'succeeded' OR existing_resource IS DISTINCT FROM requested_artifact THEN
            RAISE EXCEPTION USING ERRCODE = '55P03', MESSAGE = 'attachment deletion is incomplete';
        END IF;
        RETURN QUERY
        SELECT deletion.artifact_id, deletion.project_id, deletion.storage_path,
               deletion.size_bytes, deletion.sha256::text, deletion.state,
               deletion.gc_generation, deletion.gc_after, deletion.deleted_at
        FROM attachment.deletions AS deletion
        WHERE deletion.artifact_id = requested_artifact;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'attachment deletion result is stale';
        END IF;
        RETURN;
    END IF;

    SELECT candidate.* INTO upload
    FROM attachment.uploads AS candidate
    WHERE candidate.artifact_id = requested_artifact FOR UPDATE;
    SELECT deletion.* INTO existing_deletion
    FROM attachment.deletions AS deletion
    WHERE deletion.artifact_id = requested_artifact FOR UPDATE;
    IF upload.artifact_id IS NULL AND existing_deletion.artifact_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'attachment deletion is not authorized';
    END IF;
    IF upload.artifact_id IS NOT NULL AND upload.project_id <> candidate_project THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'attachment deletion is not authorized';
    END IF;
    IF existing_deletion.artifact_id IS NOT NULL THEN
        IF existing_deletion.project_id <> candidate_project THEN
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'attachment deletion metadata is inconsistent';
        END IF;
    ELSE
        IF upload.state NOT IN ('ready','corrupt') OR upload.ready_at IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'attachment deletion is not authorized';
        END IF;
        IF upload.state = 'ready' THEN
            SELECT ready.storage_path INTO ready_path
            FROM attachment.ready_artifacts AS ready
            WHERE ready.artifact_id = requested_artifact FOR UPDATE;
            IF ready_path IS NULL THEN
                RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'attachment READY projection is inconsistent';
            END IF;
        ELSE
            ready_path := 'ready/' || requested_artifact::text || '.blob';
        END IF;
        INSERT INTO attachment.deletions (
            artifact_id, project_id, owner_principal_id, storage_path,
            size_bytes, sha256, state, gc_after
        ) VALUES (
            requested_artifact, upload.project_id, upload.principal_id, ready_path,
            upload.size_bytes, upload.sha256, 'tombstoned', statement_timestamp() + interval '24 hours'
        );
        changed := true;
    END IF;

    DELETE FROM attachment.recipient_grant_endpoints AS endpoint
    USING attachment.recipient_grants AS recipient
    WHERE endpoint.artifact_id = recipient.artifact_id
      AND endpoint.recipient_principal_id = recipient.recipient_principal_id
      AND recipient.artifact_id = requested_artifact;
    DELETE FROM attachment.recipient_grants WHERE recipient_grants.artifact_id = requested_artifact;
    DELETE FROM attachment.ready_artifacts
    WHERE ready_artifacts.artifact_id = requested_artifact
    RETURNING ready_artifacts.storage_path INTO ready_path;
    IF ready_path IS NOT NULL THEN
        DELETE FROM attachment.ready_blob_manifest WHERE ready_blob_manifest.storage_path = ready_path;
    END IF;
    UPDATE attachment.uploads
    SET state = 'corrupt', claim_token = NULL, claim_until = NULL
    WHERE uploads.artifact_id = requested_artifact AND uploads.state = 'ready';

    UPDATE relay.idempotency_records
    SET status = 'succeeded', resource_id = requested_artifact,
        result = jsonb_build_object('version', 1), completed_at = statement_timestamp()
    WHERE key = request_key AND status = 'pending';
    IF changed THEN
        UPDATE relay.projects SET content_generation = content_generation + 1 WHERE id = canonical_project;
        PERFORM jobs.advance_change_sequence();
    END IF;
    RETURN QUERY
    SELECT deletion.artifact_id, deletion.project_id, deletion.storage_path,
           deletion.size_bytes, deletion.sha256::text, deletion.state,
           deletion.gc_generation, deletion.gc_after, deletion.deleted_at
    FROM attachment.deletions AS deletion
    WHERE deletion.artifact_id = requested_artifact;
END
$function$;

CREATE FUNCTION attachment.claim_artifact_gc(requested_artifact uuid, requested_lifetime interval)
RETURNS TABLE (
    artifact_id uuid,
    project_id uuid,
    storage_path text,
    size_bytes bigint,
    sha256 text,
    state text,
    gc_generation bigint,
    gc_token uuid,
    gc_lease_until timestamptz,
    gc_after timestamptz,
    deleted_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
SET search_path = pg_catalog
AS $function$
DECLARE
    candidate_project uuid;
BEGIN
    PERFORM jobs.assert_application_mutation();
    IF requested_lifetime < interval '30 seconds' OR requested_lifetime > interval '10 minutes' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid attachment GC claim';
    END IF;
    SELECT deletion.project_id INTO candidate_project
    FROM attachment.deletions AS deletion
    WHERE deletion.artifact_id = requested_artifact
      AND deletion.gc_after <= statement_timestamp()
      AND (deletion.state = 'tombstoned'
           OR (deletion.state = 'gc_claimed' AND deletion.gc_lease_until <= statement_timestamp()));
    IF NOT FOUND OR NOT jobs.physical_blob_gc_permitted() THEN
        RETURN;
    END IF;
    PERFORM 1 FROM relay.projects
    WHERE id = candidate_project AND merged_into IS NULL FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    PERFORM 1 FROM attachment.uploads
    WHERE uploads.artifact_id = requested_artifact AND uploads.project_id = candidate_project FOR UPDATE;
    IF NOT FOUND OR NOT jobs.physical_blob_gc_permitted() THEN
        RETURN;
    END IF;
    RETURN QUERY
    UPDATE attachment.deletions AS deletion
    SET state = 'gc_claimed',
        gc_generation = deletion.gc_generation + 1,
        gc_token = gen_random_uuid(),
        gc_lease_until = statement_timestamp() + requested_lifetime
    WHERE deletion.artifact_id = requested_artifact
      AND deletion.project_id = candidate_project
      AND deletion.gc_after <= statement_timestamp()
      AND (deletion.state = 'tombstoned'
           OR (deletion.state = 'gc_claimed' AND deletion.gc_lease_until <= statement_timestamp()))
    RETURNING deletion.artifact_id, deletion.project_id, deletion.storage_path,
              deletion.size_bytes, deletion.sha256::text, deletion.state,
              deletion.gc_generation, deletion.gc_token, deletion.gc_lease_until,
              deletion.gc_after, deletion.deleted_at;
END
$function$;

CREATE FUNCTION attachment.finalize_artifact_gc(
    requested_artifact uuid,
    requested_generation bigint,
    requested_token uuid
)
RETURNS TABLE (
    artifact_id uuid,
    project_id uuid,
    storage_path text,
    size_bytes bigint,
    sha256 text,
    state text,
    gc_generation bigint,
    gc_after timestamptz,
    deleted_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
SET search_path = pg_catalog
AS $function$
DECLARE
    candidate_project uuid;
    deletion attachment.deletions%ROWTYPE;
    upload attachment.uploads%ROWTYPE;
BEGIN
    PERFORM jobs.assert_application_mutation();
    SELECT candidate.* INTO deletion
    FROM attachment.deletions AS candidate
    WHERE candidate.artifact_id = requested_artifact;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    IF deletion.state = 'deleted' AND deletion.gc_generation = requested_generation
       AND deletion.gc_token IS NOT DISTINCT FROM requested_token THEN
        RETURN QUERY
        SELECT finalized.artifact_id, finalized.project_id, finalized.storage_path,
               finalized.size_bytes, finalized.sha256::text, finalized.state,
               finalized.gc_generation, finalized.gc_after, finalized.deleted_at
        FROM attachment.deletions AS finalized
        WHERE finalized.artifact_id = requested_artifact;
        RETURN;
    END IF;
    candidate_project := deletion.project_id;
    PERFORM 1 FROM relay.projects
    WHERE id = candidate_project AND merged_into IS NULL FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    SELECT candidate.* INTO deletion
    FROM attachment.deletions AS candidate
    WHERE candidate.artifact_id = requested_artifact FOR UPDATE;
    IF deletion.state <> 'gc_claimed' OR deletion.gc_generation <> requested_generation
       OR deletion.gc_token IS DISTINCT FROM requested_token
       OR deletion.gc_lease_until <= statement_timestamp()
       OR NOT jobs.physical_blob_gc_permitted() THEN
        RETURN;
    END IF;
    SELECT candidate.* INTO upload
    FROM attachment.uploads AS candidate
    WHERE candidate.artifact_id = requested_artifact AND candidate.project_id = candidate_project FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    PERFORM 1 FROM attachment.global_quota WHERE singleton FOR UPDATE;
    PERFORM 1 FROM attachment.project_quotas WHERE project_quotas.project_id = upload.project_id FOR UPDATE;
    PERFORM 1 FROM attachment.principal_quotas WHERE principal_quotas.principal_id = upload.principal_id FOR UPDATE;

    DELETE FROM attachment.recipient_grant_endpoints AS endpoint
    USING attachment.recipient_grants AS recipient
    WHERE endpoint.artifact_id = recipient.artifact_id
      AND endpoint.recipient_principal_id = recipient.recipient_principal_id
      AND recipient.artifact_id = requested_artifact;
    DELETE FROM attachment.recipient_grants WHERE recipient_grants.artifact_id = requested_artifact;
    DELETE FROM attachment.message_artifacts WHERE message_artifacts.artifact_id = requested_artifact;
    DELETE FROM attachment.uploads WHERE uploads.artifact_id = requested_artifact;

    UPDATE attachment.global_quota AS quota
    SET used_bytes = quota.used_bytes - deletion.size_bytes,
        ready_artifacts = quota.ready_artifacts - 1
    WHERE quota.singleton AND quota.used_bytes >= deletion.size_bytes AND quota.ready_artifacts >= 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'attachment global quota is inconsistent';
    END IF;
    UPDATE attachment.project_quotas AS quota
    SET used_bytes = quota.used_bytes - deletion.size_bytes,
        ready_artifacts = quota.ready_artifacts - 1
    WHERE quota.project_id = upload.project_id
      AND quota.used_bytes >= deletion.size_bytes AND quota.ready_artifacts >= 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'attachment project quota is inconsistent';
    END IF;
    UPDATE attachment.principal_quotas AS quota
    SET used_bytes = quota.used_bytes - deletion.size_bytes,
        ready_artifacts = quota.ready_artifacts - 1
    WHERE quota.principal_id = upload.principal_id
      AND quota.used_bytes >= deletion.size_bytes AND quota.ready_artifacts >= 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'attachment principal quota is inconsistent';
    END IF;
    UPDATE attachment.deletions AS finalized
    SET state = 'deleted', gc_lease_until = NULL,
        deleted_at = statement_timestamp()
    WHERE finalized.artifact_id = requested_artifact;
    UPDATE relay.projects SET content_generation = content_generation + 1 WHERE id = candidate_project;
    PERFORM jobs.advance_change_sequence();
    RETURN QUERY
    SELECT finalized.artifact_id, finalized.project_id, finalized.storage_path,
           finalized.size_bytes, finalized.sha256::text, finalized.state,
           finalized.gc_generation, finalized.gc_after, finalized.deleted_at
    FROM attachment.deletions AS finalized
    WHERE finalized.artifact_id = requested_artifact;
END
$function$;

CREATE OR REPLACE FUNCTION attachment.mark_corrupt(requested_artifact uuid)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
SET search_path = pg_catalog
AS $function$
DECLARE
    candidate_project uuid;
    upload attachment.uploads%ROWTYPE;
    affected_path text;
BEGIN
    PERFORM jobs.assert_application_mutation();
    SELECT candidate.project_id INTO candidate_project
    FROM attachment.uploads AS candidate
    WHERE candidate.artifact_id = requested_artifact;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    PERFORM 1 FROM relay.projects
    WHERE id = candidate_project AND merged_into IS NULL FOR UPDATE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    SELECT candidate.* INTO upload
    FROM attachment.uploads AS candidate
    WHERE candidate.artifact_id = requested_artifact FOR UPDATE;
    IF NOT FOUND OR upload.project_id <> candidate_project OR upload.state <> 'ready' THEN
        RETURN false;
    END IF;
    DELETE FROM attachment.ready_artifacts
    WHERE ready_artifacts.artifact_id = requested_artifact
    RETURNING ready_artifacts.storage_path INTO affected_path;
    IF affected_path IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'attachment READY projection is inconsistent';
    END IF;
    DELETE FROM attachment.ready_blob_manifest WHERE ready_blob_manifest.storage_path = affected_path;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'attachment READY manifest is inconsistent';
    END IF;
    UPDATE attachment.uploads SET state = 'corrupt'
    WHERE uploads.artifact_id = requested_artifact;
    INSERT INTO attachment.deletions (
        artifact_id, project_id, owner_principal_id, storage_path,
        size_bytes, sha256, state, gc_after
    ) VALUES (
        upload.artifact_id, upload.project_id, upload.principal_id, affected_path,
        upload.size_bytes, upload.sha256, 'tombstoned', statement_timestamp() + interval '24 hours'
    ) ON CONFLICT (artifact_id) DO NOTHING;
    DELETE FROM attachment.recipient_grant_endpoints AS endpoint
    USING attachment.recipient_grants AS recipient
    WHERE endpoint.artifact_id = recipient.artifact_id
      AND endpoint.recipient_principal_id = recipient.recipient_principal_id
      AND recipient.artifact_id = requested_artifact;
    DELETE FROM attachment.recipient_grants WHERE recipient_grants.artifact_id = requested_artifact;
    UPDATE relay.projects SET content_generation = content_generation + 1
    WHERE id = candidate_project AND merged_into IS NULL;
    PERFORM jobs.advance_change_sequence();
    RETURN true;
END
$function$;

CREATE FUNCTION attachment.orphan_gc_allowed(requested_artifact uuid)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT jobs.physical_blob_gc_permitted()
       AND NOT EXISTS (
           SELECT 1 FROM attachment.uploads
           WHERE uploads.artifact_id = requested_artifact
       )
       AND NOT EXISTS (
           SELECT 1 FROM attachment.deletions
           WHERE deletions.artifact_id = requested_artifact
             AND deletions.state <> 'deleted'
       )
$function$;

REVOKE ALL ON attachment.deletions FROM PUBLIC, punaro_app;
REVOKE ALL ON FUNCTION attachment.tombstone_artifact(uuid,uuid,bigint,uuid,uuid,bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION attachment.claim_artifact_gc(uuid,interval) FROM PUBLIC;
REVOKE ALL ON FUNCTION attachment.finalize_artifact_gc(uuid,bigint,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION attachment.orphan_gc_allowed(uuid) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION attachment.tombstone_artifact(uuid,uuid,bigint,uuid,uuid,bytea) TO punaro_app;
GRANT EXECUTE ON FUNCTION attachment.claim_artifact_gc(uuid,interval) TO punaro_app;
GRANT EXECUTE ON FUNCTION attachment.finalize_artifact_gc(uuid,bigint,uuid) TO punaro_app;
GRANT EXECUTE ON FUNCTION attachment.orphan_gc_allowed(uuid) TO punaro_app;
