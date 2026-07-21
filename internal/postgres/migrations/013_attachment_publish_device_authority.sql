CREATE FUNCTION attachment.reserve_upload(
    requested_principal uuid,
    requested_lookup uuid,
    requested_credential_generation bigint,
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
    authority_id uuid;
BEGIN
    PERFORM jobs.assert_application_mutation();
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
    SELECT principal.id INTO authority_id
    FROM auth.principals AS principal
    JOIN auth.device_credentials AS credential ON credential.principal_id = principal.id
    WHERE principal.id = requested_principal AND principal.disabled_at IS NULL
      AND credential.lookup_id = requested_lookup
      AND credential.generation = requested_credential_generation
      AND credential.revoked_at IS NULL
      AND (credential.expires_at IS NULL OR credential.expires_at > statement_timestamp())
    FOR SHARE OF principal, credential;
    IF authority_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'attachment reservation is not authorized';
    END IF;
    RETURN QUERY
    SELECT reserved.artifact_id, reserved.project_id, reserved.principal_id,
           reserved.timeline_id, reserved.size_bytes, reserved.sha256,
           reserved.display_name, reserved.media_type, reserved.state,
           reserved.attempt_generation, reserved.expires_at, reserved.ready_at
    FROM attachment.reserve_upload(
        requested_principal, requested_project, request_key, request_hash,
        requested_size, requested_sha256, requested_display_name,
        requested_media_type, requested_lifetime
    ) AS reserved;
END
$function$;

CREATE FUNCTION attachment.publish_upload(
    requested_principal uuid,
    requested_lookup uuid,
    requested_credential_generation bigint,
    requested_artifact uuid,
    requested_attempt_generation bigint,
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
    candidate_project uuid;
    authority_id uuid;
    grant_id uuid;
BEGIN
    PERFORM jobs.assert_application_mutation();
    SELECT candidate.project_id INTO candidate_project
    FROM attachment.uploads AS candidate
    WHERE candidate.artifact_id = requested_artifact
      AND candidate.principal_id = requested_principal;
    IF candidate_project IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'attachment publication is not authorized';
    END IF;
    PERFORM 1 FROM relay.projects
    WHERE id = candidate_project AND merged_into IS NULL FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'attachment project is unavailable';
    END IF;
    SELECT principal.id INTO authority_id
    FROM auth.principals AS principal
    JOIN auth.device_credentials AS credential ON credential.principal_id = principal.id
    WHERE principal.id = requested_principal AND principal.disabled_at IS NULL
      AND credential.lookup_id = requested_lookup
      AND credential.generation = requested_credential_generation
      AND credential.revoked_at IS NULL
      AND (credential.expires_at IS NULL OR credential.expires_at > statement_timestamp())
    FOR SHARE OF principal, credential;
    IF authority_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'attachment publication is not authorized';
    END IF;
    SELECT capability_grant.id INTO grant_id
    FROM auth.capability_grants AS capability_grant
    WHERE capability_grant.principal_id = requested_principal
      AND capability_grant.revoked_at IS NULL
      AND capability_grant.capability = 'attachment.upload'
      AND ((capability_grant.scope = 'project' AND capability_grant.project_id = candidate_project)
           OR (capability_grant.scope = 'all_projects' AND capability_grant.project_id IS NULL))
    ORDER BY capability_grant.id LIMIT 1 FOR SHARE;
    IF grant_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'attachment publication is not authorized';
    END IF;
    RETURN QUERY
    SELECT published.artifact_id, published.project_id, published.storage_path,
           published.size_bytes, published.sha256, published.state, published.ready_at
    FROM attachment.publish_upload(
        requested_principal, requested_artifact, requested_attempt_generation,
        requested_claim_token, requested_storage_path, requested_size, requested_sha256
    ) AS published;
END
$function$;

CREATE FUNCTION attachment.gc_candidates(
    requested_after uuid,
    requested_limit integer
)
RETURNS TABLE (artifact_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog
AS $function$
BEGIN
    IF requested_limit IS NULL OR requested_limit < 1 OR requested_limit > 100 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid attachment GC candidate limit';
    END IF;
    RETURN QUERY
    SELECT candidate.artifact_id
    FROM attachment.deletions AS candidate
    WHERE candidate.gc_after <= statement_timestamp()
      AND (candidate.state = 'tombstoned'
           OR (candidate.state = 'gc_claimed' AND candidate.gc_lease_until <= statement_timestamp()))
      AND (requested_after IS NULL OR candidate.artifact_id > requested_after)
    ORDER BY candidate.artifact_id
    LIMIT requested_limit;
END
$function$;

REVOKE ALL ON FUNCTION attachment.reserve_upload(uuid,uuid,uuid,bytea,bigint,text,text,text,interval) FROM punaro_app;
REVOKE ALL ON FUNCTION attachment.reserve_upload(uuid,uuid,bigint,uuid,uuid,bytea,bigint,text,text,text,interval) FROM PUBLIC;
REVOKE ALL ON FUNCTION attachment.publish_upload(uuid,uuid,bigint,uuid,text,bigint,text) FROM punaro_app;
REVOKE ALL ON FUNCTION attachment.publish_upload(uuid,uuid,bigint,uuid,bigint,uuid,text,bigint,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION attachment.gc_candidates(uuid,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION attachment.reserve_upload(uuid,uuid,bigint,uuid,uuid,bytea,bigint,text,text,text,interval) TO punaro_app;
GRANT EXECUTE ON FUNCTION attachment.publish_upload(uuid,uuid,bigint,uuid,bigint,uuid,text,bigint,text) TO punaro_app;
GRANT EXECUTE ON FUNCTION attachment.gc_candidates(uuid,integer) TO punaro_app;
