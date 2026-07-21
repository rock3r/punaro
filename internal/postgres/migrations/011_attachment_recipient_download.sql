CREATE TABLE attachment.endpoint_principals (
    endpoint text CONSTRAINT endpoint_principals_pkey PRIMARY KEY
        CONSTRAINT endpoint_principals_endpoint_fkey REFERENCES relay.mail_endpoints(endpoint),
    machine_id text NOT NULL CONSTRAINT endpoint_principals_machine_id_check CHECK (
        char_length(machine_id) BETWEEN 1 AND 128
        AND octet_length(machine_id) <= 512
        AND machine_id !~ '[[:cntrl:]]'
    ),
    principal_id uuid NOT NULL CONSTRAINT endpoint_principals_principal_id_fkey REFERENCES auth.principals(id),
    credential_lookup_id uuid NOT NULL CONSTRAINT endpoint_principals_credential_lookup_id_fkey REFERENCES auth.device_credentials(lookup_id),
    credential_generation bigint NOT NULL CONSTRAINT endpoint_principals_credential_generation_check CHECK (credential_generation >= 1),
    ownership_generation bigint NOT NULL CONSTRAINT endpoint_principals_ownership_generation_check CHECK (ownership_generation >= 1),
    bound_at timestamptz NOT NULL DEFAULT statement_timestamp()
);

CREATE INDEX endpoint_principals_principal
ON attachment.endpoint_principals (principal_id, endpoint);

CREATE TABLE attachment.conversation_projects (
    conversation_id uuid CONSTRAINT conversation_projects_pkey PRIMARY KEY
        CONSTRAINT conversation_projects_conversation_id_fkey REFERENCES relay.mail_conversations(id),
    project_id uuid NOT NULL CONSTRAINT conversation_projects_project_id_fkey REFERENCES relay.projects(id),
    bound_by uuid NOT NULL CONSTRAINT conversation_projects_bound_by_fkey REFERENCES auth.principals(id),
    bound_at timestamptz NOT NULL DEFAULT statement_timestamp()
);

CREATE INDEX conversation_projects_project
ON attachment.conversation_projects (project_id, conversation_id);

CREATE TABLE attachment.message_artifacts (
    message_id uuid NOT NULL CONSTRAINT message_artifacts_message_id_fkey REFERENCES relay.mail_messages(id),
    ordinal smallint NOT NULL CONSTRAINT message_artifacts_ordinal_check CHECK (ordinal BETWEEN 0 AND 15),
    artifact_id uuid NOT NULL CONSTRAINT message_artifacts_artifact_id_fkey REFERENCES attachment.uploads(artifact_id),
    sender_principal_id uuid NOT NULL CONSTRAINT message_artifacts_sender_principal_id_fkey REFERENCES auth.principals(id),
    linked_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT message_artifacts_pkey PRIMARY KEY (message_id, ordinal),
    CONSTRAINT message_artifacts_artifact_message_key UNIQUE (artifact_id, message_id),
    CONSTRAINT message_artifacts_artifact_key UNIQUE (artifact_id)
);

CREATE TABLE attachment.recipient_grants (
    artifact_id uuid NOT NULL,
    recipient_principal_id uuid NOT NULL CONSTRAINT recipient_grants_recipient_principal_id_fkey REFERENCES auth.principals(id),
    message_id uuid NOT NULL,
    granted_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT recipient_grants_pkey PRIMARY KEY (artifact_id, recipient_principal_id),
    CONSTRAINT recipient_grants_artifact_message_fkey FOREIGN KEY (artifact_id, message_id)
        REFERENCES attachment.message_artifacts(artifact_id, message_id)
);

CREATE INDEX recipient_grants_principal
ON attachment.recipient_grants (recipient_principal_id, artifact_id);

CREATE TABLE attachment.recipient_grant_endpoints (
    artifact_id uuid NOT NULL,
    recipient_principal_id uuid NOT NULL,
    recipient_endpoint text NOT NULL CONSTRAINT recipient_grant_endpoints_endpoint_check CHECK (
        char_length(recipient_endpoint) BETWEEN 1 AND 512
        AND octet_length(recipient_endpoint) <= 2048
        AND recipient_endpoint !~ '[[:cntrl:]]'
    ),
    recipient_machine_id text NOT NULL CONSTRAINT recipient_grant_endpoints_machine_check CHECK (
        char_length(recipient_machine_id) BETWEEN 1 AND 128
        AND octet_length(recipient_machine_id) <= 512
        AND recipient_machine_id !~ '[[:cntrl:]]'
    ),
    ownership_generation bigint NOT NULL CONSTRAINT recipient_grant_endpoints_generation_check CHECK (ownership_generation >= 1),
    message_id uuid NOT NULL,
    CONSTRAINT recipient_grant_endpoints_pkey PRIMARY KEY (artifact_id, recipient_principal_id, recipient_endpoint),
    CONSTRAINT recipient_grant_endpoints_grant_fkey FOREIGN KEY (artifact_id, recipient_principal_id)
        REFERENCES attachment.recipient_grants(artifact_id, recipient_principal_id),
    CONSTRAINT recipient_grant_endpoints_delivery_fkey FOREIGN KEY (message_id, recipient_endpoint)
        REFERENCES relay.mail_deliveries(message_id, recipient_endpoint)
);

-- Schema v10 publication locked an upload before its project, while message
-- artifact binding locks the project before its uploads. Replace the
-- publication routine at the v11 boundary so both operations use the same
-- project -> upload order and cannot deadlock one another.
CREATE OR REPLACE FUNCTION attachment.publish_upload(
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
    candidate_project uuid;
    current_timeline uuid;
    grant_id uuid;
    existing_path text;
    existing_size bigint;
    existing_sha text;
BEGIN
    PERFORM jobs.assert_application_mutation();
    SELECT candidate.project_id INTO candidate_project
    FROM attachment.uploads AS candidate
    WHERE candidate.artifact_id = requested_artifact
      AND candidate.principal_id = requested_principal;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'attachment publication is not authorized';
    END IF;
    PERFORM 1 FROM relay.projects
    WHERE id = candidate_project AND merged_into IS NULL FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'attachment project is unavailable';
    END IF;
    SELECT candidate.* INTO upload
    FROM attachment.uploads AS candidate
    WHERE candidate.artifact_id = requested_artifact FOR UPDATE;
    IF NOT FOUND OR upload.principal_id <> requested_principal OR upload.project_id <> candidate_project THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'attachment publication is not authorized';
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

CREATE FUNCTION attachment.device_authority_current(
    requested_principal uuid,
    requested_lookup uuid,
    requested_generation bigint
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT EXISTS (
        SELECT 1
        FROM auth.principals AS principal
        JOIN auth.device_credentials AS credential ON credential.principal_id = principal.id
        WHERE principal.id = requested_principal
          AND principal.disabled_at IS NULL
          AND credential.lookup_id = requested_lookup
          AND credential.generation = requested_generation
          AND credential.revoked_at IS NULL
          AND (credential.expires_at IS NULL OR credential.expires_at > statement_timestamp())
    )
$function$;

CREATE FUNCTION attachment.bind_endpoint_principals(
    requested_machine text,
    requested_principal uuid,
    requested_lookup uuid,
    requested_generation bigint,
    requested_endpoints jsonb,
    requested_now timestamptz
)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    endpoint_count integer;
    matched_count integer;
BEGIN
    PERFORM jobs.assert_application_mutation();
    IF requested_machine IS NULL OR char_length(requested_machine) < 1 OR char_length(requested_machine) > 128
       OR octet_length(requested_machine) > 512 OR requested_machine ~ '[[:cntrl:]]'
       OR requested_now IS NULL OR jsonb_typeof(requested_endpoints) <> 'array'
       OR jsonb_array_length(requested_endpoints) > 256
       OR EXISTS (
           SELECT 1 FROM jsonb_array_elements(requested_endpoints) AS item(value)
           WHERE jsonb_typeof(item.value) <> 'string'
              OR char_length(item.value #>> '{}') < 1 OR char_length(item.value #>> '{}') > 512
              OR octet_length(item.value #>> '{}') > 2048 OR (item.value #>> '{}') ~ '[[:cntrl:]]'
       ) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'endpoint principal binding is not authorized';
    END IF;
    SELECT count(*), count(DISTINCT value) INTO endpoint_count, matched_count
    FROM jsonb_array_elements_text(requested_endpoints) AS endpoint(value);
    IF endpoint_count <> matched_count THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'endpoint principal binding is invalid';
    END IF;

    IF requested_principal IS NULL OR requested_lookup IS NULL OR requested_generation IS NULL THEN
        IF requested_principal IS NOT NULL OR requested_lookup IS NOT NULL OR requested_generation IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'endpoint principal binding is not authorized';
        END IF;
        DELETE FROM attachment.endpoint_principals AS binding
        WHERE binding.machine_id = requested_machine
           OR binding.endpoint IN (
               SELECT endpoint.endpoint
               FROM relay.mail_endpoints AS endpoint
               JOIN jsonb_array_elements_text(requested_endpoints) AS requested(value)
                 ON requested.value = endpoint.endpoint
               WHERE endpoint.machine_id = requested_machine AND endpoint.lease_until > requested_now
           );
        SELECT count(*) INTO matched_count
        FROM relay.mail_endpoints AS endpoint
        JOIN jsonb_array_elements_text(requested_endpoints) AS requested(value)
          ON requested.value = endpoint.endpoint
        WHERE endpoint.machine_id = requested_machine AND endpoint.lease_until > requested_now;
        IF matched_count <> endpoint_count THEN
            RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'endpoint principal binding is not authorized';
        END IF;
        RETURN matched_count;
    END IF;
    PERFORM 1
    FROM auth.principals AS principal
    JOIN auth.device_credentials AS credential ON credential.principal_id = principal.id
    WHERE principal.id = requested_principal AND principal.disabled_at IS NULL
      AND credential.lookup_id = requested_lookup
      AND credential.generation = requested_generation
      AND credential.revoked_at IS NULL
      AND (credential.expires_at IS NULL OR credential.expires_at > statement_timestamp())
    FOR SHARE OF principal, credential;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'endpoint principal binding is not authorized';
    END IF;

    DELETE FROM attachment.endpoint_principals AS binding
    WHERE binding.machine_id = requested_machine
      AND NOT EXISTS (
          SELECT 1 FROM jsonb_array_elements_text(requested_endpoints) AS requested(value)
          WHERE requested.value = binding.endpoint
      );

    WITH requested AS (
        SELECT value AS endpoint FROM jsonb_array_elements_text(requested_endpoints)
    ), current_endpoints AS (
        SELECT endpoint.endpoint, endpoint.ownership_generation
        FROM relay.mail_endpoints AS endpoint
        JOIN requested ON requested.endpoint = endpoint.endpoint
        WHERE endpoint.machine_id = requested_machine AND endpoint.lease_until > requested_now
        ORDER BY endpoint.endpoint COLLATE "C"
        FOR UPDATE OF endpoint
    ), upserted AS (
        INSERT INTO attachment.endpoint_principals (
            endpoint, machine_id, principal_id, credential_lookup_id,
            credential_generation, ownership_generation, bound_at
        )
        SELECT endpoint, requested_machine, requested_principal, requested_lookup,
               requested_generation, ownership_generation, statement_timestamp()
        FROM current_endpoints
        ON CONFLICT (endpoint) DO UPDATE SET
            machine_id = excluded.machine_id,
            principal_id = excluded.principal_id,
            credential_lookup_id = excluded.credential_lookup_id,
            credential_generation = excluded.credential_generation,
            ownership_generation = excluded.ownership_generation,
            bound_at = excluded.bound_at
        RETURNING 1
    )
    SELECT count(*) INTO matched_count FROM upserted;
    IF matched_count <> endpoint_count THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'endpoint principal binding is not authorized';
    END IF;
    RETURN matched_count;
END
$function$;

CREATE FUNCTION attachment.bind_conversation_project(
    requested_principal uuid,
    requested_lookup uuid,
    requested_generation bigint,
    requested_conversation uuid,
    requested_creator_endpoint text,
    requested_project uuid
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    canonical_project uuid;
    existing_project uuid;
    grant_id uuid;
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
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'conversation project binding is not authorized';
    END IF;
    PERFORM 1
    FROM auth.principals AS principal
    JOIN auth.device_credentials AS credential ON credential.principal_id = principal.id
    WHERE principal.id = requested_principal AND principal.disabled_at IS NULL
      AND credential.lookup_id = requested_lookup
      AND credential.generation = requested_generation
      AND credential.revoked_at IS NULL
      AND (credential.expires_at IS NULL OR credential.expires_at > statement_timestamp())
    FOR SHARE OF principal, credential;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'conversation project binding is not authorized';
    END IF;
    SELECT capability_grant.id INTO grant_id
    FROM auth.capability_grants AS capability_grant
    WHERE capability_grant.principal_id = requested_principal
      AND capability_grant.revoked_at IS NULL
      AND capability_grant.capability = 'conversation.send'
      AND ((capability_grant.scope = 'project' AND capability_grant.project_id = canonical_project)
           OR (capability_grant.scope = 'all_projects' AND capability_grant.project_id IS NULL))
    ORDER BY capability_grant.id LIMIT 1 FOR SHARE OF capability_grant;
    IF grant_id IS NULL OR NOT EXISTS (
        SELECT 1
        FROM relay.mail_memberships AS membership
        JOIN attachment.endpoint_principals AS binding ON binding.endpoint = membership.endpoint
        WHERE membership.conversation_id = requested_conversation
          AND membership.endpoint = requested_creator_endpoint
          AND (membership.capabilities & 1) <> 0
          AND binding.principal_id = requested_principal
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'conversation project binding is not authorized';
    END IF;
    INSERT INTO attachment.conversation_projects (conversation_id, project_id, bound_by)
    VALUES (requested_conversation, canonical_project, requested_principal)
    ON CONFLICT (conversation_id) DO NOTHING;
    SELECT project_id INTO existing_project
    FROM attachment.conversation_projects
    WHERE conversation_id = requested_conversation
    FOR SHARE;
    IF existing_project IS DISTINCT FROM canonical_project THEN
        RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'conversation project binding conflicts with prior request';
    END IF;
    RETURN canonical_project;
END
$function$;

CREATE FUNCTION attachment.bind_message_artifacts(
    requested_principal uuid,
    requested_lookup uuid,
    requested_generation bigint,
    requested_message uuid,
    requested_artifacts jsonb
)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    artifact_count integer;
    distinct_count integer;
    matching_count integer;
    delivery_count integer;
    bound_delivery_count integer;
    message_project uuid;
    sender_endpoint text;
    grant_id uuid;
BEGIN
    PERFORM jobs.assert_application_mutation();
    IF jsonb_typeof(requested_artifacts) <> 'array'
       OR jsonb_array_length(requested_artifacts) < 1
       OR jsonb_array_length(requested_artifacts) > 16
       OR EXISTS (
           SELECT 1 FROM jsonb_array_elements(requested_artifacts) AS item(value)
           WHERE jsonb_typeof(item.value) <> 'string'
              OR (item.value #>> '{}') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       ) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'message attachment binding is not authorized';
    END IF;
    SELECT count(*), count(DISTINCT value) INTO artifact_count, distinct_count
    FROM jsonb_array_elements_text(requested_artifacts) AS artifact(value);
    IF artifact_count <> distinct_count THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'message attachment binding is invalid';
    END IF;
    SELECT project.project_id, message.from_endpoint
    INTO message_project, sender_endpoint
    FROM relay.mail_messages AS message
    JOIN attachment.conversation_projects AS project ON project.conversation_id = message.conversation_id
    WHERE message.id = requested_message
    FOR SHARE OF message, project;
    IF message_project IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'message attachment binding is not authorized';
    END IF;
    PERFORM 1 FROM relay.projects
    WHERE id = message_project AND merged_into IS NULL FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'message attachment binding is not authorized';
    END IF;
    PERFORM 1
    FROM auth.principals AS principal
    JOIN auth.device_credentials AS credential ON credential.principal_id = principal.id
    WHERE principal.id = requested_principal AND principal.disabled_at IS NULL
      AND credential.lookup_id = requested_lookup
      AND credential.generation = requested_generation
      AND credential.revoked_at IS NULL
      AND (credential.expires_at IS NULL OR credential.expires_at > statement_timestamp())
    FOR SHARE OF principal, credential;
    IF NOT FOUND OR NOT EXISTS (
        SELECT 1 FROM attachment.endpoint_principals
        WHERE endpoint = sender_endpoint AND principal_id = requested_principal
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'message attachment binding is not authorized';
    END IF;
    SELECT capability_grant.id INTO grant_id
    FROM auth.capability_grants AS capability_grant
    WHERE capability_grant.principal_id = requested_principal
      AND capability_grant.revoked_at IS NULL
      AND capability_grant.capability = 'conversation.send'
      AND ((capability_grant.scope = 'project' AND capability_grant.project_id = message_project)
           OR (capability_grant.scope = 'all_projects' AND capability_grant.project_id IS NULL))
    ORDER BY capability_grant.id LIMIT 1 FOR SHARE OF capability_grant;
    IF grant_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'message attachment binding is not authorized';
    END IF;

    SELECT count(*) INTO matching_count
    FROM attachment.message_artifacts AS linked
    JOIN jsonb_array_elements_text(requested_artifacts) WITH ORDINALITY AS artifact(value, ordinality)
      ON linked.ordinal = artifact.ordinality - 1
     AND linked.artifact_id = artifact.value::uuid
    WHERE linked.message_id = requested_message
      AND linked.sender_principal_id = requested_principal;
    IF matching_count > 0 THEN
        IF matching_count <> artifact_count OR EXISTS (
            SELECT 1 FROM attachment.message_artifacts
            WHERE message_id = requested_message
            OFFSET artifact_count
        ) THEN
            RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'message attachment binding conflicts with prior request';
        END IF;
        RETURN matching_count;
    END IF;

    PERFORM 1
    FROM attachment.uploads AS upload
    WHERE upload.artifact_id IN (
        SELECT value::uuid FROM jsonb_array_elements_text(requested_artifacts) AS artifact(value)
    )
    ORDER BY upload.artifact_id
    FOR UPDATE;
    SELECT count(*) INTO matching_count
    FROM attachment.uploads AS upload
    JOIN attachment.ready_artifacts AS ready ON ready.artifact_id = upload.artifact_id
    JOIN attachment.ready_blob_manifest AS manifest ON manifest.storage_path = ready.storage_path
    WHERE upload.artifact_id IN (
        SELECT value::uuid FROM jsonb_array_elements_text(requested_artifacts) AS artifact(value)
    )
      AND upload.project_id = message_project
      AND upload.principal_id = requested_principal
      AND upload.state = 'ready'
      AND manifest.size_bytes = upload.size_bytes
      AND manifest.sha256::text = upload.sha256::text;
    IF matching_count <> artifact_count THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'message attachment binding is not authorized';
    END IF;

    SELECT count(*) INTO delivery_count
    FROM relay.mail_deliveries WHERE message_id = requested_message;
    PERFORM 1
    FROM attachment.endpoint_principals AS binding
    JOIN relay.mail_deliveries AS delivery ON delivery.recipient_endpoint = binding.endpoint
    WHERE delivery.message_id = requested_message
    ORDER BY binding.endpoint
    FOR SHARE OF binding;
    SELECT count(*) INTO bound_delivery_count
    FROM relay.mail_deliveries AS delivery
    JOIN attachment.endpoint_principals AS binding ON binding.endpoint = delivery.recipient_endpoint
    WHERE delivery.message_id = requested_message;
    IF bound_delivery_count <> delivery_count THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'message attachment recipient is not authorized';
    END IF;

    INSERT INTO attachment.message_artifacts (
        message_id, ordinal, artifact_id, sender_principal_id
    )
    SELECT requested_message, (artifact.ordinality - 1)::smallint,
           artifact.value::uuid, requested_principal
    FROM jsonb_array_elements_text(requested_artifacts) WITH ORDINALITY AS artifact(value, ordinality)
    ORDER BY artifact.ordinality;

    INSERT INTO attachment.recipient_grants (
        artifact_id, recipient_principal_id, message_id
    )
    SELECT artifact.value::uuid, binding.principal_id, requested_message
    FROM jsonb_array_elements_text(requested_artifacts) AS artifact(value)
    CROSS JOIN relay.mail_deliveries AS delivery
    JOIN attachment.endpoint_principals AS binding ON binding.endpoint = delivery.recipient_endpoint
    WHERE delivery.message_id = requested_message
    GROUP BY artifact.value, binding.principal_id;

    INSERT INTO attachment.recipient_grant_endpoints (
        artifact_id, recipient_principal_id, recipient_endpoint,
        recipient_machine_id, ownership_generation, message_id
    )
    SELECT artifact.value::uuid, binding.principal_id, delivery.recipient_endpoint,
           binding.machine_id, binding.ownership_generation, requested_message
    FROM jsonb_array_elements_text(requested_artifacts) AS artifact(value)
    CROSS JOIN relay.mail_deliveries AS delivery
    JOIN attachment.endpoint_principals AS binding ON binding.endpoint = delivery.recipient_endpoint
    WHERE delivery.message_id = requested_message;
    RETURN artifact_count;
END
$function$;

CREATE FUNCTION attachment.project_has_recipient_records(
    requested_principal uuid,
    requested_project uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
SET search_path = pg_catalog
AS $function$
DECLARE
    grant_id uuid;
BEGIN
    SELECT capability_grant.id INTO grant_id
    FROM auth.principals AS principal
    JOIN auth.capability_grants AS capability_grant ON capability_grant.principal_id = principal.id
    WHERE principal.id = requested_principal AND principal.disabled_at IS NULL
      AND capability_grant.revoked_at IS NULL
      AND capability_grant.capability = 'project.administer'
      AND ((capability_grant.scope = 'project' AND capability_grant.project_id = requested_project)
           OR (capability_grant.scope = 'all_projects' AND capability_grant.project_id IS NULL))
    ORDER BY capability_grant.id LIMIT 1
    FOR SHARE OF principal, capability_grant;
    IF grant_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'attachment project state is not authorized';
    END IF;
    RETURN EXISTS (
        SELECT 1 FROM attachment.conversation_projects
        WHERE project_id = requested_project
    );
END
$function$;

CREATE FUNCTION attachment.authorize_download(
    requested_principal uuid,
    requested_lookup uuid,
    requested_generation bigint,
    requested_artifact uuid
)
RETURNS TABLE (
    artifact_id uuid,
    project_id uuid,
    storage_path text,
    size_bytes bigint,
    sha256 text,
    display_name text,
    media_type text,
    ready_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog
AS $function$
BEGIN
    IF NOT attachment.device_authority_current(requested_principal, requested_lookup, requested_generation) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'attachment download is not authorized';
    END IF;
    RETURN QUERY
    SELECT upload.artifact_id, upload.project_id, ready.storage_path,
           upload.size_bytes, upload.sha256::text, upload.display_name,
           upload.media_type, upload.ready_at
    FROM attachment.uploads AS upload
    JOIN attachment.ready_artifacts AS ready ON ready.artifact_id = upload.artifact_id
    JOIN attachment.ready_blob_manifest AS manifest ON manifest.storage_path = ready.storage_path
    JOIN attachment.recipient_grants AS recipient
      ON recipient.artifact_id = upload.artifact_id
     AND recipient.recipient_principal_id = requested_principal
    WHERE upload.artifact_id = requested_artifact
      AND upload.state = 'ready'
      AND manifest.size_bytes = upload.size_bytes
      AND manifest.sha256::text = upload.sha256::text
      AND EXISTS (
          SELECT 1 FROM auth.capability_grants AS capability_grant
          WHERE capability_grant.principal_id = requested_principal
            AND capability_grant.revoked_at IS NULL
            AND capability_grant.capability = 'attachment.download'
            AND ((capability_grant.scope = 'project' AND capability_grant.project_id = upload.project_id)
                 OR (capability_grant.scope = 'all_projects' AND capability_grant.project_id IS NULL))
      );
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'attachment download is not authorized';
    END IF;
END
$function$;

REVOKE ALL ON attachment.endpoint_principals, attachment.conversation_projects,
    attachment.message_artifacts, attachment.recipient_grants,
    attachment.recipient_grant_endpoints FROM PUBLIC, punaro_app;

REVOKE ALL ON FUNCTION attachment.device_authority_current(uuid,uuid,bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION attachment.bind_endpoint_principals(text,uuid,uuid,bigint,jsonb,timestamp with time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION attachment.bind_conversation_project(uuid,uuid,bigint,uuid,text,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION attachment.bind_message_artifacts(uuid,uuid,bigint,uuid,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION attachment.project_has_recipient_records(uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION attachment.authorize_download(uuid,uuid,bigint,uuid) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION attachment.bind_endpoint_principals(text,uuid,uuid,bigint,jsonb,timestamp with time zone) TO punaro_app;
GRANT EXECUTE ON FUNCTION attachment.bind_conversation_project(uuid,uuid,bigint,uuid,text,uuid) TO punaro_app;
GRANT EXECUTE ON FUNCTION attachment.bind_message_artifacts(uuid,uuid,bigint,uuid,jsonb) TO punaro_app;
GRANT EXECUTE ON FUNCTION attachment.project_has_recipient_records(uuid,uuid) TO punaro_app;
GRANT EXECUTE ON FUNCTION attachment.authorize_download(uuid,uuid,bigint,uuid) TO punaro_app;
