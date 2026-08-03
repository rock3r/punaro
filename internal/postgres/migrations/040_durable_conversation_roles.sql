-- Durable conversation roles deliberately live outside the endpoint namespace.
-- A binding proves that an owner machine currently controls one particular
-- endpoint generation; delivery/cursor recipient identities use role:<name>.
CREATE TABLE relay.mail_roles (
    role text PRIMARY KEY CHECK (
        char_length(role) >= 1 AND char_length(role) <= 512
        AND octet_length(role) <= 2048 AND role !~ '[[:cntrl:]]'
    ),
    machine_id text NOT NULL CHECK (
        char_length(machine_id) >= 1 AND char_length(machine_id) <= 128
        AND octet_length(machine_id) <= 512 AND machine_id !~ '[[:cntrl:]]'
    )
);

CREATE TABLE relay.mail_role_memberships (
    conversation_id uuid NOT NULL REFERENCES relay.mail_conversations(id),
    role text NOT NULL REFERENCES relay.mail_roles(role),
    capabilities smallint NOT NULL CHECK (capabilities BETWEEN 1 AND 7),
    PRIMARY KEY (conversation_id, role)
);

CREATE TABLE relay.mail_role_bindings (
    role text PRIMARY KEY REFERENCES relay.mail_roles(role),
    session_endpoint text NOT NULL REFERENCES relay.mail_endpoints(endpoint),
    machine_id text NOT NULL,
    ownership_generation bigint NOT NULL CHECK (ownership_generation > 0),
    lease_until timestamptz NOT NULL
);

CREATE INDEX mail_role_bindings_session
ON relay.mail_role_bindings (machine_id, session_endpoint, lease_until, role);

-- These recipient columns are polymorphic: a legacy endpoint or a durable
-- role:<name> identity. The relay is their only writer and validates each
-- identity transactionally before insertion.
ALTER TABLE relay.mail_deliveries
    DROP CONSTRAINT mail_deliveries_recipient_endpoint_fkey;
ALTER TABLE relay.mail_recipient_cursors
    DROP CONSTRAINT mail_recipient_cursors_recipient_endpoint_fkey;

CREATE TRIGGER mail_roles_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_roles
FOR EACH STATEMENT EXECUTE FUNCTION relay.guard_mail_mutation();
CREATE TRIGGER mail_role_memberships_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_role_memberships
FOR EACH STATEMENT EXECUTE FUNCTION relay.guard_mail_mutation();
CREATE TRIGGER mail_role_bindings_mutation_guard
BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_role_bindings
FOR EACH STATEMENT EXECUTE FUNCTION relay.guard_mail_mutation();

GRANT SELECT, INSERT ON relay.mail_roles TO punaro_app;
GRANT SELECT, INSERT ON relay.mail_role_memberships TO punaro_app;
GRANT SELECT, INSERT, UPDATE (session_endpoint, machine_id, ownership_generation, lease_until) ON relay.mail_role_bindings TO punaro_app;

ALTER TABLE relay.mail_cutover_staging DROP CONSTRAINT mail_cutover_staging_table_name_check;
ALTER TABLE relay.mail_cutover_staging ADD CONSTRAINT mail_cutover_staging_table_name_check CHECK (table_name IN ('mail_endpoints','mail_conversations','mail_memberships','mail_roles','mail_role_memberships','mail_role_bindings','mail_messages','mail_deliveries','mail_recipient_cursors','mail_message_idempotency','mail_conversation_idempotency','mail_request_nonces'));
ALTER TABLE relay.mail_cutover_checkpoints DROP CONSTRAINT mail_cutover_checkpoints_table_name_check;
ALTER TABLE relay.mail_cutover_checkpoints ADD CONSTRAINT mail_cutover_checkpoints_table_name_check CHECK (table_name IN ('mail_endpoints','mail_conversations','mail_memberships','mail_roles','mail_role_memberships','mail_role_bindings','mail_messages','mail_deliveries','mail_recipient_cursors','mail_message_idempotency','mail_conversation_idempotency','mail_request_nonces'));

-- Endpoint grants remain immutable snapshots. A role delivery instead derives
-- attachment access from its currently fenced session binding, allowing an
-- unbound role to receive an artifact-bearing message and bind later.
CREATE OR REPLACE FUNCTION attachment.bind_message_artifacts(
    requested_principal uuid, requested_lookup uuid, requested_generation bigint,
    requested_message uuid, requested_artifacts jsonb
)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $function$
DECLARE
    artifact_count integer; distinct_count integer; matching_count integer;
    delivery_count integer; bound_delivery_count integer; message_project uuid;
    sender_endpoint text; grant_id uuid;
BEGIN
    PERFORM jobs.assert_application_mutation();
    IF jsonb_typeof(requested_artifacts) <> 'array'
       OR jsonb_array_length(requested_artifacts) < 1
       OR jsonb_array_length(requested_artifacts) > 16
       OR EXISTS (SELECT 1 FROM jsonb_array_elements(requested_artifacts) AS item(value)
                  WHERE jsonb_typeof(item.value) <> 'string'
                     OR (item.value #>> '{}') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$') THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'message attachment binding is not authorized';
    END IF;
    SELECT count(*), count(DISTINCT value) INTO artifact_count, distinct_count
    FROM jsonb_array_elements_text(requested_artifacts) AS artifact(value);
    IF artifact_count <> distinct_count THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'message attachment binding is invalid';
    END IF;
    SELECT project.project_id, message.from_endpoint INTO message_project, sender_endpoint
    FROM relay.mail_messages AS message
    JOIN attachment.conversation_projects AS project ON project.conversation_id = message.conversation_id
    WHERE message.id = requested_message FOR SHARE OF message, project;
    IF message_project IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'message attachment binding is not authorized';
    END IF;
    PERFORM 1 FROM relay.projects WHERE id = message_project AND merged_into IS NULL FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'message attachment binding is not authorized';
    END IF;
    PERFORM 1 FROM auth.principals AS principal
    JOIN auth.device_credentials AS credential ON credential.principal_id = principal.id
    WHERE principal.id = requested_principal AND principal.disabled_at IS NULL
      AND credential.lookup_id = requested_lookup AND credential.generation = requested_generation
      AND credential.revoked_at IS NULL AND (credential.expires_at IS NULL OR credential.expires_at > statement_timestamp())
    FOR SHARE OF principal, credential;
    IF NOT FOUND OR NOT EXISTS (SELECT 1 FROM attachment.endpoint_principals WHERE endpoint = sender_endpoint AND principal_id = requested_principal) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'message attachment binding is not authorized';
    END IF;
    SELECT capability_grant.id INTO grant_id FROM auth.capability_grants AS capability_grant
    WHERE capability_grant.principal_id = requested_principal AND capability_grant.revoked_at IS NULL
      AND capability_grant.capability = 'conversation.send'
      AND ((capability_grant.scope = 'project' AND capability_grant.project_id = message_project)
           OR (capability_grant.scope = 'all_projects' AND capability_grant.project_id IS NULL))
    ORDER BY capability_grant.id LIMIT 1 FOR SHARE OF capability_grant;
    IF grant_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'message attachment binding is not authorized';
    END IF;
    SELECT count(*) INTO matching_count FROM attachment.message_artifacts AS linked
    JOIN jsonb_array_elements_text(requested_artifacts) WITH ORDINALITY AS artifact(value, ordinality)
      ON linked.ordinal = artifact.ordinality - 1 AND linked.artifact_id = artifact.value::uuid
    WHERE linked.message_id = requested_message AND linked.sender_principal_id = requested_principal;
    IF matching_count > 0 THEN
        IF matching_count <> artifact_count OR EXISTS (SELECT 1 FROM attachment.message_artifacts WHERE message_id = requested_message OFFSET artifact_count) THEN
            RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'message attachment binding conflicts with prior request';
        END IF;
        RETURN matching_count;
    END IF;
    PERFORM 1 FROM attachment.uploads AS upload
    WHERE upload.artifact_id IN (SELECT value::uuid FROM jsonb_array_elements_text(requested_artifacts) AS artifact(value))
    ORDER BY upload.artifact_id FOR UPDATE;
    SELECT count(*) INTO matching_count FROM attachment.uploads AS upload
    JOIN attachment.ready_artifacts AS ready ON ready.artifact_id = upload.artifact_id
    JOIN attachment.ready_blob_manifest AS manifest ON manifest.storage_path = ready.storage_path
    WHERE upload.artifact_id IN (SELECT value::uuid FROM jsonb_array_elements_text(requested_artifacts) AS artifact(value))
      AND upload.project_id = message_project AND upload.principal_id = requested_principal AND upload.state = 'ready'
      AND manifest.size_bytes = upload.size_bytes AND manifest.sha256::text = upload.sha256::text;
    IF matching_count <> artifact_count THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'message attachment binding is not authorized';
    END IF;
    SELECT count(*) INTO delivery_count FROM relay.mail_deliveries
    WHERE message_id = requested_message AND recipient_endpoint !~ ('^' || chr(30) || 'role:');
    PERFORM 1 FROM attachment.endpoint_principals AS binding
    JOIN relay.mail_deliveries AS delivery ON delivery.recipient_endpoint = binding.endpoint
    WHERE delivery.message_id = requested_message AND delivery.recipient_endpoint !~ ('^' || chr(30) || 'role:')
    ORDER BY binding.endpoint FOR SHARE OF binding;
    SELECT count(*) INTO bound_delivery_count FROM relay.mail_deliveries AS delivery
    JOIN attachment.endpoint_principals AS binding ON binding.endpoint = delivery.recipient_endpoint
    WHERE delivery.message_id = requested_message AND delivery.recipient_endpoint !~ ('^' || chr(30) || 'role:');
    IF bound_delivery_count <> delivery_count THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'message attachment recipient is not authorized';
    END IF;
    INSERT INTO attachment.message_artifacts (message_id, ordinal, artifact_id, sender_principal_id)
    SELECT requested_message, (artifact.ordinality - 1)::smallint, artifact.value::uuid, requested_principal
    FROM jsonb_array_elements_text(requested_artifacts) WITH ORDINALITY AS artifact(value, ordinality) ORDER BY artifact.ordinality;
    INSERT INTO attachment.recipient_grants (artifact_id, recipient_principal_id, message_id)
    SELECT artifact.value::uuid, binding.principal_id, requested_message
    FROM jsonb_array_elements_text(requested_artifacts) AS artifact(value)
    CROSS JOIN relay.mail_deliveries AS delivery
    JOIN attachment.endpoint_principals AS binding ON binding.endpoint = delivery.recipient_endpoint
    WHERE delivery.message_id = requested_message AND delivery.recipient_endpoint !~ ('^' || chr(30) || 'role:')
    GROUP BY artifact.value, binding.principal_id;
    INSERT INTO attachment.recipient_grant_endpoints (artifact_id, recipient_principal_id, recipient_endpoint, recipient_machine_id, ownership_generation, message_id)
    SELECT artifact.value::uuid, binding.principal_id, delivery.recipient_endpoint, binding.machine_id, binding.ownership_generation, requested_message
    FROM jsonb_array_elements_text(requested_artifacts) AS artifact(value)
    CROSS JOIN relay.mail_deliveries AS delivery
    JOIN attachment.endpoint_principals AS binding ON binding.endpoint = delivery.recipient_endpoint
    WHERE delivery.message_id = requested_message AND delivery.recipient_endpoint !~ ('^' || chr(30) || 'role:');
    RETURN artifact_count;
END
$function$;

CREATE OR REPLACE FUNCTION attachment.authorize_download(
    requested_principal uuid, requested_lookup uuid, requested_generation bigint, requested_artifact uuid
)
RETURNS TABLE (artifact_id uuid, project_id uuid, storage_path text, size_bytes bigint, sha256 text,
               display_name text, media_type text, ready_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER STABLE SET search_path = pg_catalog
AS $function$
BEGIN
    IF NOT attachment.device_authority_current(requested_principal, requested_lookup, requested_generation) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'attachment download is not authorized';
    END IF;
    RETURN QUERY
    SELECT upload.artifact_id, upload.project_id, ready.storage_path, upload.size_bytes, upload.sha256::text,
           upload.display_name, upload.media_type, upload.ready_at
    FROM attachment.uploads AS upload
    JOIN attachment.ready_artifacts AS ready ON ready.artifact_id = upload.artifact_id
    JOIN attachment.ready_blob_manifest AS manifest ON manifest.storage_path = ready.storage_path
    WHERE upload.artifact_id = requested_artifact AND upload.state = 'ready'
      AND manifest.size_bytes = upload.size_bytes AND manifest.sha256::text = upload.sha256::text
      AND (EXISTS (SELECT 1 FROM attachment.recipient_grants AS recipient
                  WHERE recipient.artifact_id = upload.artifact_id AND recipient.recipient_principal_id = requested_principal)
           OR EXISTS (
               SELECT 1 FROM attachment.message_artifacts AS artifact
               JOIN relay.mail_deliveries AS delivery ON delivery.message_id = artifact.message_id
               JOIN relay.mail_role_bindings AS binding ON delivery.recipient_endpoint = chr(30) || 'role:' || binding.role
               JOIN relay.mail_endpoints AS endpoint ON endpoint.endpoint = binding.session_endpoint
               JOIN attachment.endpoint_principals AS principal ON principal.endpoint = endpoint.endpoint
               WHERE artifact.artifact_id = upload.artifact_id
                 AND principal.principal_id = requested_principal
                 AND principal.credential_lookup_id = requested_lookup AND principal.credential_generation = requested_generation
                 AND principal.machine_id = binding.machine_id AND principal.ownership_generation = binding.ownership_generation
                 AND endpoint.machine_id = binding.machine_id AND endpoint.ownership_generation = binding.ownership_generation
                 AND endpoint.lease_until > statement_timestamp() AND binding.lease_until > statement_timestamp()
           ))
      AND EXISTS (SELECT 1 FROM auth.capability_grants AS capability_grant
                  WHERE capability_grant.principal_id = requested_principal AND capability_grant.revoked_at IS NULL
                    AND capability_grant.capability = 'attachment.download'
                    AND ((capability_grant.scope = 'project' AND capability_grant.project_id = upload.project_id)
                         OR (capability_grant.scope = 'all_projects' AND capability_grant.project_id IS NULL)));
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'attachment download is not authorized';
    END IF;
END
$function$;

-- Evidence sources use the same current, fenced role binding as attachment
-- downloads.  A durable delivery grants no standing principal entitlement:
-- it is visible only while the role has an active session whose principal,
-- machine and ownership generation still agree.
CREATE OR REPLACE FUNCTION brain.authorize_evidence_source(
    requested_principal uuid,
    requested_kind text,
    requested_project uuid,
    requested_resource uuid,
    requested_revision bigint
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
    JOIN relay.projects AS project ON project.id = requested_project AND project.merged_into IS NULL
    WHERE principal.id = requested_principal AND principal.disabled_at IS NULL
      AND (
        (requested_kind = 'message' AND requested_revision IS NULL
         AND EXISTS (
             SELECT 1
             FROM auth.capability_grants AS capability_grant
             WHERE capability_grant.principal_id = requested_principal
               AND capability_grant.revoked_at IS NULL
               AND capability_grant.capability = 'conversation.receive'
               AND ((capability_grant.scope = 'project' AND capability_grant.project_id = requested_project)
                    OR (capability_grant.scope = 'all_projects' AND capability_grant.project_id IS NULL))
         )
         AND EXISTS (
             SELECT 1
             FROM relay.mail_messages AS message
             JOIN attachment.conversation_projects AS binding
               ON binding.conversation_id = message.conversation_id AND binding.project_id = requested_project
             WHERE message.id = requested_resource
               AND (EXISTS (
                       SELECT 1 FROM attachment.endpoint_principals AS endpoint
                       WHERE endpoint.endpoint = message.from_endpoint
                         AND endpoint.principal_id = requested_principal
                    )
                    OR EXISTS (
                       SELECT 1
                       FROM relay.mail_deliveries AS delivery
                       JOIN attachment.endpoint_principals AS endpoint
                         ON endpoint.endpoint = delivery.recipient_endpoint
                       WHERE delivery.message_id = message.id
                         AND endpoint.principal_id = requested_principal
                    )
                    OR EXISTS (
                       SELECT 1
                       FROM relay.mail_deliveries AS delivery
                       JOIN relay.mail_role_bindings AS role_binding
                         ON delivery.recipient_endpoint = chr(30) || 'role:' || role_binding.role
                       JOIN relay.mail_endpoints AS endpoint ON endpoint.endpoint = role_binding.session_endpoint
                       JOIN attachment.endpoint_principals AS recipient_endpoint ON recipient_endpoint.endpoint = endpoint.endpoint
                       WHERE delivery.message_id = message.id
                         AND recipient_endpoint.principal_id = requested_principal
                         AND recipient_endpoint.machine_id = role_binding.machine_id
                         AND recipient_endpoint.ownership_generation = role_binding.ownership_generation
                         AND endpoint.machine_id = role_binding.machine_id
                         AND endpoint.ownership_generation = role_binding.ownership_generation
                         AND endpoint.lease_until > statement_timestamp()
                         AND role_binding.lease_until > statement_timestamp()
                    ))
         ))
        OR
        (requested_kind = 'attachment' AND requested_revision IS NULL
         AND EXISTS (
             SELECT 1
             FROM auth.capability_grants AS capability_grant
             WHERE capability_grant.principal_id = requested_principal
               AND capability_grant.revoked_at IS NULL
               AND capability_grant.capability = 'attachment.download'
               AND ((capability_grant.scope = 'project' AND capability_grant.project_id = requested_project)
                    OR (capability_grant.scope = 'all_projects' AND capability_grant.project_id IS NULL))
         )
         AND EXISTS (
             SELECT 1
             FROM attachment.uploads AS upload
             JOIN attachment.ready_artifacts AS ready ON ready.artifact_id = upload.artifact_id
             JOIN attachment.ready_blob_manifest AS manifest ON manifest.storage_path = ready.storage_path
             WHERE upload.artifact_id = requested_resource
               AND upload.project_id = requested_project
               AND upload.state = 'ready'
               AND manifest.size_bytes = upload.size_bytes
               AND manifest.sha256::text = upload.sha256::text
               AND (upload.principal_id = requested_principal OR EXISTS (
                   SELECT 1 FROM attachment.recipient_grants AS recipient
                   WHERE recipient.artifact_id = upload.artifact_id
                     AND recipient.recipient_principal_id = requested_principal
               ) OR EXISTS (
                   SELECT 1
                   FROM attachment.message_artifacts AS artifact
                   JOIN relay.mail_deliveries AS delivery ON delivery.message_id = artifact.message_id
                   JOIN relay.mail_role_bindings AS role_binding
                     ON delivery.recipient_endpoint = chr(30) || 'role:' || role_binding.role
                   JOIN relay.mail_endpoints AS endpoint ON endpoint.endpoint = role_binding.session_endpoint
                   JOIN attachment.endpoint_principals AS recipient_endpoint ON recipient_endpoint.endpoint = endpoint.endpoint
                   WHERE artifact.artifact_id = upload.artifact_id
                     AND recipient_endpoint.principal_id = requested_principal
                     AND recipient_endpoint.machine_id = role_binding.machine_id
                     AND recipient_endpoint.ownership_generation = role_binding.ownership_generation
                     AND endpoint.machine_id = role_binding.machine_id
                     AND endpoint.ownership_generation = role_binding.ownership_generation
                     AND endpoint.lease_until > statement_timestamp()
                     AND role_binding.lease_until > statement_timestamp()
               ))
         ))
        OR
        (requested_kind = 'memory' AND requested_revision >= 1
         AND EXISTS (
             SELECT 1
             FROM auth.capability_grants AS capability_grant
             WHERE capability_grant.principal_id = requested_principal
               AND capability_grant.revoked_at IS NULL
               AND capability_grant.capability = 'memory.read'
               AND ((capability_grant.scope = 'project' AND capability_grant.project_id = requested_project)
                    OR (capability_grant.scope = 'all_projects' AND capability_grant.project_id IS NULL))
         )
         AND EXISTS (
             SELECT 1
             FROM brain.memory_items AS item
             JOIN brain.scopes AS scope ON scope.id = item.scope_id AND scope.project_id = requested_project
             JOIN brain.memory_revisions AS revision
               ON revision.item_id = item.id AND revision.revision = requested_revision
             WHERE item.id = requested_resource
               AND NOT EXISTS (
                   SELECT 1 FROM brain.memory_quarantines AS quarantine
                   WHERE quarantine.item_id = item.id AND quarantine.released_at IS NULL
               )
         ))
      )
)
$function$;

CREATE OR REPLACE FUNCTION brain.lock_evidence_source(
    requested_principal uuid,
    requested_kind text,
    requested_project uuid,
    requested_resource uuid,
    requested_revision bigint
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
SET search_path = pg_catalog
AS $function$
DECLARE
    source_owner uuid;
BEGIN
    IF requested_kind = 'message' AND requested_revision IS NULL THEN
        PERFORM 1
        FROM relay.mail_messages AS message
        JOIN attachment.conversation_projects AS binding
          ON binding.conversation_id = message.conversation_id AND binding.project_id = requested_project
        WHERE message.id = requested_resource;
        IF NOT FOUND THEN
            RETURN false;
        END IF;
        PERFORM 1
        FROM attachment.endpoint_principals AS endpoint
        WHERE endpoint.principal_id = requested_principal
          AND (endpoint.endpoint = (SELECT message.from_endpoint FROM relay.mail_messages AS message WHERE message.id = requested_resource)
               OR endpoint.endpoint IN (SELECT delivery.recipient_endpoint FROM relay.mail_deliveries AS delivery WHERE delivery.message_id = requested_resource))
        FOR SHARE OF endpoint;
        IF NOT FOUND THEN
            PERFORM 1
            FROM relay.mail_deliveries AS delivery
            JOIN relay.mail_role_bindings AS role_binding
              ON delivery.recipient_endpoint = chr(30) || 'role:' || role_binding.role
            JOIN relay.mail_endpoints AS endpoint ON endpoint.endpoint = role_binding.session_endpoint
            JOIN attachment.endpoint_principals AS recipient_endpoint ON recipient_endpoint.endpoint = endpoint.endpoint
            WHERE delivery.message_id = requested_resource
              AND recipient_endpoint.principal_id = requested_principal
              AND recipient_endpoint.machine_id = role_binding.machine_id
              AND recipient_endpoint.ownership_generation = role_binding.ownership_generation
              AND endpoint.machine_id = role_binding.machine_id
              AND endpoint.ownership_generation = role_binding.ownership_generation
              AND endpoint.lease_until > statement_timestamp()
              AND role_binding.lease_until > statement_timestamp()
            FOR SHARE OF delivery, role_binding, endpoint, recipient_endpoint;
            IF NOT FOUND THEN
                RETURN false;
            END IF;
        END IF;
    ELSIF requested_kind = 'attachment' AND requested_revision IS NULL THEN
        SELECT upload.principal_id INTO source_owner
        FROM attachment.uploads AS upload
        JOIN attachment.ready_artifacts AS ready ON ready.artifact_id = upload.artifact_id
        JOIN attachment.ready_blob_manifest AS manifest ON manifest.storage_path = ready.storage_path
        WHERE upload.artifact_id = requested_resource AND upload.project_id = requested_project
          AND upload.state = 'ready' AND manifest.size_bytes = upload.size_bytes
          AND manifest.sha256::text = upload.sha256::text
        FOR SHARE OF upload, ready, manifest;
        IF NOT FOUND THEN
            RETURN false;
        END IF;
        IF source_owner <> requested_principal THEN
            PERFORM 1 FROM attachment.recipient_grants AS recipient
            WHERE recipient.artifact_id = requested_resource AND recipient.recipient_principal_id = requested_principal
            FOR SHARE OF recipient;
            IF NOT FOUND THEN
                PERFORM 1
                FROM attachment.message_artifacts AS artifact
                JOIN relay.mail_deliveries AS delivery ON delivery.message_id = artifact.message_id
                JOIN relay.mail_role_bindings AS role_binding
                  ON delivery.recipient_endpoint = chr(30) || 'role:' || role_binding.role
                JOIN relay.mail_endpoints AS endpoint ON endpoint.endpoint = role_binding.session_endpoint
                JOIN attachment.endpoint_principals AS recipient_endpoint ON recipient_endpoint.endpoint = endpoint.endpoint
                WHERE artifact.artifact_id = requested_resource
                  AND recipient_endpoint.principal_id = requested_principal
                  AND recipient_endpoint.machine_id = role_binding.machine_id
                  AND recipient_endpoint.ownership_generation = role_binding.ownership_generation
                  AND endpoint.machine_id = role_binding.machine_id
                  AND endpoint.ownership_generation = role_binding.ownership_generation
                  AND endpoint.lease_until > statement_timestamp()
                  AND role_binding.lease_until > statement_timestamp()
                FOR SHARE OF artifact, delivery, role_binding, endpoint, recipient_endpoint;
                IF NOT FOUND THEN
                    RETURN false;
                END IF;
            END IF;
        END IF;
    ELSIF requested_kind = 'memory' AND requested_revision >= 1 THEN
        PERFORM 1
        FROM brain.memory_items AS item
        JOIN brain.scopes AS scope ON scope.id = item.scope_id AND scope.project_id = requested_project
        JOIN brain.memory_revisions AS revision ON revision.item_id = item.id AND revision.revision = requested_revision
        WHERE item.id = requested_resource
        FOR SHARE OF item, scope, revision;
        IF NOT FOUND THEN
            RETURN false;
        END IF;
    ELSE
        RETURN false;
    END IF;
    RETURN brain.authorize_evidence_source(requested_principal, requested_kind, requested_project, requested_resource, requested_revision);
END
$function$;
