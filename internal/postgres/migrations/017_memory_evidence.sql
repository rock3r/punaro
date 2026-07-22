ALTER TABLE brain.memory_items
ADD COLUMN layer text NOT NULL DEFAULT 'curated'
    CONSTRAINT memory_items_layer_check CHECK (layer IN ('curated', 'evidence'));

ALTER TABLE brain.memory_revisions DROP CONSTRAINT memory_revisions_operation_check;
ALTER TABLE brain.memory_revisions ADD CONSTRAINT memory_revisions_operation_check CHECK (
    operation IN ('create', 'evidence_create', 'update', 'archive', 'restore')
);

ALTER TABLE brain.memory_changes DROP CONSTRAINT memory_changes_operation_check;
ALTER TABLE brain.memory_changes ADD CONSTRAINT memory_changes_operation_check CHECK (
    operation IN ('create', 'evidence_create', 'update', 'archive', 'restore', 'delete', 'quarantine', 'quarantine_release')
);

CREATE TABLE brain.memory_sources (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    item_id uuid NOT NULL,
    revision bigint NOT NULL CONSTRAINT memory_sources_revision_check CHECK (revision >= 1),
    ordinal smallint NOT NULL CONSTRAINT memory_sources_ordinal_check CHECK (ordinal BETWEEN 0 AND 7),
    mode text NOT NULL CONSTRAINT memory_sources_mode_check CHECK (mode IN ('copied', 'live')),
    kind text NOT NULL CONSTRAINT memory_sources_kind_check CHECK (
        kind IN ('message', 'attachment', 'memory', 'session', 'import', 'external')
    ),
    source_project_id uuid REFERENCES relay.projects(id),
    source_resource_id uuid,
    source_revision bigint CONSTRAINT memory_sources_source_revision_check CHECK (source_revision IS NULL OR source_revision >= 1),
    reference_sha256 bytea CONSTRAINT memory_sources_reference_sha256_check CHECK (
        reference_sha256 IS NULL OR octet_length(reference_sha256) = 32
    ),
    created_by uuid NOT NULL REFERENCES auth.principals(id),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT memory_sources_revision_fkey FOREIGN KEY (item_id, revision)
        REFERENCES brain.memory_revisions(item_id, revision) ON DELETE CASCADE,
    CONSTRAINT memory_sources_shape_check CHECK (
        (mode = 'copied' AND source_project_id IS NULL AND source_resource_id IS NULL
            AND source_revision IS NULL AND reference_sha256 IS NOT NULL)
        OR
        (mode = 'live' AND source_project_id IS NOT NULL AND source_resource_id IS NOT NULL
            AND reference_sha256 IS NULL
            AND ((kind = 'memory' AND source_revision IS NOT NULL)
                 OR (kind IN ('message', 'attachment') AND source_revision IS NULL)))
    ),
    CONSTRAINT memory_sources_item_revision_ordinal_key UNIQUE (item_id, revision, ordinal),
    CONSTRAINT memory_sources_exact_source_key UNIQUE NULLS NOT DISTINCT (
        item_id, revision, mode, kind, source_project_id, source_resource_id, source_revision, reference_sha256
    )
);

CREATE INDEX memory_sources_live_resource
ON brain.memory_sources (source_project_id, kind, source_resource_id, source_revision)
WHERE mode = 'live';

CREATE TABLE brain.memory_edges (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    from_item_id uuid NOT NULL,
    from_revision bigint NOT NULL CONSTRAINT memory_edges_from_revision_check CHECK (from_revision >= 1),
    ordinal smallint NOT NULL CONSTRAINT memory_edges_ordinal_check CHECK (ordinal BETWEEN 0 AND 15),
    edge_type text NOT NULL CONSTRAINT memory_edges_type_check CHECK (
        edge_type IN ('derived_from', 'supports', 'contradicts', 'supersedes')
    ),
    to_item_id uuid NOT NULL,
    to_revision bigint NOT NULL CONSTRAINT memory_edges_to_revision_check CHECK (to_revision >= 1),
    created_by uuid NOT NULL REFERENCES auth.principals(id),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT memory_edges_from_revision_fkey FOREIGN KEY (from_item_id, from_revision)
        REFERENCES brain.memory_revisions(item_id, revision) ON DELETE CASCADE,
    CONSTRAINT memory_edges_to_revision_fkey FOREIGN KEY (to_item_id, to_revision)
        REFERENCES brain.memory_revisions(item_id, revision) ON DELETE CASCADE,
    CONSTRAINT memory_edges_not_self_check CHECK (
        from_item_id <> to_item_id OR from_revision <> to_revision
    ),
    CONSTRAINT memory_edges_exact_key UNIQUE (
        from_item_id, from_revision, edge_type, to_item_id, to_revision
    ),
    CONSTRAINT memory_edges_item_revision_ordinal_key UNIQUE (from_item_id, from_revision, ordinal)
);

CREATE INDEX memory_edges_target_revision
ON brain.memory_edges (to_item_id, to_revision, edge_type, from_item_id, from_revision);

CREATE FUNCTION brain.authorize_evidence_source(
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

CREATE FUNCTION brain.lock_evidence_source(
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
            RETURN false;
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
                RETURN false;
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

ALTER TABLE audit.events DROP CONSTRAINT events_action_check;
ALTER TABLE audit.events ADD CONSTRAINT events_action_check CHECK (action IN (
    'principal.create', 'project.create', 'grant.create', 'grant.delete',
    'job.enqueue', 'job.complete', 'job.retry', 'job.fail',
    'owner.bootstrap', 'enrollment.create', 'enrollment.redeem',
    'credential.rotate', 'credential.revoke',
    'legacy.register', 'legacy.exchange', 'legacy.retire', 'legacy.disable',
    'project.identity.attach', 'project.merge.preview', 'project.merge',
    'memory.create', 'memory.evidence_create', 'memory.update', 'memory.archive', 'memory.restore', 'memory.delete',
    'memory.secret_exception.create', 'memory.secret_exception.revoke',
    'memory.secret_rescan', 'memory.quarantine', 'memory.quarantine_release'
));

DO $block$
DECLARE
    target regclass;
BEGIN
    FOREACH target IN ARRAY ARRAY['brain.memory_sources'::regclass, 'brain.memory_edges'::regclass]
    LOOP
        EXECUTE format(
            'CREATE TRIGGER application_mutation_fence BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION jobs.guard_application_mutation()',
            target
        );
    END LOOP;
END
$block$;

REVOKE ALL ON brain.memory_sources, brain.memory_edges FROM PUBLIC, punaro_app;
REVOKE ALL ON FUNCTION brain.authorize_evidence_source(uuid,text,uuid,uuid,bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION brain.lock_evidence_source(uuid,text,uuid,uuid,bigint) FROM PUBLIC;
GRANT SELECT ON brain.memory_sources, brain.memory_edges TO punaro_app;
GRANT INSERT (item_id,revision,ordinal,mode,kind,source_project_id,source_resource_id,source_revision,reference_sha256,created_by)
    ON brain.memory_sources TO punaro_app;
GRANT INSERT (from_item_id,from_revision,ordinal,edge_type,to_item_id,to_revision,created_by)
    ON brain.memory_edges TO punaro_app;
GRANT EXECUTE ON FUNCTION brain.authorize_evidence_source(uuid,text,uuid,uuid,bigint) TO punaro_app;
GRANT EXECUTE ON FUNCTION brain.lock_evidence_source(uuid,text,uuid,uuid,bigint) TO punaro_app;
