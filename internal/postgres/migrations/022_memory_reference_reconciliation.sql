CREATE FUNCTION brain.reconcile_memory_references(
    requested_principal uuid,
    requested_project uuid,
    requested_limit integer
)
RETURNS TABLE (
    alias_repairs integer,
    orphan_edges_removed integer,
    more boolean,
    change_sequence bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    canonical_id uuid;
    authority_id uuid;
    candidate_aliases uuid[] := '{}'::uuid[];
    repaired integer := 0;
    removed integer := 0;
    remaining integer;
    remaining_work boolean := false;
    next_sequence bigint := 0;
BEGIN
    IF requested_principal IS NULL OR requested_project IS NULL OR requested_limit IS NULL
       OR requested_limit < 1 OR requested_limit > 64 THEN
        RAISE EXCEPTION 'invalid memory reconciliation request' USING ERRCODE = '22023';
    END IF;

    PERFORM jobs.assert_application_mutation();

    SELECT project.id
    INTO canonical_id
    FROM relay.projects AS project
    WHERE project.id=requested_project AND project.merged_into IS NULL;
    IF canonical_id IS NULL THEN
        RETURN;
    END IF;

    SELECT COALESCE(array_agg(candidate.id ORDER BY candidate.id),'{}'::uuid[])
    INTO candidate_aliases
    FROM (
        SELECT project.id
        FROM relay.projects AS project
        LEFT JOIN relay.project_lookup_aliases AS alias
          ON alias.alias_project_id=project.id
        WHERE project.merged_into=canonical_id
          AND alias.canonical_project_id IS DISTINCT FROM canonical_id
        ORDER BY project.id
        LIMIT requested_limit
    ) AS candidate;

    PERFORM project.id
    FROM relay.projects AS project
    WHERE project.id=canonical_id OR project.id=ANY(candidate_aliases)
    ORDER BY project.id
    FOR UPDATE;

    IF NOT EXISTS (
        SELECT 1 FROM relay.projects
        WHERE id=canonical_id AND merged_into IS NULL
    ) THEN
        RETURN;
    END IF;

    SELECT capability_grant.id
    INTO authority_id
    FROM auth.principals AS principal
    JOIN auth.capability_grants AS capability_grant
      ON capability_grant.principal_id=principal.id
    WHERE principal.id=requested_principal
      AND principal.disabled_at IS NULL
      AND capability_grant.revoked_at IS NULL
      AND capability_grant.capability='memory.administer'
      AND ((capability_grant.scope='project' AND capability_grant.project_id=canonical_id)
           OR (capability_grant.scope='all_projects' AND capability_grant.project_id IS NULL))
    ORDER BY capability_grant.id
    LIMIT 1
    FOR SHARE OF principal,capability_grant;
    IF authority_id IS NULL THEN
        RETURN;
    END IF;

    INSERT INTO relay.project_lookup_aliases(alias_project_id,canonical_project_id)
    SELECT project.id,canonical_id
    FROM relay.projects AS project
    LEFT JOIN relay.project_lookup_aliases AS alias
      ON alias.alias_project_id=project.id
    WHERE project.id=ANY(candidate_aliases)
      AND project.merged_into=canonical_id
      AND alias.canonical_project_id IS DISTINCT FROM canonical_id
    ORDER BY project.id
    ON CONFLICT (alias_project_id) DO UPDATE
    SET canonical_project_id=EXCLUDED.canonical_project_id;
    GET DIAGNOSTICS repaired = ROW_COUNT;

    remaining := requested_limit-repaired;
    IF remaining > 0 THEN
        WITH candidates AS (
            SELECT edge.id
            FROM brain.memory_edges AS edge
            JOIN brain.memory_items AS source_item ON source_item.id=edge.from_item_id
            JOIN brain.scopes AS source_scope ON source_scope.id=source_item.scope_id
            JOIN relay.projects AS source_project ON source_project.id=source_scope.project_id
            WHERE ((source_project.id=canonical_id AND source_project.merged_into IS NULL)
                   OR source_project.merged_into=canonical_id)
              AND NOT EXISTS (
                  SELECT 1
                  FROM brain.memory_revisions AS target_revision
                  WHERE target_revision.item_id=edge.to_item_id
                    AND target_revision.revision=edge.to_revision
              )
            ORDER BY edge.id
            LIMIT remaining
            FOR UPDATE OF edge
        )
        DELETE FROM brain.memory_edges AS edge
        USING candidates
        WHERE edge.id=candidates.id;
        GET DIAGNOSTICS removed = ROW_COUNT;
    END IF;

    IF repaired+removed > 0 THEN
        UPDATE relay.projects
        SET identity_generation=identity_generation+CASE WHEN repaired>0 THEN 1 ELSE 0 END,
            content_generation=content_generation+1
        WHERE id=canonical_id;

        SELECT advanced.change_sequence
        INTO next_sequence
        FROM jobs.advance_change_sequence() AS advanced;

        INSERT INTO audit.events(
            principal_id,project_id,action,outcome,target_kind,target_id
        ) VALUES (
            requested_principal,canonical_id,'memory.reconcile','succeeded','project',canonical_id
        );
    END IF;

    IF cardinality(candidate_aliases)=requested_limit
       OR repaired+removed=requested_limit THEN
        SELECT EXISTS (
               SELECT 1
               FROM relay.projects AS project
               LEFT JOIN relay.project_lookup_aliases AS alias
                 ON alias.alias_project_id=project.id
               WHERE project.merged_into=canonical_id
                 AND alias.canonical_project_id IS DISTINCT FROM canonical_id
           ) OR EXISTS (
               SELECT 1
               FROM brain.memory_edges AS edge
               JOIN brain.memory_items AS source_item ON source_item.id=edge.from_item_id
               JOIN brain.scopes AS source_scope ON source_scope.id=source_item.scope_id
               JOIN relay.projects AS source_project ON source_project.id=source_scope.project_id
               WHERE ((source_project.id=canonical_id AND source_project.merged_into IS NULL)
                      OR source_project.merged_into=canonical_id)
              AND NOT EXISTS (
                  SELECT 1
                  FROM brain.memory_revisions AS target_revision
                  WHERE target_revision.item_id=edge.to_item_id
                    AND target_revision.revision=edge.to_revision
              )
           )
        INTO remaining_work;
    END IF;

    RETURN QUERY
    SELECT repaired,removed,remaining_work,next_sequence;
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
    'memory.create', 'memory.evidence_create', 'memory.update',
    'memory.archive', 'memory.restore', 'memory.delete',
    'memory.secret_exception.create', 'memory.secret_exception.revoke',
    'memory.secret_rescan', 'memory.quarantine', 'memory.quarantine_release',
    'memory.proposal.create', 'memory.proposal.approve', 'memory.proposal.reject',
    'memory.proposal.expire', 'memory.proposal.prune', 'memory.reconcile'
));

REVOKE ALL ON FUNCTION brain.reconcile_memory_references(uuid,uuid,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION brain.reconcile_memory_references(uuid,uuid,integer) TO punaro_app;
