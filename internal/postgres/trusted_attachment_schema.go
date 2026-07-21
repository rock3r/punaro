package postgres

import "context"

// trustedAttachmentControlsAvailable verifies the complete schema-v10
// publication authority. Migration checksums prove provenance; these catalog
// checks detect post-migration drift in storage, routines, ownership, and ACLs.
func trustedAttachmentControlsAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `
WITH objects AS (
    SELECT to_regclass('attachment.uploads') AS uploads_oid,
           to_regclass('attachment.ready_artifacts') AS ready_oid,
           to_regclass('attachment.global_quota') AS global_oid,
           to_regclass('attachment.project_quotas') AS project_oid,
           to_regclass('attachment.principal_quotas') AS principal_oid,
           to_regclass('attachment.uploads_project_state') AS project_state_index_oid,
           to_regclass('attachment.uploads_reconcile_order') AS reconcile_index_oid,
           to_regclass('attachment.recipient_grants') AS recipient_grants_oid,
           to_regprocedure('attachment.reserve_upload(uuid,uuid,uuid,bytea,bigint,text,text,text,interval)') AS reserve_oid,
           to_regprocedure('attachment.claim_upload(uuid,uuid,interval)') AS claim_oid,
           to_regprocedure('attachment.publish_upload(uuid,uuid,bigint,uuid,text,bigint,text)') AS publish_oid,
           to_regprocedure('attachment.begin_reap_upload(uuid)') AS begin_reap_oid,
           to_regprocedure('attachment.release_expired_upload(uuid,uuid)') AS release_oid,
           to_regprocedure('attachment.mark_corrupt(uuid)') AS corrupt_oid,
           to_regprocedure('attachment.reconcile_candidates(text,timestamp with time zone,uuid,integer)') AS reconcile_oid,
           to_regprocedure('attachment.project_has_records(uuid,uuid)') AS project_records_oid
), expected_columns(relation_name, column_name, type_name, type_modifier, required) AS (
    VALUES
      ('attachment.uploads','artifact_id','uuid',-1,true),
      ('attachment.uploads','project_id','uuid',-1,true),
      ('attachment.uploads','principal_id','uuid',-1,true),
      ('attachment.uploads','timeline_id','uuid',-1,true),
      ('attachment.uploads','idempotency_key','uuid',-1,true),
      ('attachment.uploads','request_sha256','character',68,true),
      ('attachment.uploads','size_bytes','bigint',-1,true),
      ('attachment.uploads','sha256','character',68,true),
      ('attachment.uploads','display_name','text',-1,true),
      ('attachment.uploads','media_type','text',-1,true),
      ('attachment.uploads','state','text',-1,true),
      ('attachment.uploads','attempt_generation','bigint',-1,true),
      ('attachment.uploads','claim_token','uuid',-1,false),
      ('attachment.uploads','claim_until','timestamp with time zone',-1,false),
      ('attachment.uploads','created_at','timestamp with time zone',-1,true),
      ('attachment.uploads','expires_at','timestamp with time zone',-1,true),
      ('attachment.uploads','ready_at','timestamp with time zone',-1,false),
      ('attachment.ready_artifacts','artifact_id','uuid',-1,true),
      ('attachment.ready_artifacts','storage_path','text',-1,true),
      ('attachment.ready_artifacts','published_at','timestamp with time zone',-1,true),
      ('attachment.global_quota','singleton','boolean',-1,true),
      ('attachment.global_quota','max_artifact_bytes','bigint',-1,true),
      ('attachment.global_quota','max_total_bytes','bigint',-1,true),
      ('attachment.global_quota','max_active_uploads','integer',-1,true),
      ('attachment.global_quota','default_project_bytes','bigint',-1,true),
      ('attachment.global_quota','default_project_uploads','integer',-1,true),
      ('attachment.global_quota','default_principal_bytes','bigint',-1,true),
      ('attachment.global_quota','default_principal_uploads','integer',-1,true),
      ('attachment.global_quota','reserved_bytes','bigint',-1,true),
      ('attachment.global_quota','used_bytes','bigint',-1,true),
      ('attachment.global_quota','reserved_uploads','integer',-1,true),
      ('attachment.global_quota','ready_artifacts','integer',-1,true),
      ('attachment.project_quotas','project_id','uuid',-1,true),
      ('attachment.project_quotas','max_bytes','bigint',-1,true),
      ('attachment.project_quotas','max_active_uploads','integer',-1,true),
      ('attachment.project_quotas','reserved_bytes','bigint',-1,true),
      ('attachment.project_quotas','used_bytes','bigint',-1,true),
      ('attachment.project_quotas','reserved_uploads','integer',-1,true),
      ('attachment.project_quotas','ready_artifacts','integer',-1,true),
      ('attachment.principal_quotas','principal_id','uuid',-1,true),
      ('attachment.principal_quotas','max_bytes','bigint',-1,true),
      ('attachment.principal_quotas','max_active_uploads','integer',-1,true),
      ('attachment.principal_quotas','reserved_bytes','bigint',-1,true),
      ('attachment.principal_quotas','used_bytes','bigint',-1,true),
      ('attachment.principal_quotas','reserved_uploads','integer',-1,true),
      ('attachment.principal_quotas','ready_artifacts','integer',-1,true)
), actual_columns AS (
    SELECT attribute.attrelid::regclass::text AS relation_name, attribute.attname AS column_name,
           attribute.atttypid::regtype::text AS type_name, attribute.atttypmod AS type_modifier,
           attribute.attnotnull AS required
    FROM pg_attribute AS attribute, objects
    WHERE attribute.attrelid = ANY(ARRAY[uploads_oid,ready_oid,global_oid,project_oid,principal_oid])
      AND attribute.attnum > 0 AND NOT attribute.attisdropped
), expected_routines(oid, body_hash, volatility) AS (
    SELECT expected.* FROM objects, LATERAL (VALUES
      (reserve_oid,'503c810da6c7090c8bdc306f474c161d','v'::"char"),
      (claim_oid,CASE WHEN recipient_grants_oid IS NULL
                      THEN '475ac4e1df29cabe6dbcae9e83038891'
                      ELSE 'a20da734d30b78d9e6868c27094cd549' END,'v'::"char"),
      (publish_oid,CASE WHEN recipient_grants_oid IS NULL
                        THEN 'a309ef5966178bd6fef53435be8c215e'
                        ELSE 'af7e5394046227aa006c7820fe97d1d8' END,'v'::"char"),
      (begin_reap_oid,'fc58a668e122b22102bd26cee052e213','v'::"char"),
      (release_oid,CASE WHEN recipient_grants_oid IS NULL
                        THEN '923f1b8e0dfa076623fe41f8f4dd059a'
                        ELSE '2a0a87320eb4124de1f1f65ecd629662' END,'v'::"char"),
      (corrupt_oid,CASE WHEN recipient_grants_oid IS NULL
                        THEN 'c4949387c79f3843bef73ddb408f9db2'
                        ELSE '51e6b83ed153fcce5b53dbddc37056b8' END,'v'::"char"),
      (reconcile_oid,'25df2c05deb346a8df8a86349a00a478','s'::"char"),
      (project_records_oid,'e7a7735e0d1b78a0766489a90a0b87c7','s'::"char")
    ) AS expected(oid,body_hash,volatility)
), routine_safety AS (
    SELECT count(*) = 8
       AND bool_and(pg_get_userbyid(proc.proowner) = 'punaro_owner')
       AND bool_and(language.lanname IN ('sql','plpgsql'))
       AND bool_and(proc.prokind = 'f' AND proc.prosecdef AND proc.provolatile = expected.volatility)
       AND bool_and(proc.proconfig = ARRAY['search_path=pg_catalog']::text[])
       AND bool_and(md5(btrim(proc.prosrc)) = expected.body_hash) AS exact
    FROM expected_routines AS expected
    JOIN pg_proc AS proc ON proc.oid = expected.oid
    JOIN pg_language AS language ON language.oid = proc.prolang
), routine_acl AS (
    SELECT count(*) = 16 AND bool_and(acl.privilege_type = 'EXECUTE' AND NOT acl.is_grantable)
       AND bool_and(grantee.rolname IN ('punaro_owner','punaro_app')) AS exact
    FROM expected_routines AS expected
    JOIN pg_proc AS proc ON proc.oid = expected.oid
    CROSS JOIN LATERAL aclexplode(COALESCE(proc.proacl,acldefault('f',proc.proowner))) AS acl
    LEFT JOIN pg_roles AS grantee ON grantee.oid = acl.grantee
), table_safety AS (
    SELECT count(*) = 5 AND bool_and(pg_get_userbyid(relation.relowner) = 'punaro_owner')
       AND bool_and(relation.relkind = 'r' AND NOT relation.relrowsecurity AND NOT relation.relforcerowsecurity) AS exact
    FROM pg_class AS relation, objects
    WHERE relation.oid = ANY(ARRAY[uploads_oid,ready_oid,global_oid,project_oid,principal_oid])
), table_acl AS (
    SELECT count(*) = 40 AND bool_and(grantee.rolname = 'punaro_owner' AND NOT acl.is_grantable) AS exact
    FROM pg_class AS relation, objects
    CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) AS acl
    LEFT JOIN pg_roles AS grantee ON grantee.oid = acl.grantee
    WHERE relation.oid = ANY(ARRAY[uploads_oid,ready_oid,global_oid,project_oid,principal_oid])
), constraint_safety AS (
    SELECT count(*) = 50 AND bool_and(convalidated AND NOT condeferrable AND NOT condeferred)
       AND count(*) FILTER (WHERE contype = 'f' AND confupdtype = 'a' AND confdeltype = 'a' AND confmatchtype = 's') = 6 AS exact
    FROM pg_constraint, objects
    WHERE conrelid = ANY(ARRAY[uploads_oid,ready_oid,global_oid,project_oid,principal_oid])
      AND contype <> 'n'
), index_safety AS (
    SELECT count(*) = 9
       AND bool_and(indisvalid AND indisready)
       AND bool_or(indexrelid = project_state_index_oid AND indkey::text = '2 11 1' AND indexprs IS NULL AND indpred IS NULL)
       AND bool_or(indexrelid = reconcile_index_oid AND indkey::text = '11 16 1' AND indexprs IS NULL AND indpred IS NULL) AS exact
    FROM pg_index, objects
    WHERE indrelid = ANY(ARRAY[uploads_oid,ready_oid,global_oid,project_oid,principal_oid])
)
SELECT uploads_oid IS NOT NULL AND ready_oid IS NOT NULL AND global_oid IS NOT NULL
   AND project_oid IS NOT NULL AND principal_oid IS NOT NULL
   AND project_state_index_oid IS NOT NULL AND reconcile_index_oid IS NOT NULL
   AND reserve_oid IS NOT NULL AND claim_oid IS NOT NULL AND publish_oid IS NOT NULL
   AND begin_reap_oid IS NOT NULL AND release_oid IS NOT NULL AND corrupt_oid IS NOT NULL AND reconcile_oid IS NOT NULL AND project_records_oid IS NOT NULL
   AND table_safety.exact AND table_acl.exact AND routine_safety.exact AND routine_acl.exact
   AND constraint_safety.exact AND index_safety.exact
	AND EXISTS (
	    SELECT 1 FROM pg_constraint
	    WHERE conrelid = uploads_oid AND conname = 'uploads_size_bytes_check' AND contype = 'c'
	      AND conkey = ARRAY[7]::smallint[] AND convalidated
	      AND pg_get_expr(conbin,conrelid) = '((size_bytes >= 1) AND (size_bytes <= ''17179869184''::bigint))'
	)
	AND EXISTS (
	    SELECT 1 FROM pg_constraint
	    WHERE conrelid = uploads_oid AND conname = 'uploads_state_check' AND contype = 'c'
	      AND conkey = ARRAY[11]::smallint[] AND convalidated
	      AND pg_get_expr(conbin,conrelid) = '(state = ANY (ARRAY[''reserved''::text, ''reaping''::text, ''ready''::text, ''corrupt''::text, ''expired''::text]))'
	)
   AND NOT EXISTS (SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns)
   AND NOT EXISTS (SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)
   AND NOT EXISTS (
       SELECT 1 FROM pg_class AS relation, objects
       WHERE relation.oid = ANY(ARRAY[uploads_oid,ready_oid,global_oid,project_oid,principal_oid])
         AND (has_table_privilege('punaro_app',relation.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
              OR has_any_column_privilege('punaro_app',relation.oid,'SELECT,INSERT,UPDATE,REFERENCES'))
   )
   AND NOT EXISTS (
       SELECT 1 FROM expected_routines AS expected
       WHERE NOT has_function_privilege('punaro_app',expected.oid,'EXECUTE')
   )
FROM objects, table_safety, table_acl, routine_safety, routine_acl, constraint_safety, index_safety`).Scan(&available)
	return available, err
}
