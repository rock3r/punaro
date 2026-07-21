package postgres

import "context"

// attachmentDeletionControlsAvailable verifies the exact schema-v12
// tombstone and token-fenced physical-GC authority. The application role has
// execute-only access to the four narrow routines and no table authority.
func attachmentDeletionControlsAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `
WITH objects AS (
    SELECT to_regclass('attachment.deletions') AS deletions_oid,
           to_regclass('attachment.deletions_gc_order') AS gc_index_oid,
           to_regprocedure('attachment.tombstone_artifact(uuid,uuid,bigint,uuid,uuid,bytea)') AS tombstone_oid,
           to_regprocedure('attachment.claim_artifact_gc(uuid,interval)') AS claim_oid,
           to_regprocedure('attachment.finalize_artifact_gc(uuid,bigint,uuid)') AS finalize_oid,
           to_regprocedure('attachment.orphan_gc_allowed(uuid)') AS orphan_oid
), expected_columns(column_name,type_name,type_modifier,required) AS (
    VALUES
      ('artifact_id','uuid',-1,true),
      ('project_id','uuid',-1,true),
      ('owner_principal_id','uuid',-1,true),
      ('storage_path','text',-1,true),
      ('size_bytes','bigint',-1,true),
      ('sha256','character',68,true),
      ('state','text',-1,true),
      ('tombstoned_at','timestamp with time zone',-1,true),
      ('gc_after','timestamp with time zone',-1,true),
      ('gc_generation','bigint',-1,true),
      ('gc_token','uuid',-1,false),
      ('gc_lease_until','timestamp with time zone',-1,false),
      ('deleted_at','timestamp with time zone',-1,false)
), actual_columns AS (
    SELECT attribute.attname, attribute.atttypid::regtype::text,
           attribute.atttypmod, attribute.attnotnull
    FROM pg_attribute AS attribute, objects
    WHERE attribute.attrelid = deletions_oid
      AND attribute.attnum > 0 AND NOT attribute.attisdropped
), expected_constraints(constraint_name,constraint_type,column_keys,is_deferrable,is_deferred) AS (
    VALUES
      ('deletions_pkey','p','{1}',false,false),
      ('deletions_storage_path_key','u','{4}',false,false),
      ('deletions_size_bytes_check','c','{5}',false,false),
      ('deletions_sha256_check','c','{6}',false,false),
      ('deletions_state_check','c','{7}',false,false),
      ('deletions_storage_path_check','c','{4,1}',false,false),
      ('deletions_gc_after_check','c','{9,8}',false,false),
      ('deletions_gc_generation_check','c','{10}',false,false),
      ('deletions_lifecycle_check','c','{7,11,12,13}',false,false)
), actual_constraints AS (
    SELECT constraint_row.conname, constraint_row.contype::text,
           constraint_row.conkey::text, constraint_row.condeferrable,
           constraint_row.condeferred
    FROM pg_constraint AS constraint_row, objects
    WHERE constraint_row.conrelid = deletions_oid
      AND constraint_row.contype <> 'n' AND constraint_row.convalidated
), expected_checks(constraint_name,migration_expression,restored_expression) AS (
    VALUES
      ('deletions_size_bytes_check','((size_bytes >= 1) AND (size_bytes <= ''17179869184''::bigint))','((size_bytes >= 1) AND (size_bytes <= ''17179869184''::bigint))'),
      ('deletions_sha256_check','(sha256 ~ ''^[0-9a-f]{64}$''::text)','(sha256 ~ ''^[0-9a-f]{64}$''::text)'),
      ('deletions_state_check','(state = ANY (ARRAY[''tombstoned''::text, ''gc_claimed''::text, ''deleted''::text]))','(state = ANY (ARRAY[''tombstoned''::text, ''gc_claimed''::text, ''deleted''::text]))'),
      ('deletions_storage_path_check','(storage_path = ((''ready/''::text || (artifact_id)::text) || ''.blob''::text))','(storage_path = ((''ready/''::text || (artifact_id)::text) || ''.blob''::text))'),
      ('deletions_gc_after_check','(gc_after >= tombstoned_at)','(gc_after >= tombstoned_at)'),
      ('deletions_gc_generation_check','(gc_generation >= 0)','(gc_generation >= 0)'),
      ('deletions_lifecycle_check','((((state = ''tombstoned''::text) AND (gc_token IS NULL) AND (gc_lease_until IS NULL) AND (deleted_at IS NULL)) OR ((state = ''gc_claimed''::text) AND (gc_token IS NOT NULL) AND (gc_lease_until IS NOT NULL) AND (deleted_at IS NULL))) OR ((state = ''deleted''::text) AND (gc_token IS NOT NULL) AND (gc_lease_until IS NULL) AND (deleted_at IS NOT NULL)))','(((state = ''tombstoned''::text) AND (gc_token IS NULL) AND (gc_lease_until IS NULL) AND (deleted_at IS NULL)) OR ((state = ''gc_claimed''::text) AND (gc_token IS NOT NULL) AND (gc_lease_until IS NOT NULL) AND (deleted_at IS NULL)) OR ((state = ''deleted''::text) AND (gc_token IS NOT NULL) AND (gc_lease_until IS NULL) AND (deleted_at IS NOT NULL)))')
), check_safety AS (
    SELECT count(*) = 7 AND bool_and(
        constraint_row.convalidated AND NOT constraint_row.condeferrable AND NOT constraint_row.condeferred
        AND pg_get_expr(constraint_row.conbin,constraint_row.conrelid)
            IN (expected.migration_expression,expected.restored_expression)
    ) AS exact
    FROM expected_checks AS expected CROSS JOIN objects
    JOIN pg_constraint AS constraint_row
      ON constraint_row.conrelid = deletions_oid
     AND constraint_row.conname = expected.constraint_name
     AND constraint_row.contype = 'c'
), expected_indexes(index_name,column_keys,is_unique,is_primary) AS (
    VALUES
      ('deletions_pkey','1',true,true),
      ('deletions_storage_path_key','4',true,false),
      ('deletions_gc_order','7 9 1',false,false)
), actual_indexes AS (
    SELECT index_class.relname, index_row.indkey::text,
           index_row.indisunique, index_row.indisprimary
    FROM pg_index AS index_row
    JOIN pg_class AS index_class ON index_class.oid = index_row.indexrelid, objects
    WHERE index_row.indrelid = deletions_oid
      AND index_row.indisvalid AND index_row.indisready
      AND index_row.indpred IS NULL AND index_row.indexprs IS NULL
), expected_routines(oid,body_hash,result_type,returns_set,language_name,volatility) AS (
    SELECT expected.* FROM objects, LATERAL (VALUES
      (tombstone_oid,'b35bc0a6a2bea7243bf9793730389833','record',true,'plpgsql','v'),
      (claim_oid,'f9118b6ca10485fb4b764ee8066d950e','record',true,'plpgsql','v'),
      (finalize_oid,'92180383d2ef021d59470babee7c879a','record',true,'plpgsql','v'),
      (orphan_oid,'c88c556c0242673bd1694025bd414057','boolean',false,'sql','s')
    ) AS expected(oid,body_hash,result_type,returns_set,language_name,volatility)
), routine_safety AS (
    SELECT count(*) = 4
       AND bool_and(pg_get_userbyid(proc.proowner) = 'punaro_owner')
       AND bool_and(language.lanname = expected.language_name)
       AND bool_and(proc.prokind = 'f' AND proc.prosecdef AND proc.provolatile = expected.volatility)
       AND bool_and(proc.proconfig = ARRAY['search_path=pg_catalog']::text[])
       AND bool_and(NOT proc.proisstrict AND NOT proc.proleakproof AND proc.proparallel = 'u' AND proc.provariadic = 0)
       AND bool_and(proc.prorettype::regtype::text = expected.result_type AND proc.proretset = expected.returns_set)
       AND bool_and(md5(btrim(proc.prosrc)) = expected.body_hash) AS exact
    FROM expected_routines AS expected
    JOIN pg_proc AS proc ON proc.oid = expected.oid
    JOIN pg_language AS language ON language.oid = proc.prolang
), routine_acl AS (
    SELECT count(*) = 8
       AND bool_and(acl.privilege_type = 'EXECUTE' AND NOT acl.is_grantable)
       AND bool_and(grantee.rolname IN ('punaro_owner','punaro_app')) AS exact
    FROM expected_routines AS expected
    JOIN pg_proc AS proc ON proc.oid = expected.oid
    CROSS JOIN LATERAL aclexplode(COALESCE(proc.proacl,acldefault('f',proc.proowner))) AS acl
    LEFT JOIN pg_roles AS grantee ON grantee.oid = acl.grantee
), table_acl AS (
    SELECT count(*) = 8
       AND bool_and(grantee.rolname = 'punaro_owner' AND NOT acl.is_grantable) AS exact
    FROM pg_class AS relation, objects
    CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) AS acl
    LEFT JOIN pg_roles AS grantee ON grantee.oid = acl.grantee
    WHERE relation.oid = deletions_oid
)
SELECT deletions_oid IS NOT NULL AND gc_index_oid IS NOT NULL
   AND tombstone_oid IS NOT NULL AND claim_oid IS NOT NULL AND finalize_oid IS NOT NULL AND orphan_oid IS NOT NULL
   AND pg_get_userbyid(relation.relowner) = 'punaro_owner'
   AND relation.relkind = 'r' AND relation.relpersistence = 'p'
   AND NOT relation.relrowsecurity AND NOT relation.relforcerowsecurity
   AND routine_safety.exact AND routine_acl.exact AND table_acl.exact AND check_safety.exact
   AND NOT EXISTS (SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns)
   AND NOT EXISTS (SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)
   AND NOT EXISTS (SELECT * FROM expected_constraints EXCEPT SELECT * FROM actual_constraints)
   AND NOT EXISTS (SELECT * FROM actual_constraints EXCEPT SELECT * FROM expected_constraints)
   AND NOT EXISTS (SELECT * FROM expected_indexes EXCEPT SELECT * FROM actual_indexes)
   AND NOT EXISTS (SELECT * FROM actual_indexes EXCEPT SELECT * FROM expected_indexes)
   AND pg_get_function_result(tombstone_oid) = 'TABLE(artifact_id uuid, project_id uuid, storage_path text, size_bytes bigint, sha256 text, state text, gc_generation bigint, gc_after timestamp with time zone, deleted_at timestamp with time zone)'
   AND pg_get_function_result(claim_oid) = 'TABLE(artifact_id uuid, project_id uuid, storage_path text, size_bytes bigint, sha256 text, state text, gc_generation bigint, gc_token uuid, gc_lease_until timestamp with time zone, gc_after timestamp with time zone, deleted_at timestamp with time zone)'
   AND pg_get_function_result(finalize_oid) = 'TABLE(artifact_id uuid, project_id uuid, storage_path text, size_bytes bigint, sha256 text, state text, gc_generation bigint, gc_after timestamp with time zone, deleted_at timestamp with time zone)'
   AND pg_get_function_result(orphan_oid) = 'boolean'
   AND NOT has_table_privilege('punaro_app',deletions_oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
   AND NOT has_any_column_privilege('punaro_app',deletions_oid,'SELECT,INSERT,UPDATE,REFERENCES')
   AND has_function_privilege('punaro_app',tombstone_oid,'EXECUTE')
   AND has_function_privilege('punaro_app',claim_oid,'EXECUTE')
   AND has_function_privilege('punaro_app',finalize_oid,'EXECUTE')
   AND has_function_privilege('punaro_app',orphan_oid,'EXECUTE')
FROM objects
JOIN pg_class AS relation ON relation.oid = deletions_oid,
     routine_safety, routine_acl, table_acl, check_safety`).Scan(&available)
	return available, err
}
