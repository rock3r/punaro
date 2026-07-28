package postgres

import "context"

// memoryConsolidationControlsAvailable verifies the schema-v33 durable
// checkpoint fence and its application-role boundary.
func memoryConsolidationControlsAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `
WITH objects AS (
    SELECT to_regclass('brain.memory_consolidation_checkpoints') AS table_oid,
           to_regprocedure('brain.claim_memory_consolidation_checkpoint(uuid,uuid,bigint)') AS claim_oid,
           to_regprocedure('brain.advance_memory_consolidation_checkpoint(uuid,uuid,bigint,uuid,bigint)') AS advance_oid
), expected_columns(name,type_name,required) AS (
    VALUES
      ('scope_id','uuid',true),('timeline_id','uuid',true),('change_sequence','bigint',true),
      ('lease_holder','uuid',false),('lease_token','uuid',false),('lease_generation','bigint',true),
      ('lease_until','timestamp with time zone',false),('updated_at','timestamp with time zone',true)
), actual_columns AS (
    SELECT attribute.attname,attribute.atttypid::regtype::text,attribute.attnotnull
    FROM pg_attribute AS attribute,objects
    WHERE attribute.attrelid=table_oid AND attribute.attnum>0 AND NOT attribute.attisdropped
), routine_safety AS (
    SELECT count(*)=2 AND bool_and(pg_get_userbyid(routine.proowner)='punaro_owner'
      AND routine.prokind='f' AND routine.prosecdef AND routine.provolatile='v'
      AND routine.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
      AND routine.proconfig=ARRAY['search_path=pg_catalog']::text[] AND NOT routine.proisstrict
      AND NOT routine.proleakproof AND routine.proparallel='u' AND routine.provariadic=0) AS exact
    FROM pg_proc AS routine,objects WHERE routine.oid=ANY(ARRAY[claim_oid,advance_oid])
), expected_acl(routine_oid,grantee,privilege_type,is_grantable) AS (
    SELECT claim_oid,'punaro_owner','EXECUTE',false FROM objects UNION ALL
    SELECT claim_oid,'punaro_app','EXECUTE',false FROM objects UNION ALL
    SELECT advance_oid,'punaro_owner','EXECUTE',false FROM objects UNION ALL
    SELECT advance_oid,'punaro_app','EXECUTE',false FROM objects
), actual_acl AS (
    SELECT routine.oid,COALESCE(grantee.rolname,'PUBLIC'),entry.privilege_type,entry.is_grantable
    FROM pg_proc AS routine CROSS JOIN LATERAL aclexplode(COALESCE(routine.proacl,acldefault('f',routine.proowner))) AS entry
    LEFT JOIN pg_roles AS grantee ON grantee.oid=entry.grantee,objects
    WHERE routine.oid=ANY(ARRAY[claim_oid,advance_oid])
)
SELECT table_oid IS NOT NULL AND claim_oid IS NOT NULL AND advance_oid IS NOT NULL
   AND (SELECT count(*)=1 AND bool_and(pg_get_userbyid(relowner)='punaro_owner') FROM pg_class WHERE oid=table_oid)
   AND NOT EXISTS (SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns)
   AND NOT EXISTS (SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)
   AND routine_safety.exact
   AND NOT EXISTS (SELECT * FROM expected_acl EXCEPT SELECT * FROM actual_acl)
   AND NOT EXISTS (SELECT * FROM actual_acl EXCEPT SELECT * FROM expected_acl)
   AND NOT has_table_privilege('punaro_app',table_oid,'SELECT,INSERT,UPDATE,DELETE')
FROM objects,routine_safety`).Scan(&available)
	return available, err
}
