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
), expected_columns(name,type_name,required,default_expression) AS (
    VALUES
      ('scope_id','uuid',true,''),('timeline_id','uuid',true,''),('change_sequence','bigint',true,'0'),
      ('lease_holder','uuid',false,''),('lease_token','uuid',false,''),('lease_generation','bigint',true,'0'),
      ('lease_until','timestamp with time zone',false,''),('updated_at','timestamp with time zone',true,'statement_timestamp()')
), actual_columns AS (
    SELECT attribute.attname,attribute.atttypid::regtype::text,attribute.attnotnull,COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),'')
    FROM pg_attribute AS attribute,objects
    LEFT JOIN pg_attrdef AS default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum
    WHERE attribute.attrelid=table_oid AND attribute.attnum>0 AND NOT attribute.attisdropped
), routine_safety AS (
    SELECT count(*)=2 AND bool_and(pg_get_userbyid(routine.proowner)='punaro_owner'
      AND routine.prokind='f' AND routine.prosecdef AND routine.provolatile='v'
      AND routine.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
      AND routine.proconfig=ARRAY['search_path=pg_catalog']::text[] AND NOT routine.proisstrict
      AND NOT routine.proleakproof AND routine.proparallel='u' AND routine.provariadic=0
      AND ((routine.oid=claim_oid AND routine.proretset AND routine.prorettype='record'::regtype
            AND routine.pronargs=3 AND routine.proargtypes='2950 2950 20'::oidvector
            AND md5(btrim(routine.prosrc,E' \n\r\t'))=$1)
        OR (routine.oid=advance_oid AND NOT routine.proretset AND routine.prorettype='boolean'::regtype
            AND routine.pronargs=5 AND routine.proargtypes='2950 2950 20 2950 20'::oidvector
            AND md5(btrim(routine.prosrc,E' \n\r\t'))=$2))) AS exact
    FROM pg_proc AS routine,objects WHERE routine.oid=ANY(ARRAY[claim_oid,advance_oid])
), constraint_safety AS (
    SELECT count(*)=5
       AND count(*) FILTER (WHERE contype='p' AND conkey=ARRAY[1]::smallint[])=1
       AND count(*) FILTER (WHERE contype='f' AND conkey=ARRAY[1]::smallint[] AND confrelid='brain.scopes'::regclass AND confdeltype='c')=1
       AND count(*) FILTER (WHERE contype='c' AND pg_get_constraintdef(oid) LIKE '%change_sequence >= 0%')=1
       AND count(*) FILTER (WHERE contype='c' AND pg_get_constraintdef(oid) LIKE '%lease_generation >= 0%')=1
       AND count(*) FILTER (WHERE contype='c' AND pg_get_constraintdef(oid) LIKE '%lease_holder IS NULL%' AND pg_get_constraintdef(oid) LIKE '%lease_until IS NOT NULL%')=1 AS exact
    FROM pg_constraint,objects WHERE conrelid=table_oid
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
   AND (SELECT count(*)=1 AND bool_and(pg_get_userbyid(relowner)='punaro_owner' AND relkind='r' AND relpersistence='p' AND NOT relrowsecurity AND NOT relforcerowsecurity) FROM pg_class WHERE oid=table_oid)
   AND NOT EXISTS (SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns)
   AND NOT EXISTS (SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)
   AND routine_safety.exact
   AND constraint_safety.exact
   AND NOT EXISTS (SELECT * FROM expected_acl EXCEPT SELECT * FROM actual_acl)
   AND NOT EXISTS (SELECT * FROM actual_acl EXCEPT SELECT * FROM expected_acl)
   AND NOT has_table_privilege('punaro_app',table_oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
   AND NOT EXISTS (SELECT 1 FROM pg_attribute,objects WHERE attrelid=table_oid AND attnum>0 AND NOT attisdropped AND attacl IS NOT NULL)
FROM objects,routine_safety,constraint_safety`, memoryConsolidationClaimRoutineMD5, memoryConsolidationAdvanceRoutineMD5).Scan(&available)
	return available, err
}

const (
	memoryConsolidationClaimRoutineMD5   = "32e95c7fb6a9e73522c73b825bc3dcea"
	memoryConsolidationAdvanceRoutineMD5 = "cce038c3cca8f3c4f48da8b5e155443c"
)
