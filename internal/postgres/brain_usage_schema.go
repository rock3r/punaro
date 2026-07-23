package postgres

import "context"

// memoryUsageControlsAvailable verifies the exact schema-v21 recall-accounting authority.
func memoryUsageControlsAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `WITH objects AS (
    SELECT to_regclass('brain.memory_usage') AS usage_oid,
           to_regclass('brain.memory_usage_last_recalled') AS usage_index_oid,
           to_regprocedure('brain.record_memory_recall(uuid,uuid[])') AS recall_oid,
           to_regprocedure('jobs.guard_application_mutation()') AS fence_oid
), expected_columns(relation_name,column_name,type_name,not_null,default_expression) AS (
    VALUES
      ('brain.memory_usage','item_id','uuid',true,''),
      ('brain.memory_usage','recall_count','bigint',true,''),
      ('brain.memory_usage','last_recalled_at','timestamp with time zone',true,'')
), actual_columns AS (
    SELECT attribute.attrelid::regclass::text,attribute.attname,format_type(attribute.atttypid,attribute.atttypmod),attribute.attnotnull,
           COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),'')
    FROM pg_attribute AS attribute
    LEFT JOIN pg_attrdef AS default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum,objects
    WHERE attribute.attrelid=usage_oid AND attribute.attnum>0 AND NOT attribute.attisdropped
), expected_constraints(relation_name,constraint_name,constraint_type,column_keys,referenced_relation,referenced_keys,update_action,delete_action,match_type,expression) AS (
    VALUES
      ('brain.memory_usage','memory_usage_pkey','p','{1}','','','','','',''),
      ('brain.memory_usage','memory_usage_item_id_fkey','f','{1}','brain.memory_items','{1}','a','c','s',''),
      ('brain.memory_usage','memory_usage_recall_count_check','c','{2}','','','','','','(recall_count >= 0)')
), actual_constraints AS (
    SELECT constraint_row.conrelid::regclass::text,constraint_row.conname,constraint_row.contype::text,constraint_row.conkey::text,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confrelid::regclass::text ELSE '' END,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confkey::text ELSE '' END,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confupdtype::text ELSE '' END,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confdeltype::text ELSE '' END,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confmatchtype::text ELSE '' END,
           CASE WHEN constraint_row.contype='c' THEN pg_get_expr(constraint_row.conbin,constraint_row.conrelid) ELSE '' END
    FROM pg_constraint AS constraint_row,objects
    WHERE constraint_row.conrelid=usage_oid AND constraint_row.contype<>'n'
      AND constraint_row.convalidated AND NOT constraint_row.condeferrable AND NOT constraint_row.condeferred
), table_safety AS (
    SELECT count(*)=1 AND bool_and(relation.relkind='r' AND relation.relpersistence='p' AND NOT relation.relrowsecurity
        AND NOT relation.relforcerowsecurity AND pg_get_userbyid(relation.relowner)='punaro_owner') AS exact
    FROM pg_class AS relation,objects WHERE relation.oid=usage_oid
), constraint_safety AS (
    SELECT count(*)=3 AND bool_and(constraint_row.convalidated AND NOT constraint_row.condeferrable AND NOT constraint_row.condeferred) AS exact
    FROM pg_constraint AS constraint_row,objects WHERE constraint_row.conrelid=usage_oid AND constraint_row.contype<>'n'
), index_safety AS (
    SELECT count(*)=2 AND bool_and(index_row.indisvalid AND index_row.indisready) AS exact
    FROM pg_index AS index_row,objects WHERE index_row.indrelid=usage_oid
), fence_safety AS (
    SELECT count(*)=1 AND bool_and(trigger_row.tgenabled='O' AND trigger_row.tgfoid=fence_oid AND trigger_row.tgtype=62) AS exact
    FROM pg_trigger AS trigger_row,objects
    WHERE trigger_row.tgrelid=usage_oid AND trigger_row.tgname='application_mutation_fence' AND NOT trigger_row.tgisinternal
), function_safety AS (
    SELECT count(*)=1 AND bool_and(pg_get_userbyid(routine.proowner)='punaro_owner' AND routine.prokind='f'
        AND routine.prosecdef AND routine.provolatile='v' AND NOT routine.proretset
		AND routine.prorettype='void'::regtype AND routine.pronargs=2
		AND routine.proargtypes='2950 2951'::oidvector
		AND routine.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
		AND routine.proconfig=ARRAY['search_path=pg_catalog']::text[]
		AND md5(btrim(routine.prosrc,E' \n\r\t'))='3da1dd4af6d9c159c01fbf4a0c6ac199') AS exact
    FROM pg_proc AS routine,objects WHERE routine.oid=recall_oid
), expected_table_acl(relation_name,grantee,privilege_type,is_grantable) AS (
    SELECT 'brain.memory_usage','punaro_owner',privilege_type,false
    FROM (VALUES ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),('REFERENCES'),('TRIGGER'),('MAINTAIN')) AS privileges(privilege_type)
    UNION ALL SELECT 'brain.memory_usage','punaro_app','SELECT',false
), actual_table_acl AS (
    SELECT relation.oid::regclass::text,COALESCE(grantee.rolname,'PUBLIC'),entry.privilege_type,entry.is_grantable
    FROM pg_class AS relation
    CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) AS entry
    LEFT JOIN pg_roles AS grantee ON grantee.oid=entry.grantee,objects
    WHERE relation.oid=usage_oid
), expected_function_acl(grantee,privilege_type,is_grantable) AS (
    VALUES ('punaro_owner','EXECUTE',false),('punaro_app','EXECUTE',false)
), actual_function_acl AS (
    SELECT COALESCE(grantee.rolname,'PUBLIC'),entry.privilege_type,entry.is_grantable
    FROM pg_proc AS routine
    CROSS JOIN LATERAL aclexplode(COALESCE(routine.proacl,acldefault('f',routine.proowner))) AS entry
    LEFT JOIN pg_roles AS grantee ON grantee.oid=entry.grantee,objects
    WHERE routine.oid=recall_oid
)
SELECT usage_oid IS NOT NULL AND usage_index_oid IS NOT NULL AND recall_oid IS NOT NULL AND fence_oid IS NOT NULL
   AND table_safety.exact AND constraint_safety.exact AND index_safety.exact AND fence_safety.exact AND function_safety.exact
   AND NOT EXISTS (SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns)
   AND NOT EXISTS (SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)
   AND NOT EXISTS (SELECT * FROM expected_constraints EXCEPT SELECT * FROM actual_constraints)
   AND NOT EXISTS (SELECT * FROM actual_constraints EXCEPT SELECT * FROM expected_constraints)
   AND NOT EXISTS (SELECT * FROM expected_table_acl EXCEPT SELECT * FROM actual_table_acl)
   AND NOT EXISTS (SELECT * FROM actual_table_acl EXCEPT SELECT * FROM expected_table_acl)
   AND NOT EXISTS (SELECT 1 FROM pg_attribute AS attribute,objects
                   WHERE attribute.attrelid=usage_oid AND attribute.attnum>0 AND NOT attribute.attisdropped AND attribute.attacl IS NOT NULL)
   AND NOT EXISTS (SELECT * FROM expected_function_acl EXCEPT SELECT * FROM actual_function_acl)
   AND NOT EXISTS (SELECT * FROM actual_function_acl EXCEPT SELECT * FROM expected_function_acl)
   AND EXISTS (
       SELECT 1
       FROM pg_index AS index_row
       JOIN pg_class AS index_relation ON index_relation.oid=index_row.indexrelid
       JOIN pg_am AS access_method ON access_method.oid=index_relation.relam
       WHERE index_row.indexrelid=usage_index_oid AND index_row.indrelid=usage_oid
         AND index_relation.relkind='i' AND index_relation.relpersistence='p'
         AND pg_get_userbyid(index_relation.relowner)='punaro_owner'
         AND access_method.amname='btree'
         AND NOT index_row.indisunique AND index_row.indisvalid AND index_row.indisready
         AND index_row.indnkeyatts=2 AND index_row.indnatts=2
         AND index_row.indkey='3 1'::int2vector
         AND index_row.indcollation='0 0'::oidvector
         AND index_row.indoption='0 0'::int2vector
         AND index_row.indclass[0]=(SELECT oid FROM pg_opclass WHERE opcname='timestamptz_ops' AND opcmethod=index_relation.relam)
         AND index_row.indclass[1]=(SELECT oid FROM pg_opclass WHERE opcname='uuid_ops' AND opcmethod=index_relation.relam)
         AND index_row.indexprs IS NULL AND index_row.indpred IS NULL
   )
FROM objects,table_safety,constraint_safety,index_safety,fence_safety,function_safety`).Scan(&available)
	return available, err
}
