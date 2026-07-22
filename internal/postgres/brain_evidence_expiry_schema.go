package postgres

import "context"

// memoryEvidenceExpiryControlsAvailable verifies the exact schema-v20 evidence expiry authority.
func memoryEvidenceExpiryControlsAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `WITH objects AS (
    SELECT to_regclass('brain.memory_evidence_expirations') AS expirations_oid,
           to_regclass('brain.memory_evidence_expirations_due') AS due_index_oid,
           to_regprocedure('jobs.guard_application_mutation()') AS fence_oid
), expected_columns(relation_name,column_name,type_name,not_null,default_expression) AS (
    VALUES
      ('brain.memory_evidence_expirations','item_id','uuid',true,''),
      ('brain.memory_evidence_expirations','expires_at','timestamp with time zone',true,''),
      ('brain.memory_evidence_expirations','created_by','uuid',true,''),
      ('brain.memory_evidence_expirations','created_at','timestamp with time zone',true,'statement_timestamp()')
), actual_columns AS (
    SELECT attribute.attrelid::regclass::text,attribute.attname,format_type(attribute.atttypid,attribute.atttypmod),attribute.attnotnull,
           COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),'')
    FROM pg_attribute AS attribute
    LEFT JOIN pg_attrdef AS default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum,objects
    WHERE attribute.attrelid=expirations_oid AND attribute.attnum>0 AND NOT attribute.attisdropped
), expected_constraints(relation_name,constraint_name,constraint_type,column_keys,referenced_relation,referenced_keys,update_action,delete_action,match_type,expression) AS (
    VALUES
      ('brain.memory_evidence_expirations','memory_evidence_expirations_pkey','p','{1}','','','','','',''),
      ('brain.memory_evidence_expirations','memory_evidence_expirations_item_id_fkey','f','{1}','brain.memory_items','{1}','a','c','s',''),
      ('brain.memory_evidence_expirations','memory_evidence_expirations_created_by_fkey','f','{3}','auth.principals','{1}','a','a','s',''),
      ('brain.memory_evidence_expirations','memory_evidence_expirations_future_check','c','{2,4}','','','','','','(expires_at > created_at)')
), actual_constraints AS (
    SELECT constraint_row.conrelid::regclass::text,constraint_row.conname,constraint_row.contype::text,constraint_row.conkey::text,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confrelid::regclass::text ELSE '' END,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confkey::text ELSE '' END,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confupdtype::text ELSE '' END,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confdeltype::text ELSE '' END,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confmatchtype::text ELSE '' END,
           CASE WHEN constraint_row.contype='c' THEN pg_get_expr(constraint_row.conbin,constraint_row.conrelid) ELSE '' END
    FROM pg_constraint AS constraint_row,objects
    WHERE constraint_row.conrelid=expirations_oid AND constraint_row.contype<>'n'
      AND constraint_row.convalidated AND NOT constraint_row.condeferrable AND NOT constraint_row.condeferred
), table_safety AS (
    SELECT count(*)=1 AND bool_and(relation.relkind='r' AND relation.relpersistence='p' AND NOT relation.relrowsecurity
        AND NOT relation.relforcerowsecurity AND pg_get_userbyid(relation.relowner)='punaro_owner') AS exact
    FROM pg_class AS relation,objects WHERE relation.oid=expirations_oid
), constraint_safety AS (
    SELECT count(*)=4 AND bool_and(constraint_row.convalidated AND NOT constraint_row.condeferrable AND NOT constraint_row.condeferred) AS exact
    FROM pg_constraint AS constraint_row,objects WHERE constraint_row.conrelid=expirations_oid AND constraint_row.contype<>'n'
), index_safety AS (
    SELECT count(*)=2 AND bool_and(index_row.indisvalid AND index_row.indisready) AS exact
    FROM pg_index AS index_row,objects WHERE index_row.indrelid=expirations_oid
), fence_safety AS (
    SELECT count(*)=1 AND bool_and(trigger_row.tgenabled='O' AND trigger_row.tgfoid=fence_oid AND trigger_row.tgtype=62) AS exact
    FROM pg_trigger AS trigger_row,objects
    WHERE trigger_row.tgrelid=expirations_oid AND trigger_row.tgname='application_mutation_fence' AND NOT trigger_row.tgisinternal
), expected_table_acl(relation_name,grantee,privilege_type,is_grantable) AS (
    SELECT 'brain.memory_evidence_expirations','punaro_owner',privilege_type,false
    FROM (VALUES ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),('REFERENCES'),('TRIGGER'),('MAINTAIN')) AS privileges(privilege_type)
    UNION ALL SELECT 'brain.memory_evidence_expirations','punaro_app','SELECT',false
), actual_table_acl AS (
    SELECT relation.oid::regclass::text,COALESCE(grantee.rolname,'PUBLIC'),entry.privilege_type,entry.is_grantable
    FROM pg_class AS relation
    CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) AS entry
    LEFT JOIN pg_roles AS grantee ON grantee.oid=entry.grantee,objects
    WHERE relation.oid=expirations_oid
), expected_column_acl(relation_name,column_name,grantee,privilege_type,is_grantable) AS (
    SELECT 'brain.memory_evidence_expirations',column_name,'punaro_app','INSERT',false
    FROM (VALUES ('item_id'),('expires_at'),('created_by')) AS columns(column_name)
), actual_column_acl AS (
    SELECT attribute.attrelid::regclass::text,attribute.attname,COALESCE(grantee.rolname,'PUBLIC'),entry.privilege_type,entry.is_grantable
    FROM pg_attribute AS attribute CROSS JOIN LATERAL aclexplode(attribute.attacl) AS entry
    LEFT JOIN pg_roles AS grantee ON grantee.oid=entry.grantee,objects
    WHERE attribute.attrelid=expirations_oid AND attribute.attnum>0 AND NOT attribute.attisdropped AND attribute.attacl IS NOT NULL
)
SELECT expirations_oid IS NOT NULL AND due_index_oid IS NOT NULL AND fence_oid IS NOT NULL
   AND table_safety.exact AND constraint_safety.exact AND index_safety.exact AND fence_safety.exact
   AND NOT EXISTS (SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns)
   AND NOT EXISTS (SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)
   AND NOT EXISTS (SELECT * FROM expected_constraints EXCEPT SELECT * FROM actual_constraints)
   AND NOT EXISTS (SELECT * FROM actual_constraints EXCEPT SELECT * FROM expected_constraints)
   AND NOT EXISTS (SELECT * FROM expected_table_acl EXCEPT SELECT * FROM actual_table_acl)
   AND NOT EXISTS (SELECT * FROM actual_table_acl EXCEPT SELECT * FROM expected_table_acl)
   AND NOT EXISTS (SELECT * FROM expected_column_acl EXCEPT SELECT * FROM actual_column_acl)
   AND NOT EXISTS (SELECT * FROM actual_column_acl EXCEPT SELECT * FROM expected_column_acl)
   AND EXISTS (SELECT 1 FROM pg_index WHERE indexrelid=due_index_oid AND indrelid=expirations_oid AND NOT indisunique
       AND indisvalid AND indisready AND indkey='2 1'::int2vector AND indexprs IS NULL AND indpred IS NULL)
FROM objects,table_safety,constraint_safety,index_safety,fence_safety`).Scan(&available)
	return available, err
}
