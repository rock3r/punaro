package postgres

import "context"

// memoryQuarantineControlsAvailable verifies schema-v16 quarantine storage,
// fencing, indexes, ownership, constraints, and least-privilege application ACLs.
func memoryQuarantineControlsAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `WITH objects AS (
    SELECT to_regclass('brain.secret_project_state') AS project_state_oid,
           to_regclass('brain.memory_secret_scans') AS scans_oid,
           to_regclass('brain.memory_quarantines') AS quarantines_oid,
           to_regclass('brain.memory_quarantines_active_item') AS active_index_oid,
           to_regclass('brain.memory_quarantines_item_history') AS history_index_oid,
           to_regprocedure('jobs.guard_application_mutation()') AS fence_oid
), expected_columns(relation_name,column_name,type_name,not_null,default_expression) AS (
    VALUES
      ('brain.secret_project_state','project_id','uuid',true,''),
      ('brain.secret_project_state','exception_generation','bigint',true,'0'),
      ('brain.secret_project_state','updated_at','timestamp with time zone',true,'statement_timestamp()'),
      ('brain.memory_secret_scans','item_id','uuid',true,''),
      ('brain.memory_secret_scans','revision','bigint',true,''),
      ('brain.memory_secret_scans','rule_version','bigint',true,''),
      ('brain.memory_secret_scans','rule_digest','bytea',true,''),
      ('brain.memory_secret_scans','exception_generation','bigint',true,''),
      ('brain.memory_secret_scans','outcome','text',true,''),
      ('brain.memory_secret_scans','scanned_by','uuid',true,''),
      ('brain.memory_secret_scans','scanned_at','timestamp with time zone',true,'statement_timestamp()'),
      ('brain.memory_quarantines','id','uuid',true,'gen_random_uuid()'),
      ('brain.memory_quarantines','item_id','uuid',true,''),
      ('brain.memory_quarantines','detected_revision','bigint',true,''),
      ('brain.memory_quarantines','rule_version','bigint',true,''),
      ('brain.memory_quarantines','rule_id','text',true,''),
      ('brain.memory_quarantines','field_path','text',true,''),
      ('brain.memory_quarantines','value_fingerprint','bytea',true,''),
      ('brain.memory_quarantines','quarantined_by','uuid',true,''),
      ('brain.memory_quarantines','quarantined_at','timestamp with time zone',true,'statement_timestamp()'),
      ('brain.memory_quarantines','released_by','uuid',false,''),
      ('brain.memory_quarantines','released_at','timestamp with time zone',false,'')
), actual_columns AS (
    SELECT attribute.attrelid::regclass::text,attribute.attname,format_type(attribute.atttypid,attribute.atttypmod),attribute.attnotnull,
           COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),'')
    FROM pg_attribute AS attribute
    LEFT JOIN pg_attrdef AS default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum,objects
    WHERE attribute.attrelid=ANY(ARRAY[project_state_oid,scans_oid,quarantines_oid]) AND attribute.attnum>0 AND NOT attribute.attisdropped
), table_safety AS (
    SELECT count(*)=3 AND bool_and(relation.relkind='r' AND relation.relpersistence='p' AND NOT relation.relrowsecurity AND NOT relation.relforcerowsecurity AND pg_get_userbyid(relation.relowner)='punaro_owner') AS exact
    FROM pg_class AS relation,objects WHERE relation.oid=ANY(ARRAY[project_state_oid,scans_oid,quarantines_oid])
), constraint_safety AS (
    SELECT count(*)=21 AND bool_and(constraint_row.convalidated AND NOT constraint_row.condeferrable AND NOT constraint_row.condeferred) AS exact
    FROM pg_constraint AS constraint_row,objects WHERE constraint_row.conrelid=ANY(ARRAY[project_state_oid,scans_oid,quarantines_oid]) AND constraint_row.contype<>'n'
), expected_constraints(relation_name,constraint_name,constraint_type,column_keys,referenced_relation,referenced_keys,update_action,delete_action,match_type,expression) AS (
    VALUES
      ('brain.secret_project_state','secret_project_state_pkey','p','{1}','','','','','',''),
      ('brain.secret_project_state','secret_project_state_project_id_fkey','f','{1}','relay.projects','{1}','a','a','s',''),
      ('brain.secret_project_state','secret_project_state_generation_check','c','{2}','','','','','','(exception_generation >= 0)'),
      ('brain.memory_secret_scans','memory_secret_scans_pkey','p','{1}','','','','','',''),
      ('brain.memory_secret_scans','memory_secret_scans_revision_check','c','{2}','','','','','','(revision >= 1)'),
      ('brain.memory_secret_scans','memory_secret_scans_rule_version_check','c','{3}','','','','','','(rule_version >= 1)'),
      ('brain.memory_secret_scans','memory_secret_scans_rule_digest_check','c','{4}','','','','','','(octet_length(rule_digest) = 32)'),
      ('brain.memory_secret_scans','memory_secret_scans_generation_check','c','{5}','','','','','','(exception_generation >= 0)'),
      ('brain.memory_secret_scans','memory_secret_scans_outcome_check','c','{6}','','','','','','(outcome = ANY (ARRAY[''clear''::text, ''quarantined''::text]))'),
      ('brain.memory_secret_scans','memory_secret_scans_scanned_by_fkey','f','{7}','auth.principals','{1}','a','a','s',''),
      ('brain.memory_secret_scans','memory_secret_scans_revision_fkey','f','{1,2}','brain.memory_revisions','{1,2}','a','c','s',''),
      ('brain.memory_quarantines','memory_quarantines_pkey','p','{1}','','','','','',''),
      ('brain.memory_quarantines','memory_quarantines_revision_check','c','{3}','','','','','','(detected_revision >= 1)'),
      ('brain.memory_quarantines','memory_quarantines_rule_version_check','c','{4}','','','','','','(rule_version >= 1)'),
      ('brain.memory_quarantines','memory_quarantines_rule_id_check','c','{5}','','','','','','(rule_id = ANY (ARRAY[''private-key''::text, ''bearer-token''::text, ''credential-assignment''::text, ''sensitive-field''::text]))'),
      ('brain.memory_quarantines','memory_quarantines_field_path_check','c','{6}','','','','','','((octet_length(field_path) >= 1) AND (octet_length(field_path) <= 1024))'),
      ('brain.memory_quarantines','memory_quarantines_fingerprint_check','c','{7}','','','','','','(octet_length(value_fingerprint) = 32)'),
      ('brain.memory_quarantines','memory_quarantines_quarantined_by_fkey','f','{8}','auth.principals','{1}','a','a','s',''),
      ('brain.memory_quarantines','memory_quarantines_released_by_fkey','f','{10}','auth.principals','{1}','a','a','s',''),
      ('brain.memory_quarantines','memory_quarantines_revision_fkey','f','{2,3}','brain.memory_revisions','{1,2}','a','c','s',''),
      ('brain.memory_quarantines','memory_quarantines_release_check','c','{11,10,9}','','','','','','(((released_at IS NULL) AND (released_by IS NULL)) OR ((released_at >= quarantined_at) AND (released_by IS NOT NULL)))')
), actual_constraints AS (
    SELECT constraint_row.conrelid::regclass::text,constraint_row.conname,constraint_row.contype::text,constraint_row.conkey::text,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confrelid::regclass::text ELSE '' END,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confkey::text ELSE '' END,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confupdtype::text ELSE '' END,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confdeltype::text ELSE '' END,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confmatchtype::text ELSE '' END,
           CASE WHEN constraint_row.contype='c' THEN pg_get_expr(constraint_row.conbin,constraint_row.conrelid) ELSE '' END
    FROM pg_constraint AS constraint_row,objects
    WHERE constraint_row.conrelid=ANY(ARRAY[project_state_oid,scans_oid,quarantines_oid]) AND constraint_row.contype<>'n' AND constraint_row.convalidated
), index_safety AS (
    SELECT count(*)=5 AND bool_and(index_row.indisvalid AND index_row.indisready) AS exact
    FROM pg_index AS index_row,objects WHERE index_row.indrelid=ANY(ARRAY[project_state_oid,scans_oid,quarantines_oid])
), fence_safety AS (
    SELECT count(*)=3 AND bool_and(trigger_row.tgenabled='O' AND trigger_row.tgfoid=fence_oid AND trigger_row.tgtype=62) AS exact
    FROM pg_trigger AS trigger_row,objects
    WHERE trigger_row.tgrelid=ANY(ARRAY[project_state_oid,scans_oid,quarantines_oid]) AND trigger_row.tgname='application_mutation_fence' AND NOT trigger_row.tgisinternal
), expected_table_acl(relation_name,grantee,privilege_type,is_grantable) AS (
    SELECT relation_name,'punaro_owner',privilege_type,false
    FROM (VALUES ('brain.secret_project_state'),('brain.memory_secret_scans'),('brain.memory_quarantines')) AS relations(relation_name)
    CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),('REFERENCES'),('TRIGGER'),('MAINTAIN')) AS privileges(privilege_type)
    UNION ALL SELECT relation_name,'punaro_app','SELECT',false
    FROM (VALUES ('brain.secret_project_state'),('brain.memory_secret_scans'),('brain.memory_quarantines')) AS relations(relation_name)
), actual_table_acl AS (
    SELECT relation.oid::regclass::text,COALESCE(grantee.rolname,'PUBLIC'),entry.privilege_type,entry.is_grantable
    FROM pg_class AS relation CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) AS entry
    LEFT JOIN pg_roles AS grantee ON grantee.oid=entry.grantee,objects
    WHERE relation.oid=ANY(ARRAY[project_state_oid,scans_oid,quarantines_oid])
), expected_column_acl(relation_name,column_name,grantee,privilege_type,is_grantable) AS (
    VALUES
      ('brain.secret_project_state','project_id','punaro_app','INSERT',false),
      ('brain.secret_project_state','exception_generation','punaro_app','UPDATE',false),
      ('brain.secret_project_state','updated_at','punaro_app','UPDATE',false),
      ('brain.memory_secret_scans','item_id','punaro_app','INSERT',false),
      ('brain.memory_secret_scans','revision','punaro_app','INSERT',false),
      ('brain.memory_secret_scans','rule_version','punaro_app','INSERT',false),
      ('brain.memory_secret_scans','rule_digest','punaro_app','INSERT',false),
      ('brain.memory_secret_scans','exception_generation','punaro_app','INSERT',false),
      ('brain.memory_secret_scans','outcome','punaro_app','INSERT',false),
      ('brain.memory_secret_scans','scanned_by','punaro_app','INSERT',false),
      ('brain.memory_secret_scans','revision','punaro_app','UPDATE',false),
      ('brain.memory_secret_scans','rule_version','punaro_app','UPDATE',false),
      ('brain.memory_secret_scans','rule_digest','punaro_app','UPDATE',false),
      ('brain.memory_secret_scans','exception_generation','punaro_app','UPDATE',false),
      ('brain.memory_secret_scans','outcome','punaro_app','UPDATE',false),
      ('brain.memory_secret_scans','scanned_by','punaro_app','UPDATE',false),
      ('brain.memory_secret_scans','scanned_at','punaro_app','UPDATE',false),
      ('brain.memory_quarantines','item_id','punaro_app','INSERT',false),
      ('brain.memory_quarantines','detected_revision','punaro_app','INSERT',false),
      ('brain.memory_quarantines','rule_version','punaro_app','INSERT',false),
      ('brain.memory_quarantines','rule_id','punaro_app','INSERT',false),
      ('brain.memory_quarantines','field_path','punaro_app','INSERT',false),
      ('brain.memory_quarantines','value_fingerprint','punaro_app','INSERT',false),
      ('brain.memory_quarantines','quarantined_by','punaro_app','INSERT',false),
      ('brain.memory_quarantines','released_by','punaro_app','UPDATE',false),
      ('brain.memory_quarantines','released_at','punaro_app','UPDATE',false)
), actual_column_acl AS (
    SELECT attribute.attrelid::regclass::text,attribute.attname,COALESCE(grantee.rolname,'PUBLIC'),entry.privilege_type,entry.is_grantable
    FROM pg_attribute AS attribute CROSS JOIN LATERAL aclexplode(attribute.attacl) AS entry
    LEFT JOIN pg_roles AS grantee ON grantee.oid=entry.grantee,objects
    WHERE attribute.attrelid=ANY(ARRAY[project_state_oid,scans_oid,quarantines_oid]) AND attribute.attnum>0 AND NOT attribute.attisdropped AND attribute.attacl IS NOT NULL
)
SELECT project_state_oid IS NOT NULL AND scans_oid IS NOT NULL AND quarantines_oid IS NOT NULL AND active_index_oid IS NOT NULL AND history_index_oid IS NOT NULL AND fence_oid IS NOT NULL
   AND table_safety.exact AND constraint_safety.exact AND index_safety.exact AND fence_safety.exact
   AND NOT EXISTS (SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns)
   AND NOT EXISTS (SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)
   AND NOT EXISTS (SELECT * FROM expected_constraints EXCEPT SELECT * FROM actual_constraints)
   AND NOT EXISTS (SELECT * FROM actual_constraints EXCEPT SELECT * FROM expected_constraints)
   AND NOT EXISTS (SELECT * FROM expected_table_acl EXCEPT SELECT * FROM actual_table_acl)
   AND NOT EXISTS (SELECT * FROM actual_table_acl EXCEPT SELECT * FROM expected_table_acl)
   AND NOT EXISTS (SELECT * FROM expected_column_acl EXCEPT SELECT * FROM actual_column_acl)
   AND NOT EXISTS (SELECT * FROM actual_column_acl EXCEPT SELECT * FROM expected_column_acl)
   AND EXISTS (SELECT 1 FROM pg_index WHERE indexrelid=active_index_oid AND indrelid=quarantines_oid AND indisunique AND indisvalid AND indisready AND indkey='2'::int2vector AND indexprs IS NULL AND pg_get_expr(indpred,indrelid)='(released_at IS NULL)')
   AND EXISTS (SELECT 1 FROM pg_index WHERE indexrelid=history_index_oid AND indrelid=quarantines_oid AND NOT indisunique AND indisvalid AND indisready AND indkey='2 9 1'::int2vector AND indexprs IS NULL AND indpred IS NULL)
   AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=project_state_oid AND conname='secret_project_state_generation_check' AND pg_get_expr(conbin,conrelid)='(exception_generation >= 0)')
   AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=scans_oid AND conname='memory_secret_scans_outcome_check' AND pg_get_expr(conbin,conrelid)='(outcome = ANY (ARRAY[''clear''::text, ''quarantined''::text]))')
   AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=quarantines_oid AND conname='memory_quarantines_release_check' AND pg_get_expr(conbin,conrelid)='(((released_at IS NULL) AND (released_by IS NULL)) OR ((released_at >= quarantined_at) AND (released_by IS NOT NULL)))')
FROM objects,table_safety,constraint_safety,index_safety,fence_safety`).Scan(&available)
	return available, err
}
