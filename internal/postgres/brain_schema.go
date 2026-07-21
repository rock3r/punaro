package postgres

import "context"

// canonicalBrainControlsAvailable verifies the exact schema-v14 canonical
// memory authority. Migration checksums prove provenance; these catalog checks
// detect later drift in storage, ownership, mutation fencing, routines, and
// least-privilege application access.
func canonicalBrainControlsAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `
WITH objects AS (
    SELECT to_regclass('brain.scopes') AS scopes_oid,
           to_regclass('brain.memory_items') AS items_oid,
		   to_regclass('brain.memory_revisions') AS revisions_oid,
		   to_regclass('brain.memory_changes') AS changes_oid,
		   to_regclass('brain.memory_tombstones') AS tombstones_oid,
           to_regclass('brain.memory_items_scope_logical_key') AS logical_key_index_oid,
           to_regclass('brain.memory_items_scope_state') AS state_index_oid,
           to_regclass('brain.memory_changes_scope_cursor') AS cursor_index_oid,
           to_regprocedure('brain.purge_memory(uuid,uuid,uuid,bigint)') AS purge_oid,
           to_regprocedure('jobs.guard_application_mutation()') AS fence_oid
), expected_columns(relation_name,column_name,type_name,required,default_expression) AS (
    VALUES
      ('brain.scopes','id','uuid',true,'gen_random_uuid()'),
      ('brain.scopes','project_id','uuid',true,''),
      ('brain.scopes','created_by','uuid',true,''),
      ('brain.scopes','created_at','timestamp with time zone',true,'statement_timestamp()'),
      ('brain.memory_items','id','uuid',true,'gen_random_uuid()'),
      ('brain.memory_items','scope_id','uuid',true,''),
      ('brain.memory_items','kind','text',true,''),
      ('brain.memory_items','state','text',true,'''active''::text'),
      ('brain.memory_items','trust','text',true,''),
      ('brain.memory_items','logical_key','text',false,''),
      ('brain.memory_items','current_revision','bigint',true,''),
      ('brain.memory_items','created_by','uuid',true,''),
      ('brain.memory_items','created_at','timestamp with time zone',true,'statement_timestamp()'),
      ('brain.memory_items','updated_at','timestamp with time zone',true,'statement_timestamp()'),
      ('brain.memory_revisions','item_id','uuid',true,''),
      ('brain.memory_revisions','revision','bigint',true,''),
      ('brain.memory_revisions','document','jsonb',true,''),
      ('brain.memory_revisions','content_sha256','bytea',true,''),
      ('brain.memory_revisions','author_principal_id','uuid',true,''),
      ('brain.memory_revisions','operation','text',true,''),
      ('brain.memory_revisions','created_at','timestamp with time zone',true,'statement_timestamp()'),
      ('brain.memory_changes','timeline_id','uuid',true,''),
      ('brain.memory_changes','change_sequence','bigint',true,''),
      ('brain.memory_changes','scope_id','uuid',true,''),
      ('brain.memory_changes','item_id','uuid',true,''),
      ('brain.memory_changes','operation','text',true,''),
	  ('brain.memory_changes','revision','bigint',true,''),
	  ('brain.memory_changes','occurred_at','timestamp with time zone',true,'statement_timestamp()'),
	  ('brain.memory_tombstones','item_id','uuid',true,''),
	  ('brain.memory_tombstones','scope_id','uuid',true,''),
	  ('brain.memory_tombstones','deleted_by','uuid',true,''),
	  ('brain.memory_tombstones','timeline_id','uuid',true,''),
	  ('brain.memory_tombstones','change_sequence','bigint',true,''),
	  ('brain.memory_tombstones','deleted_at','timestamp with time zone',true,'statement_timestamp()')
), actual_columns AS (
    SELECT attribute.attrelid::regclass::text, attribute.attname,
           attribute.atttypid::regtype::text, attribute.attnotnull,
           COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),'')
    FROM pg_attribute AS attribute
    LEFT JOIN pg_attrdef AS default_value
      ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum,
         objects
	WHERE attribute.attrelid = ANY(ARRAY[scopes_oid,items_oid,revisions_oid,changes_oid,tombstones_oid])
      AND attribute.attnum > 0 AND NOT attribute.attisdropped
), table_safety AS (
	SELECT count(*) = 5
       AND bool_and(pg_get_userbyid(relation.relowner) = 'punaro_owner')
       AND bool_and(relation.relkind = 'r' AND NOT relation.relrowsecurity AND NOT relation.relforcerowsecurity) AS exact
	FROM pg_class AS relation, objects
	WHERE relation.oid = ANY(ARRAY[scopes_oid,items_oid,revisions_oid,changes_oid,tombstones_oid])
), expected_constraints(relation_name,constraint_name,constraint_type,column_keys,referenced_relation,referenced_keys,delete_action,is_deferrable,is_deferred,expression) AS (
	VALUES
	  ('brain.scopes','scopes_pkey','p','{1}','','','',false,false,''),
	  ('brain.scopes','scopes_project_id_key','u','{2}','','','',false,false,''),
	  ('brain.scopes','scopes_project_id_fkey','f','{2}','relay.projects','{1}','a',false,false,''),
	  ('brain.scopes','scopes_created_by_fkey','f','{3}','auth.principals','{1}','a',false,false,''),
	  ('brain.memory_items','memory_items_pkey','p','{1}','','','',false,false,''),
	  ('brain.memory_items','memory_items_scope_id_fkey','f','{2}','brain.scopes','{1}','a',false,false,''),
	  ('brain.memory_items','memory_items_kind_check','c','{3}','','','',false,false,'(kind ~ ''^[a-z][a-z0-9_.:-]{0,63}$''::text)'),
	  ('brain.memory_items','memory_items_state_check','c','{4}','','','',false,false,'(state = ANY (ARRAY[''active''::text, ''archived''::text]))'),
	  ('brain.memory_items','memory_items_trust_check','c','{5}','','','',false,false,'(trust ~ ''^[a-z][a-z0-9_.:-]{0,63}$''::text)'),
	  ('brain.memory_items','memory_items_logical_key_check','c','{6}','','','',false,false,'((logical_key IS NULL) OR (((char_length(logical_key) >= 1) AND (char_length(logical_key) <= 128)) AND (octet_length(logical_key) <= 512) AND (logical_key !~ ''[[:cntrl:]]''::text)))'),
	  ('brain.memory_items','memory_items_current_revision_check','c','{7}','','','',false,false,'(current_revision >= 1)'),
	  ('brain.memory_items','memory_items_created_by_fkey','f','{8}','auth.principals','{1}','a',false,false,''),
	  ('brain.memory_items','memory_items_timestamp_check','c','{10,9}','','','',false,false,'(updated_at >= created_at)'),
	  ('brain.memory_items','memory_items_current_revision_fkey','f','{1,7}','brain.memory_revisions','{1,2}','a',true,true,''),
	  ('brain.memory_revisions','memory_revisions_pkey','p','{1,2}','','','',false,false,''),
	  ('brain.memory_revisions','memory_revisions_item_id_fkey','f','{1}','brain.memory_items','{1}','c',false,false,''),
	  ('brain.memory_revisions','memory_revisions_revision_check','c','{2}','','','',false,false,'(revision >= 1)'),
	  ('brain.memory_revisions','memory_revisions_document_check','c','{3}','','','',false,false,'((jsonb_typeof(document) = ''object''::text) AND (octet_length((document)::text) <= 262144))'),
	  ('brain.memory_revisions','memory_revisions_content_sha256_check','c','{4}','','','',false,false,'(octet_length(content_sha256) = 32)'),
	  ('brain.memory_revisions','memory_revisions_author_principal_id_fkey','f','{5}','auth.principals','{1}','a',false,false,''),
	  ('brain.memory_revisions','memory_revisions_operation_check','c','{6}','','','',false,false,'(operation = ANY (ARRAY[''create''::text, ''update''::text, ''archive''::text, ''restore''::text]))'),
	  ('brain.memory_changes','memory_changes_pkey','p','{1,2}','','','',false,false,''),
	  ('brain.memory_changes','memory_changes_sequence_check','c','{2}','','','',false,false,'(change_sequence >= 1)'),
	  ('brain.memory_changes','memory_changes_scope_id_fkey','f','{3}','brain.scopes','{1}','a',false,false,''),
	  ('brain.memory_changes','memory_changes_operation_check','c','{5}','','','',false,false,'(operation = ANY (ARRAY[''create''::text, ''update''::text, ''archive''::text, ''restore''::text, ''delete''::text]))'),
	  ('brain.memory_changes','memory_changes_revision_check','c','{6}','','','',false,false,'(revision >= 1)'),
	  ('brain.memory_tombstones','memory_tombstones_pkey','p','{1}','','','',false,false,''),
	  ('brain.memory_tombstones','memory_tombstones_scope_id_fkey','f','{2}','brain.scopes','{1}','a',false,false,''),
	  ('brain.memory_tombstones','memory_tombstones_deleted_by_fkey','f','{3}','auth.principals','{1}','a',false,false,''),
	  ('brain.memory_tombstones','memory_tombstones_sequence_check','c','{5}','','','',false,false,'(change_sequence >= 1)')
), actual_constraints AS (
	SELECT constraint_row.conrelid::regclass::text, constraint_row.conname,
	       constraint_row.contype::text, constraint_row.conkey::text,
	       CASE WHEN constraint_row.contype='f' THEN constraint_row.confrelid::regclass::text ELSE '' END,
	       CASE WHEN constraint_row.contype='f' THEN constraint_row.confkey::text ELSE '' END,
	       CASE WHEN constraint_row.contype='f' THEN constraint_row.confdeltype::text ELSE '' END,
	       constraint_row.condeferrable, constraint_row.condeferred,
	       CASE WHEN constraint_row.contype='c' THEN
	         CASE
	           WHEN constraint_row.conname='memory_items_logical_key_check'
	             AND pg_get_expr(constraint_row.conbin,constraint_row.conrelid)='((logical_key IS NULL) OR ((char_length(logical_key) >= 1) AND (char_length(logical_key) <= 128) AND (octet_length(logical_key) <= 512) AND (logical_key !~ ''[[:cntrl:]]''::text)))'
	           THEN '((logical_key IS NULL) OR (((char_length(logical_key) >= 1) AND (char_length(logical_key) <= 128)) AND (octet_length(logical_key) <= 512) AND (logical_key !~ ''[[:cntrl:]]''::text)))'
	           ELSE pg_get_expr(constraint_row.conbin,constraint_row.conrelid)
	         END
	       ELSE '' END
	FROM pg_constraint AS constraint_row, objects
	WHERE constraint_row.conrelid = ANY(ARRAY[scopes_oid,items_oid,revisions_oid,changes_oid,tombstones_oid])
	  AND constraint_row.contype <> 'n' AND constraint_row.convalidated
), constraint_safety AS (
	SELECT count(*) = 30 AND bool_and(constraint_row.convalidated)
	   AND bool_and(NOT constraint_row.condeferred OR constraint_row.conname = 'memory_items_current_revision_fkey')
	   AND bool_and(NOT constraint_row.condeferrable OR constraint_row.conname = 'memory_items_current_revision_fkey')
	   AND count(*) FILTER (WHERE constraint_row.contype='f' AND constraint_row.confupdtype='a' AND constraint_row.confmatchtype='s') = 10 AS exact
    FROM pg_constraint AS constraint_row, objects
	WHERE constraint_row.conrelid = ANY(ARRAY[scopes_oid,items_oid,revisions_oid,changes_oid,tombstones_oid])
      AND constraint_row.contype <> 'n'
), index_safety AS (
	SELECT count(*) = 9 AND bool_and(index_row.indisvalid AND index_row.indisready) AS exact
    FROM pg_index AS index_row, objects
	WHERE index_row.indrelid = ANY(ARRAY[scopes_oid,items_oid,revisions_oid,changes_oid,tombstones_oid])
), fence_safety AS (
	SELECT count(*) = 5 AND bool_and(trigger_row.tgenabled = 'O' AND trigger_row.tgfoid = fence_oid AND trigger_row.tgtype = 62) AS exact
    FROM pg_trigger AS trigger_row, objects
	WHERE trigger_row.tgrelid = ANY(ARRAY[scopes_oid,items_oid,revisions_oid,changes_oid,tombstones_oid])
      AND trigger_row.tgname = 'application_mutation_fence' AND NOT trigger_row.tgisinternal
), routine_safety AS (
    SELECT count(*) = 1
       AND bool_and(pg_get_userbyid(routine.proowner) = 'punaro_owner')
	   AND bool_and(language.lanname = 'plpgsql' AND routine.prokind = 'f' AND routine.prosecdef AND routine.provolatile = 'v')
	   AND bool_and(routine.proretset AND routine.prorettype = 'record'::regtype AND routine.pronargs = 4)
	   AND bool_and(pg_get_function_result(routine.oid) = 'TABLE(scope_id uuid, revision bigint, timeline_id uuid, change_sequence bigint)')
	   AND bool_and(routine.proconfig = ARRAY['search_path=pg_catalog']::text[])
	   AND bool_and(md5(btrim(routine.prosrc, E' \n\r\t')) = 'd86c3c70ca43f0e160fae9f3aaf5a9fd') AS exact
    FROM pg_proc AS routine JOIN pg_language AS language ON language.oid=routine.prolang, objects
    WHERE routine.oid = purge_oid
), routine_acl AS (
    SELECT count(*) = 2 AND bool_and(entry.privilege_type = 'EXECUTE' AND NOT entry.is_grantable)
       AND bool_and(grantee.rolname IN ('punaro_owner','punaro_app')) AS exact
    FROM pg_proc AS routine
    CROSS JOIN LATERAL aclexplode(COALESCE(routine.proacl,acldefault('f',routine.proowner))) AS entry
    LEFT JOIN pg_roles AS grantee ON grantee.oid=entry.grantee, objects
    WHERE routine.oid=purge_oid
), expected_table_acl(relation_name,grantee,privilege_type,is_grantable) AS (
    SELECT relation_name,'punaro_owner',privilege_type,false
    FROM (VALUES ('brain.scopes'),('brain.memory_items'),('brain.memory_revisions'),('brain.memory_changes'),('brain.memory_tombstones')) AS relations(relation_name)
    CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),('REFERENCES'),('TRIGGER'),('MAINTAIN')) AS privileges(privilege_type)
    UNION ALL
    SELECT relation_name,'punaro_app',privilege_type,false
    FROM (VALUES ('brain.scopes'),('brain.memory_items'),('brain.memory_revisions'),('brain.memory_changes')) AS relations(relation_name)
    CROSS JOIN (VALUES ('SELECT'),('INSERT')) AS privileges(privilege_type)
), actual_table_acl AS (
    SELECT relation.oid::regclass::text,COALESCE(grantee.rolname,'PUBLIC'),entry.privilege_type,entry.is_grantable
    FROM pg_class AS relation
    CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) AS entry
    LEFT JOIN pg_roles AS grantee ON grantee.oid=entry.grantee, objects
    WHERE relation.oid = ANY(ARRAY[scopes_oid,items_oid,revisions_oid,changes_oid,tombstones_oid])
), expected_column_acl(relation_name,column_name,grantee,privilege_type,is_grantable) AS (
    SELECT 'brain.memory_items',column_name,'punaro_app','UPDATE',false
    FROM (VALUES ('kind'),('state'),('trust'),('logical_key'),('current_revision'),('updated_at')) AS columns(column_name)
), actual_column_acl AS (
    SELECT attribute.attrelid::regclass::text,attribute.attname,COALESCE(grantee.rolname,'PUBLIC'),entry.privilege_type,entry.is_grantable
    FROM pg_attribute AS attribute
    CROSS JOIN LATERAL aclexplode(attribute.attacl) AS entry
    LEFT JOIN pg_roles AS grantee ON grantee.oid=entry.grantee, objects
    WHERE attribute.attrelid = ANY(ARRAY[scopes_oid,items_oid,revisions_oid,changes_oid,tombstones_oid])
      AND attribute.attnum > 0 AND NOT attribute.attisdropped AND attribute.attacl IS NOT NULL
)
SELECT scopes_oid IS NOT NULL AND items_oid IS NOT NULL AND revisions_oid IS NOT NULL AND changes_oid IS NOT NULL AND tombstones_oid IS NOT NULL
   AND logical_key_index_oid IS NOT NULL AND state_index_oid IS NOT NULL AND cursor_index_oid IS NOT NULL
   AND purge_oid IS NOT NULL AND fence_oid IS NOT NULL
   AND table_safety.exact AND constraint_safety.exact AND index_safety.exact AND fence_safety.exact
	   AND routine_safety.exact AND routine_acl.exact
	   AND NOT EXISTS (SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns)
	   AND NOT EXISTS (SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)
	   AND NOT EXISTS (SELECT * FROM expected_constraints EXCEPT SELECT * FROM actual_constraints)
	   AND NOT EXISTS (SELECT * FROM actual_constraints EXCEPT SELECT * FROM expected_constraints)
	   AND NOT EXISTS (SELECT * FROM expected_table_acl EXCEPT SELECT * FROM actual_table_acl)
	   AND NOT EXISTS (SELECT * FROM actual_table_acl EXCEPT SELECT * FROM expected_table_acl)
	   AND NOT EXISTS (SELECT * FROM expected_column_acl EXCEPT SELECT * FROM actual_column_acl)
	   AND NOT EXISTS (SELECT * FROM actual_column_acl EXCEPT SELECT * FROM expected_column_acl)
   AND EXISTS (
       SELECT 1 FROM pg_index
       WHERE indexrelid=logical_key_index_oid AND indrelid=items_oid
         AND indisunique AND indisvalid AND indisready AND indkey='2 6'::int2vector
         AND indexprs IS NULL AND pg_get_expr(indpred,indrelid)='(logical_key IS NOT NULL)'
   )
   AND EXISTS (
       SELECT 1 FROM pg_index
       WHERE indexrelid=state_index_oid AND indrelid=items_oid
         AND NOT indisunique AND indisvalid AND indisready AND indkey='2 4 1'::int2vector
         AND indexprs IS NULL AND indpred IS NULL
   )
   AND EXISTS (
       SELECT 1 FROM pg_index
       WHERE indexrelid=cursor_index_oid AND indrelid=changes_oid
         AND NOT indisunique AND indisvalid AND indisready AND indkey='3 1 2 4'::int2vector
         AND indexprs IS NULL AND indpred IS NULL
   )
   AND has_function_privilege('punaro_app',purge_oid,'EXECUTE')
FROM objects, table_safety, constraint_safety, index_safety, fence_safety, routine_safety, routine_acl`).Scan(&available)
	return available, err
}
