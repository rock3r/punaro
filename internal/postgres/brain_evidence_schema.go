package postgres

import "context"

// memoryEvidenceControlsAvailable verifies the exact schema-v17 evidence authority.
func memoryEvidenceControlsAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `WITH objects AS (
    SELECT to_regclass('brain.memory_items') AS items_oid,
           to_regclass('brain.memory_sources') AS sources_oid,
           to_regclass('brain.memory_edges') AS edges_oid,
           to_regclass('brain.memory_sources_exact_source_key') AS source_exact_index_oid,
           to_regclass('brain.memory_sources_live_resource') AS source_index_oid,
           to_regclass('brain.memory_edges_target_revision') AS edge_index_oid,
           to_regprocedure('brain.authorize_evidence_source(uuid,text,uuid,uuid,bigint)') AS authorize_oid,
           to_regprocedure('brain.lock_evidence_source(uuid,text,uuid,uuid,bigint)') AS lock_oid,
           to_regprocedure('brain.record_evidence_claim(uuid,bigint,smallint,text,uuid,bigint,uuid)') AS record_claim_oid,
           to_regprocedure('brain.copy_evidence_claims(uuid,bigint,bigint,uuid)') AS copy_claims_oid,
           to_regprocedure('jobs.guard_application_mutation()') AS fence_oid
), expected_columns(relation_name,column_name,type_name,not_null,default_expression) AS (
    VALUES
      ('brain.memory_sources','id','uuid',true,'gen_random_uuid()'),
      ('brain.memory_sources','item_id','uuid',true,''),
      ('brain.memory_sources','revision','bigint',true,''),
      ('brain.memory_sources','ordinal','smallint',true,''),
      ('brain.memory_sources','mode','text',true,''),
      ('brain.memory_sources','kind','text',true,''),
      ('brain.memory_sources','source_project_id','uuid',false,''),
      ('brain.memory_sources','source_resource_id','uuid',false,''),
      ('brain.memory_sources','source_revision','bigint',false,''),
      ('brain.memory_sources','reference_sha256','bytea',false,''),
      ('brain.memory_sources','created_by','uuid',true,''),
      ('brain.memory_sources','created_at','timestamp with time zone',true,'statement_timestamp()'),
      ('brain.memory_edges','id','uuid',true,'gen_random_uuid()'),
      ('brain.memory_edges','from_item_id','uuid',true,''),
      ('brain.memory_edges','from_revision','bigint',true,''),
      ('brain.memory_edges','ordinal','smallint',true,''),
      ('brain.memory_edges','edge_type','text',true,''),
      ('brain.memory_edges','to_item_id','uuid',true,''),
      ('brain.memory_edges','to_revision','bigint',true,''),
      ('brain.memory_edges','created_by','uuid',true,''),
      ('brain.memory_edges','created_at','timestamp with time zone',true,'statement_timestamp()')
), actual_columns AS (
    SELECT attribute.attrelid::regclass::text,attribute.attname,format_type(attribute.atttypid,attribute.atttypmod),attribute.attnotnull,
           COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),'')
    FROM pg_attribute AS attribute
    LEFT JOIN pg_attrdef AS default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum,objects
    WHERE attribute.attrelid=ANY(ARRAY[sources_oid,edges_oid]) AND attribute.attnum>0 AND NOT attribute.attisdropped
), table_safety AS (
    SELECT count(*)=2 AND bool_and(relation.relkind='r' AND relation.relpersistence='p' AND NOT relation.relrowsecurity
        AND NOT relation.relforcerowsecurity AND pg_get_userbyid(relation.relowner)='punaro_owner') AS exact
    FROM pg_class AS relation,objects WHERE relation.oid=ANY(ARRAY[sources_oid,edges_oid])
), expected_relational_constraints(relation_name,constraint_name,constraint_type,column_keys,referenced_relation,referenced_keys,update_action,delete_action,match_type) AS (
    VALUES
      ('brain.memory_sources','memory_sources_pkey','p','{1}','','','','',''),
      ('brain.memory_sources','memory_sources_source_project_id_fkey','f','{7}','relay.projects','{1}','a','a','s'),
      ('brain.memory_sources','memory_sources_created_by_fkey','f','{11}','auth.principals','{1}','a','a','s'),
      ('brain.memory_sources','memory_sources_revision_fkey','f','{2,3}','brain.memory_revisions','{1,2}','a','c','s'),
      ('brain.memory_sources','memory_sources_item_revision_ordinal_key','u','{2,3,4}','','','','',''),
      ('brain.memory_sources','memory_sources_exact_source_key','u','{2,3,5,6,7,8,9,10}','','','','',''),
      ('brain.memory_edges','memory_edges_pkey','p','{1}','','','','',''),
      ('brain.memory_edges','memory_edges_created_by_fkey','f','{8}','auth.principals','{1}','a','a','s'),
      ('brain.memory_edges','memory_edges_from_revision_fkey','f','{2,3}','brain.memory_revisions','{1,2}','a','c','s'),
      ('brain.memory_edges','memory_edges_exact_key','u','{2,3,5,6,7}','','','','',''),
      ('brain.memory_edges','memory_edges_item_revision_ordinal_key','u','{2,3,4}','','','','','')
), actual_relational_constraints AS (
    SELECT constraint_row.conrelid::regclass::text,constraint_row.conname,constraint_row.contype::text,constraint_row.conkey::text,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confrelid::regclass::text ELSE '' END,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confkey::text ELSE '' END,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confupdtype::text ELSE '' END,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confdeltype::text ELSE '' END,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confmatchtype::text ELSE '' END
    FROM pg_constraint AS constraint_row,objects
    WHERE constraint_row.conrelid=ANY(ARRAY[sources_oid,edges_oid]) AND constraint_row.contype IN ('p','u','f')
      AND constraint_row.convalidated AND NOT constraint_row.condeferrable AND NOT constraint_row.condeferred
), expected_checks(relation_name,constraint_name,expression) AS (
    VALUES
      ('brain.memory_sources','memory_sources_revision_check','(revision >= 1)'),
      ('brain.memory_sources','memory_sources_ordinal_check','((ordinal >= 0) AND (ordinal <= 7))'),
      ('brain.memory_sources','memory_sources_mode_check','(mode = ANY (ARRAY[''copied''::text, ''live''::text]))'),
      ('brain.memory_sources','memory_sources_kind_check','(kind = ANY (ARRAY[''message''::text, ''attachment''::text, ''memory''::text, ''session''::text, ''import''::text, ''external''::text]))'),
      ('brain.memory_sources','memory_sources_source_revision_check','((source_revision IS NULL) OR (source_revision >= 1))'),
      ('brain.memory_sources','memory_sources_reference_sha256_check','((reference_sha256 IS NULL) OR (octet_length(reference_sha256) = 32))'),
      ('brain.memory_sources','memory_sources_shape_check','(((mode = ''copied''::text) AND (source_project_id IS NULL) AND (source_resource_id IS NULL) AND (source_revision IS NULL) AND (reference_sha256 IS NOT NULL)) OR ((mode = ''live''::text) AND (source_project_id IS NOT NULL) AND (source_resource_id IS NOT NULL) AND (reference_sha256 IS NULL) AND (((kind = ''memory''::text) AND (source_revision IS NOT NULL)) OR ((kind = ANY (ARRAY[''message''::text, ''attachment''::text])) AND (source_revision IS NULL)))))'),
      ('brain.memory_edges','memory_edges_from_revision_check','(from_revision >= 1)'),
      ('brain.memory_edges','memory_edges_ordinal_check','((ordinal >= 0) AND (ordinal <= 15))'),
      ('brain.memory_edges','memory_edges_type_check','(edge_type = ANY (ARRAY[''derived_from''::text, ''supports''::text, ''contradicts''::text, ''supersedes''::text]))'),
      ('brain.memory_edges','memory_edges_to_revision_check','(to_revision >= 1)'),
      ('brain.memory_edges','memory_edges_not_self_check','((from_item_id <> to_item_id) OR (from_revision <> to_revision))')
), actual_checks AS (
    SELECT constraint_row.conrelid::regclass::text,constraint_row.conname,pg_get_expr(constraint_row.conbin,constraint_row.conrelid)
    FROM pg_constraint AS constraint_row,objects
    WHERE constraint_row.conrelid=ANY(ARRAY[sources_oid,edges_oid]) AND constraint_row.contype='c'
      AND constraint_row.convalidated AND NOT constraint_row.condeferrable AND NOT constraint_row.condeferred
), constraint_safety AS (
    SELECT count(*)=23 AND bool_and(constraint_row.convalidated AND NOT constraint_row.condeferrable AND NOT constraint_row.condeferred) AS exact
    FROM pg_constraint AS constraint_row,objects
    WHERE constraint_row.conrelid=ANY(ARRAY[sources_oid,edges_oid]) AND constraint_row.contype<>'n'
), index_safety AS (
    SELECT count(*)=8 AND bool_and(index_row.indisvalid AND index_row.indisready) AS exact
    FROM pg_index AS index_row,objects WHERE index_row.indrelid=ANY(ARRAY[sources_oid,edges_oid])
), fence_safety AS (
    SELECT count(*)=2 AND bool_and(trigger_row.tgenabled='O' AND trigger_row.tgfoid=fence_oid AND trigger_row.tgtype=62) AS exact
    FROM pg_trigger AS trigger_row,objects
    WHERE trigger_row.tgrelid=ANY(ARRAY[sources_oid,edges_oid]) AND trigger_row.tgname='application_mutation_fence' AND NOT trigger_row.tgisinternal
), expected_table_acl(relation_name,grantee,privilege_type,is_grantable) AS (
    SELECT relation_name,'punaro_owner',privilege_type,false
    FROM (VALUES ('brain.memory_sources'),('brain.memory_edges')) AS relations(relation_name)
    CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),('REFERENCES'),('TRIGGER'),('MAINTAIN')) AS privileges(privilege_type)
    UNION ALL
    SELECT relation_name,'punaro_app','SELECT',false
    FROM (VALUES ('brain.memory_sources'),('brain.memory_edges')) AS relations(relation_name)
), actual_table_acl AS (
    SELECT relation.oid::regclass::text,COALESCE(grantee.rolname,'PUBLIC'),entry.privilege_type,entry.is_grantable
    FROM pg_class AS relation
    CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) AS entry
    LEFT JOIN pg_roles AS grantee ON grantee.oid=entry.grantee,objects
    WHERE relation.oid=ANY(ARRAY[sources_oid,edges_oid])
), expected_column_acl(relation_name,column_name,grantee,privilege_type,is_grantable) AS (
    SELECT 'brain.memory_sources',column_name,'punaro_app','INSERT',false
    FROM (VALUES ('item_id'),('revision'),('ordinal'),('mode'),('kind'),('source_project_id'),('source_resource_id'),('source_revision'),('reference_sha256'),('created_by')) AS columns(column_name)
), actual_column_acl AS (
    SELECT attribute.attrelid::regclass::text,attribute.attname,COALESCE(grantee.rolname,'PUBLIC'),entry.privilege_type,entry.is_grantable
    FROM pg_attribute AS attribute CROSS JOIN LATERAL aclexplode(attribute.attacl) AS entry
    LEFT JOIN pg_roles AS grantee ON grantee.oid=entry.grantee,objects
    WHERE attribute.attrelid=ANY(ARRAY[sources_oid,edges_oid]) AND attribute.attnum>0 AND NOT attribute.attisdropped AND attribute.attacl IS NOT NULL
), routine_safety AS (
    SELECT count(*)=4 AND bool_and(pg_get_userbyid(routine.proowner)='punaro_owner'
        AND routine.prokind='f' AND routine.prosecdef AND NOT routine.proretset
        AND NOT routine.proisstrict AND NOT routine.proleakproof AND routine.proparallel='u' AND routine.provariadic=0
        AND routine.proconfig=ARRAY['search_path=pg_catalog']::text[]
        AND ((routine.oid=authorize_oid AND routine.prorettype='boolean'::regtype AND routine.pronargs=5
              AND language.lanname='sql' AND routine.provolatile='s'
		      AND md5(btrim(routine.prosrc, E' \n\r\t'))='87f442f8d737d5f13d747304c45d3403')
          OR (routine.oid=lock_oid AND routine.prorettype='boolean'::regtype AND routine.pronargs=5
              AND language.lanname='plpgsql' AND routine.provolatile='v'
		      AND md5(btrim(routine.prosrc, E' \n\r\t'))='7baec7f39e031ad9db527cfeac3fd707')
          OR (routine.oid=record_claim_oid AND routine.prorettype='uuid'::regtype AND routine.pronargs=7
              AND language.lanname='plpgsql' AND routine.provolatile='v'
		      AND md5(btrim(routine.prosrc, E' \n\r\t'))='a7b66d8aad85cf3237eed2e52744047d')
          OR (routine.oid=copy_claims_oid AND routine.prorettype='integer'::regtype AND routine.pronargs=4
              AND language.lanname='plpgsql' AND routine.provolatile='v'
		      AND md5(btrim(routine.prosrc, E' \n\r\t'))='40975e6a2397f21f0eb45b365e994fc5'))) AS exact
	FROM pg_proc AS routine JOIN pg_language AS language ON language.oid=routine.prolang,objects
	WHERE routine.oid=ANY(ARRAY[authorize_oid,lock_oid,record_claim_oid,copy_claims_oid])
), routine_acl AS (
    SELECT count(*)=8 AND bool_and(entry.privilege_type='EXECUTE' AND NOT entry.is_grantable)
        AND bool_and(grantee.rolname IN ('punaro_owner','punaro_app')) AS exact
    FROM pg_proc AS routine
    CROSS JOIN LATERAL aclexplode(COALESCE(routine.proacl,acldefault('f',routine.proowner))) AS entry
    LEFT JOIN pg_roles AS grantee ON grantee.oid=entry.grantee,objects
    WHERE routine.oid=ANY(ARRAY[authorize_oid,lock_oid,record_claim_oid,copy_claims_oid])
)
SELECT items_oid IS NOT NULL AND sources_oid IS NOT NULL AND edges_oid IS NOT NULL
   AND source_exact_index_oid IS NOT NULL AND source_index_oid IS NOT NULL AND edge_index_oid IS NOT NULL
   AND authorize_oid IS NOT NULL AND lock_oid IS NOT NULL AND record_claim_oid IS NOT NULL AND copy_claims_oid IS NOT NULL AND fence_oid IS NOT NULL
   AND table_safety.exact AND constraint_safety.exact AND index_safety.exact AND fence_safety.exact
   AND routine_safety.exact AND routine_acl.exact
   AND NOT EXISTS (SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns)
   AND NOT EXISTS (SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)
   AND NOT EXISTS (SELECT * FROM expected_relational_constraints EXCEPT SELECT * FROM actual_relational_constraints)
   AND NOT EXISTS (SELECT * FROM actual_relational_constraints EXCEPT SELECT * FROM expected_relational_constraints)
   AND NOT EXISTS (SELECT * FROM expected_checks EXCEPT SELECT * FROM actual_checks)
   AND NOT EXISTS (SELECT * FROM actual_checks EXCEPT SELECT * FROM expected_checks)
   AND NOT EXISTS (SELECT * FROM expected_table_acl EXCEPT SELECT * FROM actual_table_acl)
   AND NOT EXISTS (SELECT * FROM actual_table_acl EXCEPT SELECT * FROM expected_table_acl)
   AND NOT EXISTS (SELECT * FROM expected_column_acl EXCEPT SELECT * FROM actual_column_acl)
   AND NOT EXISTS (SELECT * FROM actual_column_acl EXCEPT SELECT * FROM expected_column_acl)
   AND EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid=items_oid AND attname='layer' AND atttypid='text'::regtype
       AND attnotnull AND pg_get_expr((SELECT adbin FROM pg_attrdef WHERE adrelid=items_oid AND adnum=attnum),items_oid)='''curated''::text')
   AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=items_oid AND conname='memory_items_layer_check' AND convalidated
       AND pg_get_expr(conbin,conrelid)='(layer = ANY (ARRAY[''curated''::text, ''evidence''::text]))')
   AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=sources_oid AND conname='memory_sources_shape_check' AND convalidated)
   AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=edges_oid AND conname='memory_edges_not_self_check' AND convalidated)
   AND EXISTS (SELECT 1 FROM pg_index WHERE indexrelid=source_exact_index_oid AND indrelid=sources_oid AND indisunique
       AND indisvalid AND indisready AND indnullsnotdistinct AND indkey='2 3 5 6 7 8 9 10'::int2vector AND indexprs IS NULL AND indpred IS NULL)
   AND EXISTS (SELECT 1 FROM pg_index WHERE indexrelid=source_index_oid AND indrelid=sources_oid AND NOT indisunique
       AND indisvalid AND indisready AND indkey='7 6 8 9'::int2vector AND indexprs IS NULL AND pg_get_expr(indpred,indrelid)='(mode = ''live''::text)')
   AND EXISTS (SELECT 1 FROM pg_index WHERE indexrelid=edge_index_oid AND indrelid=edges_oid AND NOT indisunique
       AND indisvalid AND indisready AND indkey='6 7 5 2 3'::int2vector AND indexprs IS NULL AND indpred IS NULL)
   AND has_function_privilege('punaro_app',authorize_oid,'EXECUTE')
   AND has_function_privilege('punaro_app',lock_oid,'EXECUTE')
   AND has_function_privilege('punaro_app',record_claim_oid,'EXECUTE')
   AND has_function_privilege('punaro_app',copy_claims_oid,'EXECUTE')
FROM objects,table_safety,constraint_safety,index_safety,fence_safety,routine_safety,routine_acl`).Scan(&available)
	return available, err
}
