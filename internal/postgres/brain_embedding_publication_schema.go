package postgres

import "context"

// memoryEmbeddingPublicationControlsAvailable verifies the exact schema-v25
// derived-chunk authority. A migrated database must fail readiness if any
// publication fence, referential boundary, or application privilege drifts.
func memoryEmbeddingPublicationControlsAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `WITH objects AS (
    SELECT to_regclass('brain.embedding_chunks') AS chunks_oid,
           to_regprocedure('brain.publish_embedding_job(uuid,uuid,bigint,bytea,uuid,bigint,jsonb)') AS publish_oid,
           to_regprocedure('jobs.guard_application_mutation()') AS fence_oid
), expected_columns(relation_name,column_name,type_name,not_null,default_expression) AS (
    VALUES
      ('brain.embedding_chunks','generation_id','uuid',true,''),
      ('brain.embedding_chunks','item_id','uuid',true,''),
      ('brain.embedding_chunks','revision','bigint',true,''),
      ('brain.embedding_chunks','ordinal','smallint',true,''),
      ('brain.embedding_chunks','content_sha256','bytea',true,''),
      ('brain.embedding_chunks','start_offset','integer',true,''),
      ('brain.embedding_chunks','end_offset','integer',true,''),
      ('brain.embedding_chunks','created_at','timestamp with time zone',true,'statement_timestamp()')
), actual_columns AS (
    SELECT attribute.attrelid::regclass::text,attribute.attname,format_type(attribute.atttypid,attribute.atttypmod),attribute.attnotnull,
           COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),'')
    FROM pg_attribute AS attribute
    LEFT JOIN pg_attrdef AS default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum,objects
    WHERE attribute.attrelid=chunks_oid AND attribute.attnum>0 AND NOT attribute.attisdropped
), table_safety AS (
    SELECT count(*)=1 AND bool_and(relation.relkind='r' AND relation.relpersistence='p' AND NOT relation.relrowsecurity
        AND NOT relation.relforcerowsecurity AND pg_get_userbyid(relation.relowner)='punaro_owner') AS exact
    FROM pg_class AS relation,objects WHERE relation.oid=chunks_oid
), expected_relational_constraints(relation_name,constraint_name,constraint_type,column_keys,referenced_relation,referenced_keys,update_action,delete_action,match_type) AS (
    VALUES
      ('brain.embedding_chunks','embedding_chunks_pkey','p','{1,2,3,4}','','','','',''),
      ('brain.embedding_chunks','embedding_chunks_generation_id_fkey','f','{1}','brain.embedding_generations','{1}','a','a','s'),
      ('brain.embedding_chunks','embedding_chunks_item_id_revision_fkey','f','{2,3}','brain.memory_revisions','{1,2}','a','c','s')
), actual_relational_constraints AS (
    SELECT constraint_row.conrelid::regclass::text,constraint_row.conname,constraint_row.contype::text,constraint_row.conkey::text,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confrelid::regclass::text ELSE '' END,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confkey::text ELSE '' END,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confupdtype::text ELSE '' END,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confdeltype::text ELSE '' END,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confmatchtype::text ELSE '' END
    FROM pg_constraint AS constraint_row,objects
    WHERE constraint_row.conrelid=chunks_oid AND constraint_row.contype IN ('p','f')
      AND constraint_row.convalidated AND NOT constraint_row.condeferrable AND NOT constraint_row.condeferred
), expected_checks(relation_name,constraint_name,expression) AS (
    VALUES
      ('brain.embedding_chunks','embedding_chunks_revision_check','(revision >= 1)'),
      ('brain.embedding_chunks','embedding_chunks_ordinal_check','((ordinal >= 0) AND (ordinal <= 63))'),
      ('brain.embedding_chunks','embedding_chunks_content_sha256_check','(octet_length(content_sha256) = 32)'),
      ('brain.embedding_chunks','embedding_chunks_start_offset_check','(start_offset >= 0)'),
      ('brain.embedding_chunks','embedding_chunks_check','((end_offset > start_offset) AND (end_offset <= 262144))')
), actual_checks AS (
    SELECT constraint_row.conrelid::regclass::text,constraint_row.conname,pg_get_expr(constraint_row.conbin,constraint_row.conrelid)
    FROM pg_constraint AS constraint_row,objects
    WHERE constraint_row.conrelid=chunks_oid AND constraint_row.contype='c'
      AND constraint_row.convalidated AND NOT constraint_row.condeferrable AND NOT constraint_row.condeferred
), constraint_safety AS (
    SELECT count(*)=8 AND bool_and(constraint_row.convalidated AND NOT constraint_row.condeferrable AND NOT constraint_row.condeferred) AS exact
    FROM pg_constraint AS constraint_row,objects
    WHERE constraint_row.conrelid=chunks_oid AND constraint_row.contype<>'n'
), index_safety AS (
    SELECT count(*)=1 AND bool_and(index_row.indisvalid AND index_row.indisready AND index_row.indisunique
        AND index_row.indkey='1 2 3 4'::int2vector AND index_row.indexprs IS NULL AND index_row.indpred IS NULL) AS exact
    FROM pg_index AS index_row,objects WHERE index_row.indrelid=chunks_oid
), fence_safety AS (
    SELECT count(*)=1 AND bool_and(trigger_row.tgname='application_mutation_fence' AND trigger_row.tgenabled='O' AND trigger_row.tgfoid=fence_oid AND trigger_row.tgtype=62) AS exact
    FROM pg_trigger AS trigger_row,objects
    WHERE trigger_row.tgrelid=chunks_oid AND NOT trigger_row.tgisinternal
), routine_safety AS (
    SELECT count(*)=1 AND bool_and(pg_get_userbyid(proc.proowner)='punaro_owner' AND proc.prokind='f'
        AND proc.prorettype='boolean'::regtype AND NOT proc.proretset AND proc.prosecdef
        AND proc.provolatile='v' AND proc.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
        AND proc.proconfig=ARRAY['search_path=pg_catalog']::text[]
        AND md5(btrim(proc.prosrc,E' \n\r\t'))='2a5bb540102e4944f41c63c31a5aed49') AS exact
    FROM pg_proc AS proc,objects WHERE proc.oid=publish_oid
), expected_routine_acl(grantee,privilege_type,is_grantable) AS (
    VALUES ('punaro_owner','EXECUTE',false),('punaro_app','EXECUTE',false)
), actual_routine_acl AS (
    SELECT COALESCE(role.rolname,'PUBLIC'),entry.privilege_type,entry.is_grantable
    FROM pg_proc AS proc
    CROSS JOIN LATERAL aclexplode(COALESCE(proc.proacl,acldefault('f',proc.proowner))) AS entry
    LEFT JOIN pg_roles AS role ON role.oid=entry.grantee,objects
    WHERE proc.oid=publish_oid
), routine_acl AS (
    SELECT NOT EXISTS (SELECT * FROM expected_routine_acl EXCEPT SELECT * FROM actual_routine_acl)
       AND NOT EXISTS (SELECT * FROM actual_routine_acl EXCEPT SELECT * FROM expected_routine_acl) AS exact
), column_acl AS (
    SELECT NOT EXISTS (
        SELECT 1
        FROM pg_attribute AS attribute,objects
        WHERE attribute.attrelid=chunks_oid AND attribute.attnum>0 AND NOT attribute.attisdropped
          AND attribute.attacl IS NOT NULL
    ) AS exact
), table_acl AS (
    SELECT count(*)=9 AND bool_and(NOT entry.is_grantable)
       AND bool_and(role.rolname='punaro_owner' OR (role.rolname='punaro_app' AND entry.privilege_type='SELECT')) AS exact
    FROM pg_class AS relation
    CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) AS entry
    LEFT JOIN pg_roles AS role ON role.oid=entry.grantee,objects
    WHERE relation.oid=chunks_oid
)
SELECT chunks_oid IS NOT NULL AND publish_oid IS NOT NULL AND fence_oid IS NOT NULL
   AND table_safety.exact AND constraint_safety.exact AND index_safety.exact AND fence_safety.exact
   AND routine_safety.exact AND routine_acl.exact AND column_acl.exact AND table_acl.exact
   AND NOT EXISTS (SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns)
   AND NOT EXISTS (SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)
   AND NOT EXISTS (SELECT * FROM expected_relational_constraints EXCEPT SELECT * FROM actual_relational_constraints)
   AND NOT EXISTS (SELECT * FROM actual_relational_constraints EXCEPT SELECT * FROM expected_relational_constraints)
   AND NOT EXISTS (SELECT * FROM expected_checks EXCEPT SELECT * FROM actual_checks)
   AND NOT EXISTS (SELECT * FROM actual_checks EXCEPT SELECT * FROM expected_checks)
   AND has_table_privilege('punaro_app',chunks_oid,'SELECT')
   AND NOT has_table_privilege('punaro_app',chunks_oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
FROM objects,table_safety,constraint_safety,index_safety,fence_safety,routine_safety,routine_acl,column_acl,table_acl`).Scan(&available)
	return available, err
}
