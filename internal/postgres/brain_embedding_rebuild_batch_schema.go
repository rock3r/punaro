package postgres

import "context"

// memoryEmbeddingRebuildBatchControlsAvailable verifies the schema-v27 bounded
// rebuild boundary. The progress cursor is owner-only and the batch routine is
// the sole authority that may advance it or enqueue historical work.
func memoryEmbeddingRebuildBatchControlsAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `WITH objects AS (
    SELECT to_regclass('brain.embedding_rebuild_progress') AS progress_oid,
           to_regprocedure('brain.enqueue_embedding_rebuild_batch(uuid,integer)') AS batch_oid
), expected_columns(relation_name,column_name,type_name,not_null,default_expression) AS (
    VALUES
      ('brain.embedding_rebuild_progress','generation_id','uuid',true,''),
      ('brain.embedding_rebuild_progress','timeline_id','uuid',true,''),
      ('brain.embedding_rebuild_progress','timeline_watermark','bigint',true,''),
      ('brain.embedding_rebuild_progress','cursor_change_sequence','bigint',true,'0'),
      ('brain.embedding_rebuild_progress','reported_progress','bigint',true,'0'),
      ('brain.embedding_rebuild_progress','complete','boolean',true,'false')
), actual_columns AS (
    SELECT attribute.attrelid::regclass::text,attribute.attname,format_type(attribute.atttypid,attribute.atttypmod),attribute.attnotnull,
           COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),'')
    FROM pg_attribute AS attribute
    LEFT JOIN pg_attrdef AS default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum,objects
    WHERE attribute.attrelid=progress_oid AND attribute.attnum>0 AND NOT attribute.attisdropped
), table_safety AS (
    SELECT count(*)=1 AND bool_and(relation.relkind='r' AND relation.relpersistence='p' AND NOT relation.relrowsecurity
        AND NOT relation.relforcerowsecurity AND pg_get_userbyid(relation.relowner)='punaro_owner') AS exact
    FROM pg_class AS relation,objects WHERE relation.oid=progress_oid
), expected_relational_constraints(relation_name,constraint_name,constraint_type,column_keys,referenced_relation,referenced_keys,update_action,delete_action,match_type) AS (
    VALUES
      ('brain.embedding_rebuild_progress','embedding_rebuild_progress_pkey','p','{1}','','','','',''),
      ('brain.embedding_rebuild_progress','embedding_rebuild_progress_generation_id_fkey','f','{1}','brain.embedding_generations','{1}','a','c','s')
), actual_relational_constraints AS (
    SELECT constraint_row.conrelid::regclass::text,constraint_row.conname,constraint_row.contype::text,constraint_row.conkey::text,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confrelid::regclass::text ELSE '' END,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confkey::text ELSE '' END,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confupdtype::text ELSE '' END,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confdeltype::text ELSE '' END,
           CASE WHEN constraint_row.contype='f' THEN constraint_row.confmatchtype::text ELSE '' END
    FROM pg_constraint AS constraint_row,objects
    WHERE constraint_row.conrelid=progress_oid AND constraint_row.contype IN ('p','f')
      AND constraint_row.convalidated AND NOT constraint_row.condeferrable AND NOT constraint_row.condeferred
), expected_checks(relation_name,constraint_name,expression) AS (
    VALUES
      ('brain.embedding_rebuild_progress','embedding_rebuild_progress_cursor_change_sequence_check','(cursor_change_sequence >= 0)'),
      ('brain.embedding_rebuild_progress','embedding_rebuild_progress_reported_progress_check','(reported_progress >= 0)'),
      ('brain.embedding_rebuild_progress','embedding_rebuild_progress_timeline_watermark_check','(timeline_watermark >= 0)')
), actual_checks AS (
    SELECT constraint_row.conrelid::regclass::text,constraint_row.conname,pg_get_expr(constraint_row.conbin,constraint_row.conrelid)
    FROM pg_constraint AS constraint_row,objects
    WHERE constraint_row.conrelid=progress_oid AND constraint_row.contype='c'
      AND constraint_row.convalidated AND NOT constraint_row.condeferrable AND NOT constraint_row.condeferred
), constraint_safety AS (
    SELECT count(*)=5 AND bool_and(constraint_row.convalidated AND NOT constraint_row.condeferrable AND NOT constraint_row.condeferred) AS exact
    FROM pg_constraint AS constraint_row,objects
    WHERE constraint_row.conrelid=progress_oid AND constraint_row.contype<>'n'
), routine_safety AS (
    SELECT count(*)=1 AND bool_and(pg_get_userbyid(proc.proowner)='punaro_owner' AND proc.prokind='f'
        AND pg_get_function_result(proc.oid)='TABLE(enqueued integer, cursor_change_sequence bigint, complete boolean)'
        AND proc.prosecdef AND proc.provolatile='v'
        AND proc.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
        AND proc.proconfig=ARRAY['search_path=pg_catalog']::text[]
        AND md5(btrim(proc.prosrc,E' \n\r\t'))=$1) AS exact
    FROM pg_proc AS proc,objects WHERE proc.oid=batch_oid
), expected_routine_acl(grantee,privilege_type,is_grantable) AS (
    VALUES ('punaro_owner','EXECUTE',false)
), actual_routine_acl AS (
    SELECT COALESCE(role.rolname,'PUBLIC'),entry.privilege_type,entry.is_grantable
    FROM pg_proc AS proc
    CROSS JOIN LATERAL aclexplode(COALESCE(proc.proacl,acldefault('f',proc.proowner))) AS entry
    LEFT JOIN pg_roles AS role ON role.oid=entry.grantee,objects
    WHERE proc.oid=batch_oid
), routine_acl AS (
    SELECT NOT EXISTS (SELECT * FROM expected_routine_acl EXCEPT SELECT * FROM actual_routine_acl)
       AND NOT EXISTS (SELECT * FROM actual_routine_acl EXCEPT SELECT * FROM expected_routine_acl) AS exact
), column_acl AS (
    SELECT NOT EXISTS (
        SELECT 1 FROM pg_attribute AS attribute,objects
        WHERE attribute.attrelid=progress_oid AND attribute.attnum>0 AND NOT attribute.attisdropped AND attribute.attacl IS NOT NULL
    ) AS exact
), table_acl AS (
    SELECT count(*)=8 AND bool_and(role.rolname='punaro_owner' AND NOT entry.is_grantable) AS exact
    FROM pg_class AS relation
    CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) AS entry
    LEFT JOIN pg_roles AS role ON role.oid=entry.grantee,objects
    WHERE relation.oid=progress_oid
)
SELECT progress_oid IS NOT NULL AND batch_oid IS NOT NULL
   AND table_safety.exact AND constraint_safety.exact AND routine_safety.exact AND routine_acl.exact
   AND column_acl.exact AND table_acl.exact
   AND NOT EXISTS (SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns)
   AND NOT EXISTS (SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)
   AND NOT EXISTS (SELECT * FROM expected_relational_constraints EXCEPT SELECT * FROM actual_relational_constraints)
   AND NOT EXISTS (SELECT * FROM actual_relational_constraints EXCEPT SELECT * FROM expected_relational_constraints)
   AND NOT EXISTS (SELECT * FROM expected_checks EXCEPT SELECT * FROM actual_checks)
   AND NOT EXISTS (SELECT * FROM actual_checks EXCEPT SELECT * FROM expected_checks)
   AND NOT has_table_privilege('punaro_app',progress_oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
FROM objects,table_safety,constraint_safety,routine_safety,routine_acl,column_acl,table_acl`, memoryEmbeddingRebuildBatchRoutineMD5).Scan(&available)
	return available, err
}

const memoryEmbeddingRebuildBatchRoutineMD5 = "3ee4777558c46f798e81ffeb301ca3cb"
