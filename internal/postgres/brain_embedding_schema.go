package postgres

import "context"

// memoryEmbeddingControlsAvailable verifies the schema-v23 derived-work
// frontier. Canonical memory remains usable when no generation exists, but a
// migrated database must never silently accept a damaged queue or weakened
// application-role boundary.
func memoryEmbeddingControlsAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `
WITH objects AS (
    SELECT to_regclass('brain.embedding_generations') AS generations_oid,
           to_regclass('brain.embedding_jobs') AS jobs_oid,
           to_regclass('brain.embedding_generations_one_active') AS active_index_oid,
           to_regclass('brain.embedding_jobs_claim_order') AS claim_index_oid,
           to_regclass('brain.embedding_jobs_expired_lease') AS expired_index_oid,
           to_regprocedure('brain.queue_embedding_revision()') AS queue_oid,
           to_regprocedure('brain.reject_embedding_generation_mutation()') AS immutable_oid
), expected_columns(relation_name,column_name,type_name,required) AS (
    VALUES
      ('brain.embedding_generations','id','uuid',true),
      ('brain.embedding_generations','model','text',true),
      ('brain.embedding_generations','model_revision','text',true),
      ('brain.embedding_generations','dimensions','integer',true),
      ('brain.embedding_generations','state','text',true),
      ('brain.embedding_generations','created_at','timestamp with time zone',true),
      ('brain.embedding_jobs','generation_id','uuid',true),
      ('brain.embedding_jobs','item_id','uuid',true),
      ('brain.embedding_jobs','revision','bigint',true),
      ('brain.embedding_jobs','content_sha256','bytea',true),
      ('brain.embedding_jobs','state','text',true),
      ('brain.embedding_jobs','attempts','integer',true),
      ('brain.embedding_jobs','lease_holder','uuid',false),
      ('brain.embedding_jobs','lease_token','uuid',false),
      ('brain.embedding_jobs','lease_generation','bigint',true),
      ('brain.embedding_jobs','lease_until','timestamp with time zone',false),
      ('brain.embedding_jobs','last_error_code','text',false),
      ('brain.embedding_jobs','created_at','timestamp with time zone',true),
      ('brain.embedding_jobs','updated_at','timestamp with time zone',true),
      ('brain.embedding_jobs','completed_at','timestamp with time zone',false)
), actual_columns AS (
    SELECT attribute.attrelid::regclass::text,attribute.attname,attribute.atttypid::regtype::text,attribute.attnotnull
    FROM pg_attribute AS attribute,objects
    WHERE attribute.attrelid=ANY(ARRAY[generations_oid,jobs_oid]) AND attribute.attnum>0 AND NOT attribute.attisdropped
), table_safety AS (
    SELECT count(*)=2 AND bool_and(pg_get_userbyid(relation.relowner)='punaro_owner') AS exact
    FROM pg_class AS relation,objects WHERE relation.oid=ANY(ARRAY[generations_oid,jobs_oid])
), trigger_safety AS (
    SELECT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid=generations_oid AND tgname='embedding_generation_immutable'
                   AND tgenabled='O' AND NOT tgisinternal AND tgfoid=immutable_oid AND tgtype=27)
       AND EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='brain.memory_revisions'::regclass AND tgname='memory_revision_embedding_queue'
                   AND tgenabled='O' AND NOT tgisinternal AND tgfoid=queue_oid AND tgtype=5) AS exact
    FROM objects
), index_safety AS (
    SELECT active_index_oid IS NOT NULL AND claim_index_oid IS NOT NULL AND expired_index_oid IS NOT NULL
      AND EXISTS (SELECT 1 FROM pg_index WHERE indexrelid=active_index_oid AND indisunique AND indisvalid AND indisready)
      AND EXISTS (SELECT 1 FROM pg_index WHERE indexrelid=claim_index_oid AND NOT indisunique AND indisvalid AND indisready AND pg_get_expr(indpred,indrelid)='(state = ''queued''::text)')
      AND EXISTS (SELECT 1 FROM pg_index WHERE indexrelid=expired_index_oid AND NOT indisunique AND indisvalid AND indisready AND pg_get_expr(indpred,indrelid)='(state = ''running''::text)') AS exact
    FROM objects
)
SELECT generations_oid IS NOT NULL AND jobs_oid IS NOT NULL AND queue_oid IS NOT NULL AND immutable_oid IS NOT NULL
   AND table_safety.exact AND trigger_safety.exact AND index_safety.exact
   AND NOT EXISTS (SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns)
   AND NOT EXISTS (SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)
   AND has_table_privilege('punaro_app',generations_oid,'SELECT')
   AND has_table_privilege('punaro_app',jobs_oid,'SELECT')
	AND NOT has_table_privilege('punaro_app',generations_oid,'INSERT')
	AND NOT has_table_privilege('punaro_app',generations_oid,'UPDATE')
	AND NOT has_table_privilege('punaro_app',generations_oid,'DELETE')
	AND NOT has_table_privilege('punaro_app',jobs_oid,'INSERT')
	AND NOT has_table_privilege('punaro_app',jobs_oid,'UPDATE')
	AND NOT has_table_privilege('punaro_app',jobs_oid,'DELETE')
FROM objects,table_safety,trigger_safety,index_safety`).Scan(&available)
	return available, err
}
