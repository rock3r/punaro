package postgres

import "context"

// memoryEmbeddingVectorControlsAvailable verifies v29's derived vector
// payload. It intentionally forbids vector indexes: approximate indexing is a
// separately benchmark-gated decision, not an incidental schema side effect.
func memoryEmbeddingVectorControlsAvailable(ctx context.Context, q queryer) (bool, error) {
	var exact bool
	if err := q.QueryRowContext(ctx, `SELECT EXISTS (
    SELECT 1 FROM pg_extension AS ext
    WHERE ext.extname='vector' AND ext.extnamespace='public'::regnamespace
      AND pg_get_userbyid(ext.extowner)='punaro_owner'
) AND (SELECT array_agg(attribute.attname::text ORDER BY attribute.attnum)=ARRAY['generation_id','item_id','revision','ordinal','content_sha256','start_offset','end_offset','created_at','embedding']::text[]
         FROM pg_attribute AS attribute
         WHERE attribute.attrelid='brain.embedding_chunks'::regclass AND attribute.attnum>0 AND NOT attribute.attisdropped)
  AND EXISTS (
    SELECT 1 FROM pg_attribute AS attribute
    WHERE attribute.attrelid='brain.embedding_chunks'::regclass AND attribute.attname='embedding'
      AND attribute.attnotnull AND format_type(attribute.atttypid,attribute.atttypmod)='vector' AND attribute.attacl IS NULL
)`).Scan(&exact); err != nil || !exact {
		return exact, err
	}
	if err := q.QueryRowContext(ctx, `SELECT pg_get_userbyid(relation.relowner)='punaro_owner'
    AND relation.relkind='r' AND NOT relation.relrowsecurity
    AND has_table_privilege('punaro_app',relation.oid,'SELECT')
    AND NOT has_table_privilege('punaro_app',relation.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
FROM pg_class AS relation WHERE relation.oid='brain.embedding_chunks'::regclass`).Scan(&exact); err != nil || !exact {
		return exact, err
	}
	if err := q.QueryRowContext(ctx, `SELECT count(*)=1 AND bool_and(pg_get_userbyid(proc.proowner)='punaro_owner' AND proc.prokind='f'
    AND proc.prorettype='boolean'::regtype AND NOT proc.proretset AND proc.prosecdef AND proc.provolatile='v'
    AND proc.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql') AND proc.proconfig=ARRAY['search_path=pg_catalog']::text[]
    AND md5(btrim(proc.prosrc,E' \n\r\t'))=$1)
FROM pg_proc AS proc WHERE proc.oid=to_regprocedure('brain.publish_embedding_job(uuid,uuid,bigint,bytea,uuid,bigint,jsonb)')`, memoryEmbeddingVectorPublicationRoutineMD5).Scan(&exact); err != nil || !exact {
		return exact, err
	}
	if err := q.QueryRowContext(ctx, `SELECT count(*)=2 AND bool_and(trigger_row.tgenabled='O')
    AND bool_and((trigger_row.tgname='application_mutation_fence' AND trigger_row.tgfoid=to_regprocedure('jobs.guard_application_mutation()') AND trigger_row.tgtype=54)
                 OR (trigger_row.tgname='embedding_chunks_delete_fence' AND trigger_row.tgfoid=to_regprocedure('brain.guard_embedding_chunk_delete()') AND trigger_row.tgtype=11))
FROM pg_trigger AS trigger_row WHERE trigger_row.tgrelid='brain.embedding_chunks'::regclass AND NOT trigger_row.tgisinternal`).Scan(&exact); err != nil || !exact {
		return exact, err
	}
	if err := q.QueryRowContext(ctx, `SELECT NOT EXISTS (
    SELECT 1 FROM pg_index AS index_row
    JOIN pg_attribute AS attribute ON attribute.attrelid=index_row.indrelid
      AND attribute.attname='embedding' AND attribute.attnum=ANY(index_row.indkey::smallint[])
    WHERE index_row.indrelid='brain.embedding_chunks'::regclass
)`).Scan(&exact); err != nil {
		return false, err
	}
	return exact, nil
}

const memoryEmbeddingVectorPublicationRoutineMD5 = "7c5f2698ecd2998cafcaf13e1d54992a"
