package postgres

import "context"

// memoryEmbeddingRebuildControlsAvailable verifies the schema-v26 boundary:
// a schema-owner-only building generation may be created beside, but never
// replaces, the immutable active generation in this slice.
func memoryEmbeddingRebuildControlsAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `WITH objects AS (
    SELECT to_regclass('brain.embedding_generations') AS generations_oid,
           to_regprocedure('brain.start_embedding_generation(text,text,integer)') AS start_oid,
           to_regprocedure('brain.queue_embedding_revision()') AS queue_oid
), generation_state AS (
    SELECT count(*) = 1 AND bool_and(constraint_row.convalidated AND NOT constraint_row.condeferrable
        AND NOT constraint_row.condeferred AND pg_get_expr(constraint_row.conbin,constraint_row.conrelid)
        = '(((state = ''active''::text) AND (start_change_sequence IS NULL)) OR ((state = ''building''::text) AND (start_change_sequence >= 0)))') AS exact
    FROM pg_constraint AS constraint_row,objects
    WHERE constraint_row.conrelid=generations_oid AND constraint_row.conname='embedding_generations_state_check'
), generation_tuple AS (
    SELECT NOT EXISTS (
        SELECT 1
        FROM pg_constraint AS constraint_row,objects
        WHERE constraint_row.conrelid=generations_oid
          AND constraint_row.conname='embedding_generations_model_model_revision_dimensions_key'
    ) AS exact
), routines AS (
    SELECT count(*) = 2 AND bool_and(proc.prokind='f' AND proc.prosecdef AND proc.provolatile='v'
        AND proc.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
        AND proc.proconfig=ARRAY['search_path=pg_catalog']::text[]
        AND pg_get_userbyid(proc.proowner)='punaro_owner'
        AND ((proc.oid=queue_oid AND md5(btrim(proc.prosrc,E' \n\r\t'))=$1)
          OR (proc.oid=start_oid AND md5(btrim(proc.prosrc,E' \n\r\t'))=$2))) AS exact
    FROM pg_proc AS proc,objects WHERE proc.oid=ANY(ARRAY[start_oid,queue_oid])
), start_signature AS (
    SELECT start_oid IS NOT NULL AND pg_get_function_result(start_oid)='TABLE(generation_id uuid, start_change_sequence bigint)'
       AS exact
    FROM objects
), expected_start_acl(grantee,privilege_type,is_grantable) AS (
    VALUES ('punaro_owner','EXECUTE',false)
), actual_start_acl AS (
    SELECT COALESCE(role.rolname,'PUBLIC'),entry.privilege_type,entry.is_grantable
    FROM pg_proc AS proc
    CROSS JOIN LATERAL aclexplode(COALESCE(proc.proacl,acldefault('f',proc.proowner))) AS entry
    LEFT JOIN pg_roles AS role ON role.oid=entry.grantee,objects
    WHERE proc.oid=start_oid
), start_acl AS (
    SELECT NOT EXISTS (SELECT * FROM expected_start_acl EXCEPT SELECT * FROM actual_start_acl)
       AND NOT EXISTS (SELECT * FROM actual_start_acl EXCEPT SELECT * FROM expected_start_acl) AS exact
)
SELECT generations_oid IS NOT NULL AND start_oid IS NOT NULL AND queue_oid IS NOT NULL
   AND generation_state.exact AND generation_tuple.exact AND routines.exact AND start_signature.exact AND start_acl.exact
FROM objects,generation_state,generation_tuple,routines,start_signature,start_acl`, memoryEmbeddingRebuildQueueRoutineMD5, memoryEmbeddingRebuildStartRoutineMD5).Scan(&available)
	return available, err
}

const (
	memoryEmbeddingRebuildQueueRoutineMD5 = "b09c65e6d07819ec41948de85675de5c"
	memoryEmbeddingRebuildStartRoutineMD5 = "ef8ca889c0937b89d9ea3406aff994c4"
)
