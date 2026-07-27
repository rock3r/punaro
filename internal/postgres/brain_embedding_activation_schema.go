package postgres

import "context"

// memoryEmbeddingActivationControlsAvailable verifies the schema-v28 promotion
// fence: only the owner may retire an active derived generation and activate a
// fully rebuilt generation.
func memoryEmbeddingActivationControlsAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `WITH objects AS (
    SELECT to_regprocedure('brain.activate_embedding_generation(uuid)') AS activate_oid,
           to_regprocedure('brain.guard_embedding_chunk_delete()') AS delete_guard_oid,
           to_regprocedure('brain.reject_embedding_generation_mutation()') AS immutable_oid,
           'brain.embedding_generations'::regclass AS generations_oid,
           'brain.embedding_chunks'::regclass AS chunks_oid
), routines AS (
    SELECT count(*)=3 AND bool_and(pg_get_userbyid(proc.proowner)='punaro_owner' AND proc.prokind='f'
        AND proc.prosecdef AND proc.provolatile='v'
        AND proc.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
        AND proc.proconfig=ARRAY['search_path=pg_catalog']::text[]
        AND ((proc.oid=activate_oid AND pg_get_function_result(proc.oid)='TABLE(generation_id uuid)' AND md5(btrim(proc.prosrc,E' \n\r\t'))=$1)
          OR (proc.oid=delete_guard_oid AND pg_get_function_result(proc.oid)='trigger' AND md5(btrim(proc.prosrc,E' \n\r\t'))=$2)
          OR (proc.oid=immutable_oid AND pg_get_function_result(proc.oid)='trigger' AND md5(btrim(proc.prosrc,E' \n\r\t'))=$3))) AS exact
    FROM pg_proc AS proc,objects WHERE proc.oid=ANY(ARRAY[activate_oid,delete_guard_oid,immutable_oid])
), activation_acl AS (
    SELECT NOT EXISTS (SELECT * FROM (VALUES ('punaro_owner','EXECUTE',false)) AS expected(grantee,privilege_type,is_grantable)
                       EXCEPT SELECT COALESCE(role.rolname,'PUBLIC'),entry.privilege_type,entry.is_grantable FROM pg_proc AS proc CROSS JOIN LATERAL aclexplode(COALESCE(proc.proacl,acldefault('f',proc.proowner))) AS entry LEFT JOIN pg_roles AS role ON role.oid=entry.grantee,objects WHERE proc.oid=activate_oid)
       AND NOT EXISTS (SELECT COALESCE(role.rolname,'PUBLIC'),entry.privilege_type,entry.is_grantable FROM pg_proc AS proc CROSS JOIN LATERAL aclexplode(COALESCE(proc.proacl,acldefault('f',proc.proowner))) AS entry LEFT JOIN pg_roles AS role ON role.oid=entry.grantee,objects WHERE proc.oid=activate_oid
                       EXCEPT SELECT * FROM (VALUES ('punaro_owner','EXECUTE',false)) AS expected(grantee,privilege_type,is_grantable)) AS exact
), triggers AS (
    SELECT EXISTS (SELECT 1 FROM pg_trigger,objects WHERE tgrelid=generations_oid AND tgname='embedding_generation_immutable' AND tgenabled='O' AND tgfoid=immutable_oid AND tgtype=27)
       AND EXISTS (SELECT 1 FROM pg_trigger,objects WHERE tgrelid=chunks_oid AND tgname='embedding_chunks_delete_fence' AND tgenabled='O' AND tgfoid=delete_guard_oid AND tgtype=11) AS exact
)
SELECT activate_oid IS NOT NULL AND delete_guard_oid IS NOT NULL AND immutable_oid IS NOT NULL
   AND routines.exact AND activation_acl.exact AND triggers.exact
FROM objects,routines,activation_acl,triggers`, memoryEmbeddingActivationRoutineMD5, memoryEmbeddingChunkDeleteGuardRoutineMD5, memoryEmbeddingGenerationMutationRoutineMD5).Scan(&available)
	return available, err
}

const (
	memoryEmbeddingActivationRoutineMD5         = "1714e7ec63388aa89c3756ffa175316b"
	memoryEmbeddingChunkDeleteGuardRoutineMD5   = "8e425c1cc346a818814c2903f8d52786"
	memoryEmbeddingGenerationMutationRoutineMD5 = "5ba945bbb850d7f58c7a7ce2cea1516d"
)
