package postgres

import "context"

// memoryEmbeddingQuarantineReleaseControlsAvailable verifies the schema-v32
// quarantine-release trigger that requeues an expired lease whose final
// attempt was held behind that quarantine fence.
func memoryEmbeddingQuarantineReleaseControlsAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `WITH objects AS (
    SELECT to_regprocedure('brain.requeue_expired_quarantined_embedding_jobs()') AS requeue_oid,
           'brain.memory_quarantines'::regclass AS quarantines_oid
), routine_safety AS (
    SELECT count(*)=1 AND bool_and(pg_get_userbyid(proc.proowner)='punaro_owner'
        AND proc.prokind='f' AND proc.prosecdef AND proc.provolatile='v'
        AND proc.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
        AND proc.proconfig=ARRAY['search_path=pg_catalog']::text[]
        AND pg_get_function_result(proc.oid)='trigger'
        AND md5(btrim(proc.prosrc,E' \n\r\t'))=$1) AS exact
    FROM pg_proc AS proc,objects WHERE proc.oid=requeue_oid
), routine_acl AS (
    SELECT NOT EXISTS (SELECT * FROM (VALUES ('punaro_owner','EXECUTE',false)) AS expected(grantee,privilege_type,is_grantable)
    EXCEPT
    SELECT COALESCE(role.rolname,'PUBLIC'),entry.privilege_type,entry.is_grantable
    FROM pg_proc AS proc
    CROSS JOIN LATERAL aclexplode(COALESCE(proc.proacl,acldefault('f',proc.proowner))) AS entry
    LEFT JOIN pg_roles AS role ON role.oid=entry.grantee,objects
    WHERE proc.oid=requeue_oid)
    AND NOT EXISTS (
    SELECT COALESCE(role.rolname,'PUBLIC'),entry.privilege_type,entry.is_grantable
    FROM pg_proc AS proc
    CROSS JOIN LATERAL aclexplode(COALESCE(proc.proacl,acldefault('f',proc.proowner))) AS entry
    LEFT JOIN pg_roles AS role ON role.oid=entry.grantee,objects
    WHERE proc.oid=requeue_oid
    EXCEPT SELECT * FROM (VALUES ('punaro_owner','EXECUTE',false)) AS expected(grantee,privilege_type,is_grantable)) AS exact
), trigger_safety AS (
    SELECT EXISTS (SELECT 1 FROM pg_trigger,objects WHERE tgrelid=quarantines_oid AND NOT tgisinternal
        AND tgname='memory_quarantine_embedding_release' AND tgenabled='O' AND tgfoid=requeue_oid AND tgtype=17)
)
SELECT requeue_oid IS NOT NULL AND quarantines_oid IS NOT NULL AND routine_safety.exact AND routine_acl.exact AND trigger_safety.exact
FROM objects,routine_safety,routine_acl,trigger_safety`, memoryEmbeddingQuarantineReleaseRoutineV32MD5).Scan(&available)
	return available, err
}

const memoryEmbeddingQuarantineReleaseRoutineV32MD5 = "08026175c35c150fff31a00d16127082"
