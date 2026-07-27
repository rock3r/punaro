package postgres

import "context"

// memoryEmbeddingQuarantineReleaseControlsAvailable verifies the schema-v32
// owner routine that atomically releases quarantine and requeues an expired
// lease whose final attempt was held behind that quarantine fence.
func memoryEmbeddingQuarantineReleaseControlsAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `WITH objects AS (
    SELECT to_regprocedure('brain.release_memory_quarantine(uuid,uuid)') AS release_oid
), routine_safety AS (
    SELECT count(*)=1 AND bool_and(pg_get_userbyid(proc.proowner)='punaro_owner'
        AND proc.prokind='f' AND proc.prosecdef AND proc.provolatile='v'
        AND proc.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
        AND proc.proconfig=ARRAY['search_path=pg_catalog']::text[]
        AND pg_get_function_result(proc.oid)='boolean'
        AND md5(btrim(proc.prosrc,E' \n\r\t'))=$1) AS exact
    FROM pg_proc AS proc,objects WHERE proc.oid=release_oid
), routine_acl AS (
    SELECT NOT EXISTS (SELECT * FROM (VALUES
        ('punaro_owner','EXECUTE',false),
        ('punaro_app','EXECUTE',false)
    ) AS expected(grantee,privilege_type,is_grantable)
    EXCEPT
    SELECT COALESCE(role.rolname,'PUBLIC'),entry.privilege_type,entry.is_grantable
    FROM pg_proc AS proc
    CROSS JOIN LATERAL aclexplode(COALESCE(proc.proacl,acldefault('f',proc.proowner))) AS entry
    LEFT JOIN pg_roles AS role ON role.oid=entry.grantee,objects
    WHERE proc.oid=release_oid)
    AND NOT EXISTS (
    SELECT COALESCE(role.rolname,'PUBLIC'),entry.privilege_type,entry.is_grantable
    FROM pg_proc AS proc
    CROSS JOIN LATERAL aclexplode(COALESCE(proc.proacl,acldefault('f',proc.proowner))) AS entry
    LEFT JOIN pg_roles AS role ON role.oid=entry.grantee,objects
    WHERE proc.oid=release_oid
    EXCEPT SELECT * FROM (VALUES
        ('punaro_owner','EXECUTE',false),
        ('punaro_app','EXECUTE',false)
    ) AS expected(grantee,privilege_type,is_grantable)) AS exact
)
SELECT release_oid IS NOT NULL AND routine_safety.exact AND routine_acl.exact
FROM objects,routine_safety,routine_acl`, memoryEmbeddingQuarantineReleaseRoutineV32MD5).Scan(&available)
	return available, err
}

const memoryEmbeddingQuarantineReleaseRoutineV32MD5 = "89deeaec7da8da82eaab25ff4f706000"
