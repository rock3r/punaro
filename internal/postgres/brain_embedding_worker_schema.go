package postgres

import "context"

// memoryEmbeddingWorkerControlsAvailable verifies that the only application
// mutation path for embedding jobs remains the bounded owner routines.
func memoryEmbeddingWorkerControlsAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `WITH objects AS (
    SELECT to_regprocedure('brain.claim_embedding_jobs(uuid,integer,bigint)') AS claim_oid,
           to_regprocedure('brain.retry_embedding_job(uuid,uuid,bigint,bytea,uuid,bigint,bigint,text)') AS retry_oid
), routine_safety AS (
    SELECT count(*)=2 AND bool_and(pg_get_userbyid(proc.proowner)='punaro_owner'
        AND proc.prokind='f' AND proc.prosecdef AND proc.provolatile='v'
        AND proc.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
        AND proc.proconfig=ARRAY['search_path=pg_catalog']::text[]
        AND ((proc.oid=claim_oid AND md5(btrim(proc.prosrc,E' \n\r\t'))=$1)
          OR (proc.oid=retry_oid AND md5(btrim(proc.prosrc,E' \n\r\t'))=$2))) AS exact
    FROM pg_proc AS proc,objects WHERE proc.oid=ANY(ARRAY[claim_oid,retry_oid])
), routine_acl AS (
    SELECT count(*)=2
       AND NOT EXISTS (SELECT * FROM (VALUES
           ('brain.claim_embedding_jobs(uuid,integer,bigint)','punaro_owner','EXECUTE',false),
           ('brain.claim_embedding_jobs(uuid,integer,bigint)','punaro_app','EXECUTE',false),
           ('brain.retry_embedding_job(uuid,uuid,bigint,bytea,uuid,bigint,bigint,text)','punaro_owner','EXECUTE',false),
           ('brain.retry_embedding_job(uuid,uuid,bigint,bytea,uuid,bigint,bigint,text)','punaro_app','EXECUTE',false)
       ) AS expected(signature,grantee,privilege_type,is_grantable)
       EXCEPT
       SELECT proc.oid::regprocedure::text,COALESCE(role.rolname,'PUBLIC'),entry.privilege_type,entry.is_grantable
       FROM pg_proc AS proc
       CROSS JOIN LATERAL aclexplode(COALESCE(proc.proacl,acldefault('f',proc.proowner))) AS entry
       LEFT JOIN pg_roles AS role ON role.oid=entry.grantee,objects
       WHERE proc.oid=ANY(ARRAY[claim_oid,retry_oid]))
       AND NOT EXISTS (
       SELECT proc.oid::regprocedure::text,COALESCE(role.rolname,'PUBLIC'),entry.privilege_type,entry.is_grantable
       FROM pg_proc AS proc
       CROSS JOIN LATERAL aclexplode(COALESCE(proc.proacl,acldefault('f',proc.proowner))) AS entry
       LEFT JOIN pg_roles AS role ON role.oid=entry.grantee,objects
       WHERE proc.oid=ANY(ARRAY[claim_oid,retry_oid])
       EXCEPT
       SELECT * FROM (VALUES
           ('brain.claim_embedding_jobs(uuid,integer,bigint)','punaro_owner','EXECUTE',false),
           ('brain.claim_embedding_jobs(uuid,integer,bigint)','punaro_app','EXECUTE',false),
           ('brain.retry_embedding_job(uuid,uuid,bigint,bytea,uuid,bigint,bigint,text)','punaro_owner','EXECUTE',false),
           ('brain.retry_embedding_job(uuid,uuid,bigint,bytea,uuid,bigint,bigint,text)','punaro_app','EXECUTE',false)
       ) AS expected(signature,grantee,privilege_type,is_grantable)) AS exact
    FROM pg_proc AS proc,objects WHERE proc.oid=ANY(ARRAY[claim_oid,retry_oid])
)
SELECT claim_oid IS NOT NULL AND retry_oid IS NOT NULL AND routine_safety.exact AND routine_acl.exact
FROM objects,routine_safety,routine_acl`, memoryEmbeddingClaimRoutineMD5, memoryEmbeddingRetryRoutineMD5).Scan(&available)
	return available, err
}

const (
	memoryEmbeddingClaimRoutineMD5 = "d211877029240bc95f35abb2b00df576"
	memoryEmbeddingRetryRoutineMD5 = "06f3d49f9ba794dd42ccdfe0ddfd9e0a"
)
