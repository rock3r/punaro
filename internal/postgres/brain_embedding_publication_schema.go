package postgres

import "context"

func memoryEmbeddingPublicationControlsAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `WITH objects AS (
    SELECT to_regclass('brain.embedding_chunks') AS chunks_oid,
           to_regprocedure('brain.publish_embedding_job(uuid,uuid,bigint,bytea,uuid,bigint,jsonb)') AS publish_oid,
           to_regprocedure('jobs.guard_application_mutation()') AS fence_oid
), routine AS (
    SELECT count(*)=1 AND bool_and(pg_get_userbyid(proowner)='punaro_owner' AND prosecdef AND provolatile='v'
        AND prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql') AND proconfig=ARRAY['search_path=pg_catalog']::text[]
        AND md5(btrim(prosrc,E' \n\r\t'))='2a5bb540102e4944f41c63c31a5aed49') AS exact
    FROM pg_proc AS proc,objects WHERE proc.oid=publish_oid
), acl AS (
    SELECT count(*)=2 AND bool_and(entry.privilege_type='EXECUTE' AND NOT entry.is_grantable AND role.rolname IN ('punaro_owner','punaro_app')) AS exact
    FROM pg_proc AS proc CROSS JOIN LATERAL aclexplode(COALESCE(proc.proacl,acldefault('f',proc.proowner))) AS entry
    JOIN pg_roles AS role ON role.oid=entry.grantee,objects WHERE proc.oid=publish_oid
)
SELECT chunks_oid IS NOT NULL AND publish_oid IS NOT NULL AND routine.exact AND acl.exact
   AND pg_get_userbyid((SELECT relowner FROM pg_class WHERE oid=chunks_oid))='punaro_owner'
   AND NOT has_table_privilege('punaro_app',chunks_oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
   AND has_table_privilege('punaro_app',chunks_oid,'SELECT')
   AND EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid=chunks_oid AND tgname='application_mutation_fence' AND tgfoid=fence_oid AND tgenabled='O' AND NOT tgisinternal AND tgtype=62)
FROM objects,routine,acl`).Scan(&available)
	return available, err
}
