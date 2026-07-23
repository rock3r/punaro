package postgres

import "context"

// memoryReconciliationControlsAvailable verifies the exact schema-v22 repair authority.
func memoryReconciliationControlsAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `WITH objects AS (
    SELECT to_regprocedure('brain.reconcile_memory_references(uuid,uuid,integer)') AS reconcile_oid
), routine_safety AS (
    SELECT count(*)=1 AND bool_and(
        pg_get_userbyid(routine.proowner)='punaro_owner'
        AND routine.prokind='f'
        AND routine.prosecdef
        AND routine.provolatile='v'
        AND routine.proretset
        AND routine.prorettype='record'::regtype
        AND routine.pronargs=3
        AND routine.proargtypes='2950 2950 23'::oidvector
        AND routine.proallargtypes=ARRAY[
            'uuid'::regtype,'uuid'::regtype,'integer'::regtype,
            'integer'::regtype,'integer'::regtype,'boolean'::regtype,'bigint'::regtype
        ]::oid[]
        AND routine.proargmodes=ARRAY['i','i','i','t','t','t','t']::"char"[]
        AND routine.proargnames=ARRAY[
            'requested_principal','requested_project','requested_limit',
            'alias_repairs','orphan_edges_removed','more','change_sequence'
        ]::text[]
        AND routine.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
        AND routine.proconfig=ARRAY['search_path=pg_catalog']::text[]
        AND NOT routine.proisstrict
        AND NOT routine.proleakproof
        AND routine.proparallel='u'
        AND routine.provariadic=0
        AND md5(btrim(routine.prosrc,E' \n\r\t'))=$1
    ) AS exact
    FROM pg_proc AS routine,objects
    WHERE routine.oid=reconcile_oid
), expected_acl(grantee,privilege_type,is_grantable) AS (
    VALUES ('punaro_owner','EXECUTE',false),('punaro_app','EXECUTE',false)
), actual_acl AS (
    SELECT COALESCE(grantee.rolname,'PUBLIC'),entry.privilege_type,entry.is_grantable
    FROM pg_proc AS routine
    CROSS JOIN LATERAL aclexplode(COALESCE(routine.proacl,acldefault('f',routine.proowner))) AS entry
    LEFT JOIN pg_roles AS grantee ON grantee.oid=entry.grantee,objects
    WHERE routine.oid=reconcile_oid
)
SELECT reconcile_oid IS NOT NULL
   AND routine_safety.exact
   AND NOT EXISTS (SELECT * FROM expected_acl EXCEPT SELECT * FROM actual_acl)
   AND NOT EXISTS (SELECT * FROM actual_acl EXCEPT SELECT * FROM expected_acl)
FROM objects,routine_safety`, memoryReconciliationRoutineMD5).Scan(&available)
	return available, err
}

const memoryReconciliationRoutineMD5 = "81dd1c41fe4407ad8f663d072796197d"
