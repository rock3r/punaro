package postgres

import "context"

const pruneMailTerminalRoutineMD5 = "11c50ad2a94e9f3e29cc3911afc482fe"

// relayTerminalRetentionControlsAvailable confirms the SECURITY DEFINER prune
// routine is owned by the schema role, pinned to pg_catalog, and executable
// only by the application role. punaro_app still has no table DELETE on
// mail_deliveries.
func relayTerminalRetentionControlsAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `
WITH objects AS (
    SELECT to_regprocedure('relay.prune_mail_terminal(timestamp with time zone, integer)') AS prune_oid
), routine_safety AS (
    SELECT count(*)=1 AND bool_and(pg_get_userbyid(proc.proowner)='punaro_owner' AND proc.prosecdef
       AND proc.prokind='f' AND proc.provolatile='v' AND NOT proc.proretset
       AND proc.prorettype='bigint'::regtype AND proc.pronargs=2
       AND COALESCE(proc.proconfig=ARRAY['search_path=pg_catalog']::text[],false)
       AND md5(regexp_replace(proc.prosrc,'^\s+|\s+$','','g'))=$1) AS exact
    FROM objects JOIN pg_proc AS proc ON proc.oid=prune_oid
), routine_acl AS (
    SELECT has_function_privilege('punaro_app',prune_oid,'EXECUTE')
	   AND (SELECT count(*)=2 AND bool_and(NOT acl.is_grantable AND (grantee.rolname='punaro_owner' OR grantee.rolname='punaro_app'))
	        FROM pg_proc AS routine
	        CROSS JOIN LATERAL aclexplode(COALESCE(routine.proacl,acldefault('f',routine.proowner))) AS acl
	        LEFT JOIN pg_roles AS grantee ON grantee.oid=acl.grantee
	        WHERE routine.oid=prune_oid)
	   AND NOT EXISTS (
	       SELECT 1 FROM pg_proc AS routine
	       CROSS JOIN LATERAL aclexplode(COALESCE(routine.proacl,acldefault('f',routine.proowner))) AS acl
	       WHERE routine.oid=prune_oid AND acl.grantee=0 AND acl.privilege_type='EXECUTE'
	   ) AS exact
    FROM objects
)
SELECT prune_oid IS NOT NULL AND routine_safety.exact AND routine_acl.exact
FROM objects,routine_safety,routine_acl`, pruneMailTerminalRoutineMD5).Scan(&available)
	return available, err
}
