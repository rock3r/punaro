package postgres

import "context"

// relayPendingCapacityControlsAvailable confirms the durable pending-capacity
// table is owned by the schema role and writable only through bounded grants.
func relayPendingCapacityControlsAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `
WITH objects AS (
    SELECT to_regclass('relay.mail_pending_capacity') AS capacity_oid,
           to_regprocedure('relay.guard_mail_mutation()') AS guard_oid
), relations AS (
    SELECT count(*)=1 AND bool_and(pg_get_userbyid(class.relowner)='punaro_owner' AND class.relkind='r'
       AND class.relpersistence='p' AND NOT class.relrowsecurity AND NOT class.relforcerowsecurity) AS exact
    FROM objects JOIN pg_class AS class ON class.oid=capacity_oid
), columns AS (
    SELECT count(*)=4
       AND bool_and((attribute.attrelid,attribute.attname,attribute.atttypid,attribute.attnotnull) IN (
           (capacity_oid,'scope','text'::regtype,true),(capacity_oid,'scope_key','text'::regtype,true),
           (capacity_oid,'pending_count','int8'::regtype,true),(capacity_oid,'pending_bytes','int8'::regtype,true))) AS exact
    FROM objects JOIN pg_attribute AS attribute ON attribute.attrelid=capacity_oid
       AND attribute.attnum>0 AND NOT attribute.attisdropped
), expected_constraints(table_oid,constraint_name,constraint_type,column_keys,check_expression) AS (
    SELECT expected.* FROM objects, LATERAL (VALUES
        (capacity_oid,'mail_pending_capacity_pkey','p'::"char",ARRAY[1,2]::smallint[],NULL::text),
        (capacity_oid,'mail_pending_capacity_scope_check','c'::"char",ARRAY[1]::smallint[],'(scope = ANY (ARRAY[''installation''::text, ''recipient''::text]))'),
        (capacity_oid,'mail_pending_capacity_pending_count_check','c'::"char",ARRAY[3]::smallint[],'(pending_count >= 0)'),
        (capacity_oid,'mail_pending_capacity_pending_bytes_check','c'::"char",ARRAY[4]::smallint[],'(pending_bytes >= 0)'),
        (capacity_oid,'mail_pending_capacity_shape_check','c'::"char",ARRAY[1,2]::smallint[],'(((scope = ''installation''::text) AND (scope_key = ''''::text)) OR ((scope = ''recipient''::text) AND (char_length(scope_key) >= 1) AND (((char_length(scope_key) <= 512) AND (octet_length(scope_key) <= 2048) AND (scope_key !~ ''[[:cntrl:]]''::text)) OR ((substr(scope_key, 1, 6) = (chr(30) || ''role:''::text)) AND (char_length(substr(scope_key, 7)) >= 1) AND (char_length(substr(scope_key, 7)) <= 512) AND (octet_length(substr(scope_key, 7)) <= 2048) AND (substr(scope_key, 7) !~ ''[[:cntrl:]]''::text)))))')
    ) AS expected(table_oid,constraint_name,constraint_type,column_keys,check_expression)
), actual_constraints AS (
    SELECT constraint_.conrelid,constraint_.conname,constraint_.contype,constraint_.conkey,
           CASE WHEN constraint_.contype='c' THEN pg_get_expr(constraint_.conbin,constraint_.conrelid) END
    FROM objects JOIN pg_constraint AS constraint_ ON constraint_.conrelid=capacity_oid
    WHERE constraint_.contype IN ('p','c')
      AND constraint_.convalidated AND NOT constraint_.condeferrable AND NOT constraint_.condeferred
), constraints AS (
    SELECT NOT EXISTS (SELECT * FROM expected_constraints EXCEPT SELECT * FROM actual_constraints)
       AND NOT EXISTS (SELECT * FROM actual_constraints EXCEPT SELECT * FROM expected_constraints) AS exact
), guards AS (
    SELECT count(*)=1 AND bool_and(trigger.tgfoid=guard_oid AND trigger.tgenabled='O' AND NOT trigger.tgisinternal
       AND trigger.tgtype=30 AND trigger.tgconstraint=0 AND NOT trigger.tgdeferrable AND NOT trigger.tginitdeferred
       AND trigger.tgnargs=0 AND trigger.tgqual IS NULL AND trigger.tgnewtable IS NULL AND trigger.tgoldtable IS NULL
       AND trigger.tgattr::text='') AS exact
    FROM objects JOIN pg_trigger AS trigger ON trigger.tgrelid=capacity_oid
       AND trigger.tgname='mail_pending_capacity_mutation_guard'
), acl AS (
    SELECT has_table_privilege('punaro_app',capacity_oid,'SELECT,INSERT')
       AND NOT has_table_privilege('punaro_app',capacity_oid,'DELETE,TRUNCATE,REFERENCES,TRIGGER')
       AND has_column_privilege('punaro_app',capacity_oid,'pending_count','UPDATE')
       AND has_column_privilege('punaro_app',capacity_oid,'pending_bytes','UPDATE')
       AND NOT has_column_privilege('punaro_app',capacity_oid,'scope','UPDATE')
       AND NOT has_column_privilege('punaro_app',capacity_oid,'scope_key','UPDATE') AS exact
    FROM objects
)
SELECT capacity_oid IS NOT NULL AND guard_oid IS NOT NULL
   AND relations.exact AND columns.exact AND constraints.exact AND guards.exact AND acl.exact
FROM objects,relations,columns,constraints,guards,acl`).Scan(&available)
	return available, err
}
