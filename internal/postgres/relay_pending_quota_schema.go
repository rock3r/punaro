package postgres

import "context"

// relayPendingQuotaControlsAvailable confirms explicit pending-capacity counters
// are owned by the schema role and writable through bounded application grants.
func relayPendingQuotaControlsAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `
WITH objects AS (
    SELECT to_regclass('relay.mail_pending_recipients') AS recipients_oid,
           to_regclass('relay.mail_pending_install') AS install_oid,
           to_regprocedure('relay.guard_mail_mutation()') AS guard_oid
), relations AS (
    SELECT count(*)=2 AND bool_and(pg_get_userbyid(class.relowner)='punaro_owner' AND class.relkind='r'
       AND class.relpersistence='p' AND NOT class.relrowsecurity AND NOT class.relforcerowsecurity) AS exact
    FROM objects JOIN pg_class AS class ON class.oid=ANY(ARRAY[recipients_oid,install_oid])
), columns AS (
    SELECT count(*)=6
       AND bool_and((attribute.attrelid,attribute.attname,attribute.atttypid,attribute.attnotnull) IN (
           (recipients_oid,'recipient_endpoint','text'::regtype,true),(recipients_oid,'pending_count','int8'::regtype,true),
           (recipients_oid,'pending_bytes','int8'::regtype,true),(install_oid,'singleton','int4'::regtype,true),
           (install_oid,'pending_count','int8'::regtype,true),(install_oid,'pending_bytes','int8'::regtype,true))) AS exact
    FROM objects JOIN pg_attribute AS attribute ON attribute.attrelid=ANY(ARRAY[recipients_oid,install_oid])
       AND attribute.attnum>0 AND NOT attribute.attisdropped
), expected_constraints(table_oid,constraint_name,constraint_type,column_keys,check_expression) AS (
    SELECT expected.* FROM objects, LATERAL (VALUES
        (recipients_oid,'mail_pending_recipients_pkey','p'::"char",ARRAY[1]::smallint[],NULL::text),
        (recipients_oid,'mail_pending_recipients_recipient_endpoint_check','c'::"char",ARRAY[1]::smallint[],'((char_length(recipient_endpoint) >= 1) AND (char_length(recipient_endpoint) <= 512) AND (octet_length(recipient_endpoint) <= 2048))'),
        (recipients_oid,'mail_pending_recipients_pending_count_check','c'::"char",ARRAY[2]::smallint[],'(pending_count >= 0)'),
        (recipients_oid,'mail_pending_recipients_pending_bytes_check','c'::"char",ARRAY[3]::smallint[],'(pending_bytes >= 0)'),
        (install_oid,'mail_pending_install_pkey','p'::"char",ARRAY[1]::smallint[],NULL::text),
        (install_oid,'mail_pending_install_singleton_check','c'::"char",ARRAY[1]::smallint[],'(singleton = 1)'),
        (install_oid,'mail_pending_install_pending_count_check','c'::"char",ARRAY[2]::smallint[],'(pending_count >= 0)'),
        (install_oid,'mail_pending_install_pending_bytes_check','c'::"char",ARRAY[3]::smallint[],'(pending_bytes >= 0)')
    ) AS expected(table_oid,constraint_name,constraint_type,column_keys,check_expression)
), actual_constraints AS (
    SELECT constraint_.conrelid,constraint_.conname,constraint_.contype,constraint_.conkey,
           CASE WHEN constraint_.contype='c' THEN pg_get_expr(constraint_.conbin,constraint_.conrelid) END
    FROM objects JOIN pg_constraint AS constraint_ ON constraint_.conrelid=ANY(ARRAY[recipients_oid,install_oid])
    WHERE constraint_.contype IN ('p','c')
      AND constraint_.convalidated AND NOT constraint_.condeferrable AND NOT constraint_.condeferred
), constraints AS (
    SELECT NOT EXISTS (SELECT * FROM expected_constraints EXCEPT SELECT * FROM actual_constraints)
       AND NOT EXISTS (SELECT * FROM actual_constraints EXCEPT SELECT * FROM expected_constraints) AS exact
), guards AS (
    SELECT count(*)=2 AND bool_and(trigger.tgfoid=guard_oid AND trigger.tgenabled='O' AND NOT trigger.tgisinternal
       AND trigger.tgtype=30 AND trigger.tgconstraint=0 AND NOT trigger.tgdeferrable AND NOT trigger.tginitdeferred
       AND trigger.tgnargs=0 AND trigger.tgqual IS NULL AND trigger.tgnewtable IS NULL AND trigger.tgoldtable IS NULL
       AND trigger.tgattr::text='') AS exact
    FROM objects JOIN pg_trigger AS trigger ON trigger.tgrelid=ANY(ARRAY[recipients_oid,install_oid])
       AND trigger.tgname IN ('mail_pending_recipients_mutation_guard','mail_pending_install_mutation_guard')
), acl AS (
    SELECT has_table_privilege('punaro_app',recipients_oid,'SELECT,INSERT,UPDATE,DELETE')
       AND NOT has_table_privilege('punaro_app',recipients_oid,'TRUNCATE,REFERENCES,TRIGGER')
       AND has_table_privilege('punaro_app',install_oid,'SELECT,INSERT,UPDATE,DELETE')
       AND NOT has_table_privilege('punaro_app',install_oid,'TRUNCATE,REFERENCES,TRIGGER') AS exact
    FROM objects
)
SELECT recipients_oid IS NOT NULL AND install_oid IS NOT NULL AND guard_oid IS NOT NULL
   AND relations.exact AND columns.exact AND constraints.exact AND guards.exact AND acl.exact
FROM objects,relations,columns,constraints,guards,acl`).Scan(&available)
	return available, err
}
