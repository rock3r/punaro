package postgres

import "context"

func relayDeliveryTerminalsAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `
WITH objects AS (
    SELECT to_regclass('relay.mail_delivery_terminals') AS terminals_oid,
           to_regprocedure('relay.guard_mail_mutation()') AS guard_oid
), relations AS (
    SELECT count(*)=1 AND bool_and(pg_get_userbyid(class.relowner)='punaro_owner' AND class.relkind='r'
       AND class.relpersistence='p' AND NOT class.relrowsecurity AND NOT class.relforcerowsecurity) AS exact
    FROM objects JOIN pg_class AS class ON class.oid=terminals_oid
), columns AS (
    SELECT count(*)=9
       AND bool_and((attribute.attrelid,attribute.attname,attribute.atttypid,attribute.attnotnull) IN (
           (terminals_oid,'delivery_id','uuid'::regtype,true),(terminals_oid,'message_id','uuid'::regtype,true),
           (terminals_oid,'conversation_id','uuid'::regtype,true),(terminals_oid,'recipient_endpoint','text'::regtype,true),
           (terminals_oid,'sequence','int8'::regtype,true),(terminals_oid,'closed_reason','text'::regtype,true),
           (terminals_oid,'lease_generation','int8'::regtype,true),(terminals_oid,'created_at','timestamptz'::regtype,true),
           (terminals_oid,'closed_at','timestamptz'::regtype,true))) AS exact
    FROM objects JOIN pg_attribute AS attribute ON attribute.attrelid=terminals_oid
       AND attribute.attnum>0 AND NOT attribute.attisdropped
), expected_constraints(table_oid,constraint_name,constraint_type,column_keys,check_expression) AS (
    SELECT expected.* FROM objects, LATERAL (VALUES
        (terminals_oid,'mail_delivery_terminals_pkey','p'::"char",ARRAY[1]::smallint[],NULL::text),
        (terminals_oid,'mail_delivery_terminals_recipient_endpoint_check','c'::"char",ARRAY[4]::smallint[],'((char_length(recipient_endpoint) >= 1) AND (char_length(recipient_endpoint) <= 512) AND (octet_length(recipient_endpoint) <= 2048))'),
        (terminals_oid,'mail_delivery_terminals_sequence_check','c'::"char",ARRAY[5]::smallint[],'(sequence >= 1)'),
        (terminals_oid,'mail_delivery_terminals_closed_reason_check','c'::"char",ARRAY[6]::smallint[],'((closed_reason = ANY (ARRAY[''acked''::text, ''expired''::text, ''revoked''::text])))'),
        (terminals_oid,'mail_delivery_terminals_lease_generation_check','c'::"char",ARRAY[7]::smallint[],'(lease_generation >= 0)')
    ) AS expected(table_oid,constraint_name,constraint_type,column_keys,check_expression)
), actual_constraints AS (
    SELECT constraint_.conrelid,constraint_.conname,constraint_.contype,constraint_.conkey,
           CASE WHEN constraint_.contype='c' THEN pg_get_expr(constraint_.conbin,constraint_.conrelid) END
    FROM objects JOIN pg_constraint AS constraint_ ON constraint_.conrelid=terminals_oid
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
    FROM objects JOIN pg_trigger AS trigger ON trigger.tgrelid=terminals_oid
       AND trigger.tgname='mail_delivery_terminals_mutation_guard'
), acl AS (
    SELECT has_table_privilege('punaro_app',terminals_oid,'SELECT,INSERT,UPDATE,DELETE')
       AND NOT has_table_privilege('punaro_app',terminals_oid,'TRUNCATE,REFERENCES,TRIGGER') AS exact
    FROM objects
)
SELECT terminals_oid IS NOT NULL AND guard_oid IS NOT NULL
   AND relations.exact AND columns.exact AND constraints.exact AND guards.exact AND acl.exact
FROM objects,relations,columns,constraints,guards,acl`).Scan(&available)
	return available, err
}
