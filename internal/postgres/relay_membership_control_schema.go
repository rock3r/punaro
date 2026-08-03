package postgres

import "context"

// relayMembershipControlsAvailable confirms that the content-free membership
// control audit trail and retry ledger remain owned by the schema role and
// cannot be rewritten by an application connection.
func relayMembershipControlsAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `
WITH objects AS (
    SELECT to_regclass('relay.mail_conversation_controls') AS controls_oid,
           to_regclass('relay.mail_conversation_control_idempotency') AS retries_oid,
           to_regclass('relay.mail_conversations') AS conversations_oid,
           to_regprocedure('relay.guard_mail_mutation()') AS guard_oid
), relations AS (
    SELECT count(*)=2 AND bool_and(pg_get_userbyid(class.relowner)='punaro_owner' AND class.relkind='r'
       AND class.relpersistence='p' AND NOT class.relrowsecurity AND NOT class.relforcerowsecurity) AS exact
    FROM objects JOIN pg_class AS class ON class.oid=ANY(ARRAY[controls_oid,retries_oid])
), columns AS (
    SELECT count(*)=12
       AND bool_and((attribute.attrelid,attribute.attname,attribute.atttypid,attribute.attnotnull) IN (
           (controls_oid,'id','uuid'::regtype,true),(controls_oid,'conversation_id','uuid'::regtype,true),
           (controls_oid,'actor_endpoint','text'::regtype,true),(controls_oid,'operation','text'::regtype,true),
           (controls_oid,'member_endpoint','text'::regtype,true),(controls_oid,'member_capabilities','int2'::regtype,true),
           (controls_oid,'created_at','timestamptz'::regtype,true),
           (retries_oid,'machine_id','text'::regtype,true),(retries_oid,'key','text'::regtype,true),
           (retries_oid,'request_hash','bpchar'::regtype,true),(retries_oid,'control_id','uuid'::regtype,true),
           (retries_oid,'created_at','timestamptz'::regtype,true))) AS exact
    FROM objects JOIN pg_attribute AS attribute ON attribute.attrelid=ANY(ARRAY[controls_oid,retries_oid])
       AND attribute.attnum>0 AND NOT attribute.attisdropped
), constraints AS (
    SELECT count(*) FILTER (WHERE constraint_.contype='p')=2
       AND count(*) FILTER (WHERE constraint_.contype='u')=1
       AND count(*) FILTER (WHERE constraint_.contype='f')=2
       AND count(*) FILTER (WHERE constraint_.contype='c')=4
       AND bool_and(constraint_.convalidated AND NOT constraint_.condeferrable AND NOT constraint_.condeferred) AS exact
    FROM objects JOIN pg_constraint AS constraint_ ON constraint_.conrelid=ANY(ARRAY[controls_oid,retries_oid])
), guards AS (
    SELECT count(*)=2 AND bool_and(trigger.tgfoid=guard_oid AND trigger.tgenabled='O' AND NOT trigger.tgisinternal
       AND trigger.tgtype=30 AND trigger.tgconstraint=0 AND NOT trigger.tgdeferrable AND NOT trigger.tginitdeferred
       AND trigger.tgnargs=0 AND trigger.tgqual IS NULL AND trigger.tgnewtable IS NULL AND trigger.tgoldtable IS NULL
       AND trigger.tgattr::text='') AS exact
    FROM objects JOIN pg_trigger AS trigger ON trigger.tgrelid=ANY(ARRAY[controls_oid,retries_oid])
       AND trigger.tgname IN ('mail_conversation_controls_mutation_guard','mail_conversation_control_idempotency_mutation_guard')
), acl AS (
    SELECT has_table_privilege('punaro_app',controls_oid,'SELECT,INSERT')
       AND has_table_privilege('punaro_app',retries_oid,'SELECT,INSERT')
       AND NOT has_table_privilege('punaro_app',controls_oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
       AND NOT has_table_privilege('punaro_app',retries_oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AS exact
    FROM objects
)
SELECT controls_oid IS NOT NULL AND retries_oid IS NOT NULL AND conversations_oid IS NOT NULL AND guard_oid IS NOT NULL
   AND relations.exact AND columns.exact AND constraints.exact AND guards.exact AND acl.exact
FROM objects,relations,columns,constraints,guards,acl`).Scan(&available)
	return available, err
}
