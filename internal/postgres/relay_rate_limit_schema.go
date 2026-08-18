package postgres

import "context"

// relayRateLimitControlsAvailable confirms that durable sender and conversation
// token buckets remain owned by the schema role with column-bounded updates.
func relayRateLimitControlsAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `
WITH objects AS (
    SELECT to_regclass('relay.mail_rate_buckets') AS buckets_oid,
           to_regprocedure('relay.guard_mail_mutation()') AS guard_oid
), relations AS (
    SELECT count(*)=1 AND bool_and(pg_get_userbyid(class.relowner)='punaro_owner' AND class.relkind='r'
       AND class.relpersistence='p' AND NOT class.relrowsecurity AND NOT class.relforcerowsecurity) AS exact
    FROM objects JOIN pg_class AS class ON class.oid=buckets_oid
), columns AS (
    SELECT count(*)=4
       AND bool_and((attribute.attrelid,attribute.attname,attribute.atttypid,attribute.attnotnull) IN (
           (buckets_oid,'scope','text'::regtype,true),(buckets_oid,'bucket_key','text'::regtype,true),
           (buckets_oid,'tokens_milli','int8'::regtype,true),(buckets_oid,'last_refill_at','timestamptz'::regtype,true))) AS exact
    FROM objects JOIN pg_attribute AS attribute ON attribute.attrelid=buckets_oid
       AND attribute.attnum>0 AND NOT attribute.attisdropped
), expected_constraints(table_oid,constraint_name,constraint_type,column_keys,check_expression) AS (
    SELECT expected.* FROM objects, LATERAL (VALUES
        (buckets_oid,'mail_rate_buckets_pkey','p'::"char",ARRAY[1,2]::smallint[],NULL::text),
        (buckets_oid,'mail_rate_buckets_scope_check','c'::"char",ARRAY[1]::smallint[],'(scope = ANY (ARRAY[''sender_machine''::text, ''conversation''::text]))'),
        (buckets_oid,'mail_rate_buckets_bucket_key_check','c'::"char",ARRAY[2]::smallint[],'((char_length(bucket_key) >= 1) AND (char_length(bucket_key) <= 512) AND (octet_length(bucket_key) <= 2048) AND (bucket_key !~ ''[[:cntrl:]]''::text))'),
        (buckets_oid,'mail_rate_buckets_tokens_milli_check','c'::"char",ARRAY[3]::smallint[],'(tokens_milli >= 0)')
    ) AS expected(table_oid,constraint_name,constraint_type,column_keys,check_expression)
), actual_constraints AS (
    SELECT constraint_.conrelid,constraint_.conname,constraint_.contype,constraint_.conkey,
           CASE WHEN constraint_.contype='c' THEN pg_get_expr(constraint_.conbin,constraint_.conrelid) END
    FROM objects JOIN pg_constraint AS constraint_ ON constraint_.conrelid=buckets_oid
    WHERE constraint_.contype IN ('p','c')
      AND constraint_.convalidated AND NOT constraint_.condeferrable AND NOT constraint_.condeferred
), constraints AS (
    SELECT NOT EXISTS (SELECT * FROM expected_constraints EXCEPT SELECT * FROM actual_constraints)
       AND NOT EXISTS (SELECT * FROM actual_constraints EXCEPT SELECT * FROM expected_constraints) AS exact
    FROM expected_constraints
), guards AS (
    SELECT count(*)=1 AND bool_and(trigger.tgfoid=guard_oid AND trigger.tgenabled='O' AND NOT trigger.tgisinternal
       AND trigger.tgtype=30 AND trigger.tgconstraint=0 AND NOT trigger.tgdeferrable AND NOT trigger.tginitdeferred
       AND trigger.tgnargs=0 AND trigger.tgqual IS NULL AND trigger.tgnewtable IS NULL AND trigger.tgoldtable IS NULL
       AND trigger.tgattr::text='') AS exact
    FROM objects JOIN pg_trigger AS trigger ON trigger.tgrelid=buckets_oid
       AND trigger.tgname='mail_rate_buckets_mutation_guard'
), acl AS (
    SELECT has_table_privilege('punaro_app',buckets_oid,'SELECT,INSERT')
       AND NOT has_table_privilege('punaro_app',buckets_oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
       AND has_column_privilege('punaro_app',buckets_oid,'tokens_milli','UPDATE')
       AND has_column_privilege('punaro_app',buckets_oid,'last_refill_at','UPDATE')
       AND NOT has_column_privilege('punaro_app',buckets_oid,'scope','UPDATE')
       AND NOT has_column_privilege('punaro_app',buckets_oid,'bucket_key','UPDATE') AS exact
    FROM objects
)
SELECT buckets_oid IS NOT NULL AND guard_oid IS NOT NULL
   AND relations.exact AND columns.exact AND constraints.exact AND guards.exact AND acl.exact
FROM objects,relations,columns,constraints,guards,acl`).Scan(&available)
	return available, err
}
