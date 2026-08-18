package postgres

import "context"

// relayDirectMessagesAvailable confirms that direct-role conversation and
// sender-role envelope tables remain owned by the schema role.
func relayDirectMessagesAvailable(ctx context.Context, q queryer, schemaVersion int64) (bool, error) {
	if schemaVersion < 47 {
		return true, nil
	}
	var available bool
	err := q.QueryRowContext(ctx, `
WITH objects AS (
    SELECT to_regclass('relay.mail_direct_conversations') AS pairs_oid,
           to_regclass('relay.mail_message_from_roles') AS senders_oid,
           to_regclass('relay.mail_direct_message_idempotency') AS retries_oid,
           to_regclass('relay.mail_roles') AS roles_oid,
           to_regclass('relay.mail_conversations') AS conversations_oid,
           to_regclass('relay.mail_messages') AS messages_oid,
           to_regprocedure('relay.guard_mail_mutation()') AS guard_oid
), relations AS (
    SELECT count(*)=3 AND bool_and(pg_get_userbyid(class.relowner)='punaro_owner' AND class.relkind='r'
       AND class.relpersistence='p' AND NOT class.relrowsecurity AND NOT class.relforcerowsecurity) AS exact
    FROM objects JOIN pg_class AS class ON class.oid=ANY(ARRAY[pairs_oid,senders_oid,retries_oid])
), columns AS (
    SELECT count(*)=15
       AND bool_and((attribute.attrelid,attribute.attname,attribute.atttypid,attribute.attnotnull) IN (
           (pairs_oid,'role_low','text'::regtype,true),(pairs_oid,'role_high','text'::regtype,true),
           (pairs_oid,'conversation_id','uuid'::regtype,true),(pairs_oid,'created_at','timestamptz'::regtype,true),
           (senders_oid,'message_id','uuid'::regtype,true),(senders_oid,'from_role','text'::regtype,true),
           (retries_oid,'machine_id','text'::regtype,true),(retries_oid,'key','text'::regtype,true),
           (retries_oid,'request_hash','bpchar'::regtype,true),(retries_oid,'from_role','text'::regtype,true),
           (retries_oid,'to_role','text'::regtype,true),(retries_oid,'conversation_id','uuid'::regtype,true),
           (retries_oid,'message_id','uuid'::regtype,true),(retries_oid,'sequence','int8'::regtype,true),
           (retries_oid,'created_at','timestamptz'::regtype,true))) AS exact
    FROM objects JOIN pg_attribute AS attribute ON attribute.attrelid=ANY(ARRAY[pairs_oid,senders_oid,retries_oid])
       AND attribute.attnum>0 AND NOT attribute.attisdropped
), expected_constraints(table_oid,constraint_name,constraint_type,column_keys,foreign_table_oid,foreign_column_keys,delete_type,check_expression) AS (
    SELECT expected.* FROM objects, LATERAL (VALUES
        (pairs_oid,'mail_direct_conversations_pkey','p'::"char",ARRAY[1,2]::smallint[],NULL::oid,NULL::smallint[],NULL::"char",NULL::text),
        (pairs_oid,'mail_direct_conversations_conversation_id_key','u'::"char",ARRAY[3]::smallint[],NULL::oid,NULL::smallint[],NULL::"char",NULL::text),
        (pairs_oid,'mail_direct_conversations_role_order_check','c'::"char",ARRAY[1,2]::smallint[],NULL::oid,NULL::smallint[],NULL::"char",'(role_low < role_high)'),
        (pairs_oid,'mail_direct_conversations_role_low_fkey','f'::"char",ARRAY[1]::smallint[],roles_oid,ARRAY[1]::smallint[],'a'::"char",NULL::text),
        (pairs_oid,'mail_direct_conversations_role_high_fkey','f'::"char",ARRAY[2]::smallint[],roles_oid,ARRAY[1]::smallint[],'a'::"char",NULL::text),
        (pairs_oid,'mail_direct_conversations_conversation_id_fkey','f'::"char",ARRAY[3]::smallint[],conversations_oid,ARRAY[1]::smallint[],'a'::"char",NULL::text),
        (senders_oid,'mail_message_from_roles_pkey','p'::"char",ARRAY[1]::smallint[],NULL::oid,NULL::smallint[],NULL::"char",NULL::text),
        (senders_oid,'mail_message_from_roles_message_id_fkey','f'::"char",ARRAY[1]::smallint[],messages_oid,ARRAY[1]::smallint[],'a'::"char",NULL::text),
        (senders_oid,'mail_message_from_roles_from_role_fkey','f'::"char",ARRAY[2]::smallint[],roles_oid,ARRAY[1]::smallint[],'a'::"char",NULL::text),
        (retries_oid,'mail_direct_message_idempotency_pkey','p'::"char",ARRAY[1,2]::smallint[],NULL::oid,NULL::smallint[],NULL::"char",NULL::text),
        (retries_oid,'mail_direct_message_idempotency_key_check','c'::"char",ARRAY[2]::smallint[],NULL::oid,NULL::smallint[],NULL::"char",'((char_length(key) >= 1) AND (char_length(key) <= 128) AND (octet_length(key) <= 512) AND (key !~ ''[[:cntrl:]]''::text))'),
        (retries_oid,'mail_direct_message_idempotency_request_hash_check','c'::"char",ARRAY[3]::smallint[],NULL::oid,NULL::smallint[],NULL::"char",'(request_hash ~ ''^[0-9a-f]{64}$''::text)'),
        (retries_oid,'mail_direct_message_idempotency_sequence_check','c'::"char",ARRAY[8]::smallint[],NULL::oid,NULL::smallint[],NULL::"char",'(sequence >= 1)'),
        (retries_oid,'mail_direct_message_idempotency_conversation_id_fkey','f'::"char",ARRAY[6]::smallint[],conversations_oid,ARRAY[1]::smallint[],'a'::"char",NULL::text),
        (retries_oid,'mail_direct_message_idempotency_message_id_fkey','f'::"char",ARRAY[7]::smallint[],messages_oid,ARRAY[1]::smallint[],'a'::"char",NULL::text)
    ) AS expected(table_oid,constraint_name,constraint_type,column_keys,foreign_table_oid,foreign_column_keys,delete_type,check_expression)
), actual_constraints AS (
    SELECT constraint_.conrelid,constraint_.conname,constraint_.contype,constraint_.conkey,
           NULLIF(constraint_.confrelid,0),constraint_.confkey,
           CASE WHEN constraint_.contype='f' THEN constraint_.confdeltype END,
           CASE WHEN constraint_.contype='c' THEN pg_get_expr(constraint_.conbin,constraint_.conrelid) END
    FROM objects JOIN pg_constraint AS constraint_ ON constraint_.conrelid=ANY(ARRAY[pairs_oid,senders_oid,retries_oid])
    WHERE constraint_.contype IN ('p','u','f','c')
      AND constraint_.convalidated AND NOT constraint_.condeferrable AND NOT constraint_.condeferred
), constraints AS (
    SELECT NOT EXISTS (SELECT * FROM expected_constraints EXCEPT SELECT * FROM actual_constraints)
       AND NOT EXISTS (SELECT * FROM actual_constraints EXCEPT SELECT * FROM expected_constraints) AS exact
    FROM expected_constraints
), guards AS (
    SELECT count(*)=3 AND bool_and(trigger.tgfoid=guard_oid AND trigger.tgenabled='O' AND NOT trigger.tgisinternal
       AND trigger.tgtype=30 AND trigger.tgconstraint=0 AND NOT trigger.tgdeferrable AND NOT trigger.tginitdeferred
       AND trigger.tgnargs=0 AND trigger.tgqual IS NULL AND trigger.tgnewtable IS NULL AND trigger.tgoldtable IS NULL
       AND trigger.tgattr::text='') AS exact
    FROM objects JOIN pg_trigger AS trigger ON trigger.tgrelid=ANY(ARRAY[pairs_oid,senders_oid,retries_oid])
       AND trigger.tgname IN ('mail_direct_conversations_mutation_guard','mail_message_from_roles_mutation_guard','mail_direct_message_idempotency_mutation_guard')
), acl AS (
    SELECT has_table_privilege('punaro_app',pairs_oid,'SELECT,INSERT')
       AND has_table_privilege('punaro_app',senders_oid,'SELECT,INSERT')
       AND has_table_privilege('punaro_app',retries_oid,'SELECT,INSERT')
       AND NOT has_table_privilege('punaro_app',pairs_oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
       AND NOT has_table_privilege('punaro_app',senders_oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
       AND NOT has_table_privilege('punaro_app',retries_oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AS exact
    FROM objects
)
SELECT pairs_oid IS NOT NULL AND senders_oid IS NOT NULL AND retries_oid IS NOT NULL AND roles_oid IS NOT NULL
   AND conversations_oid IS NOT NULL AND messages_oid IS NOT NULL AND guard_oid IS NOT NULL
   AND relations.exact AND columns.exact AND constraints.exact AND guards.exact AND acl.exact
   AND EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid=retries_oid AND attname='request_hash' AND atttypid='bpchar'::regtype AND atttypmod=68)
FROM objects,relations,columns,constraints,guards,acl`).Scan(&available)
	return available, err
}
