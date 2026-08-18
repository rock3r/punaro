package postgres

import "context"

// relayRoleProfilesAvailable confirms that opt-in durable role identity remains
// owned by the schema role and cannot be rewritten by an application connection.
func relayRoleProfilesAvailable(ctx context.Context, q queryer, schemaVersion int64) (bool, error) {
	if schemaVersion < 45 {
		return true, nil
	}
	var available bool
	err := q.QueryRowContext(ctx, `
WITH objects AS (
    SELECT to_regclass('relay.mail_role_profiles') AS profiles_oid,
           to_regclass('relay.mail_role_profile_idempotency') AS retries_oid,
           to_regclass('relay.mail_roles') AS roles_oid,
           to_regprocedure('relay.guard_mail_mutation()') AS guard_oid
), relations AS (
    SELECT count(*)=2 AND bool_and(pg_get_userbyid(class.relowner)='punaro_owner' AND class.relkind='r'
       AND class.relpersistence='p' AND NOT class.relrowsecurity AND NOT class.relforcerowsecurity) AS exact
    FROM objects JOIN pg_class AS class ON class.oid=ANY(ARRAY[profiles_oid,retries_oid])
), columns AS (
    SELECT count(*)=12
       AND bool_and((attribute.attrelid,attribute.attname,attribute.atttypid,attribute.attnotnull) IN (
           (profiles_oid,'role','text'::regtype,true),(profiles_oid,'display_name','text'::regtype,false),
           (profiles_oid,'direct_addressable','bool'::regtype,true),(profiles_oid,'updated_at','timestamptz'::regtype,true),
           (retries_oid,'machine_id','text'::regtype,true),(retries_oid,'key','text'::regtype,true),
           (retries_oid,'request_hash','bpchar'::regtype,true),(retries_oid,'role','text'::regtype,true),
           (retries_oid,'display_name','text'::regtype,false),(retries_oid,'direct_addressable','bool'::regtype,true),
           (retries_oid,'updated_at','timestamptz'::regtype,true),(retries_oid,'created_at','timestamptz'::regtype,true))) AS exact
    FROM objects JOIN pg_attribute AS attribute ON attribute.attrelid=ANY(ARRAY[profiles_oid,retries_oid])
       AND attribute.attnum>0 AND NOT attribute.attisdropped
), expected_constraints(table_oid,constraint_name,constraint_type,column_keys,foreign_table_oid,foreign_column_keys,delete_type,check_expression) AS (
    SELECT expected.* FROM objects, LATERAL (VALUES
        (profiles_oid,'mail_role_profiles_pkey','p'::"char",ARRAY[1]::smallint[],NULL::oid,NULL::smallint[],NULL::"char",NULL::text),
        (profiles_oid,'mail_role_profiles_role_fkey','f'::"char",ARRAY[1]::smallint[],roles_oid,ARRAY[1]::smallint[],'a'::"char",NULL::text),
        (profiles_oid,'mail_role_profiles_display_name_check','c'::"char",ARRAY[2]::smallint[],NULL::oid,NULL::smallint[],NULL::"char",'((display_name IS NULL) OR ((char_length(display_name) >= 1) AND (char_length(display_name) <= 128) AND (octet_length(display_name) <= 128) AND (display_name !~ ''[[:cntrl:]]''::text) AND (display_name = btrim(display_name))))'),
        (retries_oid,'mail_role_profile_idempotency_pkey','p'::"char",ARRAY[1,2]::smallint[],NULL::oid,NULL::smallint[],NULL::"char",NULL::text),
        (retries_oid,'mail_role_profile_idempotency_key_check','c'::"char",ARRAY[2]::smallint[],NULL::oid,NULL::smallint[],NULL::"char",'((char_length(key) >= 1) AND (char_length(key) <= 128) AND (octet_length(key) <= 512) AND (key !~ ''[[:cntrl:]]''::text))'),
        (retries_oid,'mail_role_profile_idempotency_request_hash_check','c'::"char",ARRAY[3]::smallint[],NULL::oid,NULL::smallint[],NULL::"char",'(request_hash ~ ''^[0-9a-f]{64}$''::text)'),
        (retries_oid,'mail_role_profile_idempotency_display_name_check','c'::"char",ARRAY[5]::smallint[],NULL::oid,NULL::smallint[],NULL::"char",'((display_name IS NULL) OR ((char_length(display_name) >= 1) AND (char_length(display_name) <= 128) AND (octet_length(display_name) <= 128) AND (display_name !~ ''[[:cntrl:]]''::text) AND (display_name = btrim(display_name))))'),
        (retries_oid,'mail_role_profile_idempotency_role_fkey','f'::"char",ARRAY[4]::smallint[],profiles_oid,ARRAY[1]::smallint[],'a'::"char",NULL::text)
    ) AS expected(table_oid,constraint_name,constraint_type,column_keys,foreign_table_oid,foreign_column_keys,delete_type,check_expression)
), actual_constraints AS (
    SELECT constraint_.conrelid,constraint_.conname,constraint_.contype,constraint_.conkey,
           NULLIF(constraint_.confrelid,0),constraint_.confkey,
           CASE WHEN constraint_.contype='f' THEN constraint_.confdeltype END,
           CASE WHEN constraint_.contype='c' THEN pg_get_expr(constraint_.conbin,constraint_.conrelid) END
    FROM objects JOIN pg_constraint AS constraint_ ON constraint_.conrelid=ANY(ARRAY[profiles_oid,retries_oid])
    WHERE constraint_.contype IN ('p','u','f','c')
      AND constraint_.convalidated AND NOT constraint_.condeferrable AND NOT constraint_.condeferred
), constraints AS (
    SELECT NOT EXISTS (SELECT * FROM expected_constraints EXCEPT SELECT * FROM actual_constraints)
       AND NOT EXISTS (SELECT * FROM actual_constraints EXCEPT SELECT * FROM expected_constraints) AS exact
    FROM expected_constraints
), defaults AS (
    SELECT count(*)=1 AND bool_and(pg_get_expr(default_value.adbin,default_value.adrelid)='false') AS exact
    FROM objects JOIN pg_attrdef AS default_value ON default_value.adrelid=profiles_oid
    JOIN pg_attribute AS attribute ON attribute.attrelid=default_value.adrelid AND attribute.attnum=default_value.adnum AND attribute.attname='direct_addressable'
), guards AS (
    SELECT count(*)=2 AND bool_and(trigger.tgfoid=guard_oid AND trigger.tgenabled='O' AND NOT trigger.tgisinternal
       AND trigger.tgtype=30 AND trigger.tgconstraint=0 AND NOT trigger.tgdeferrable AND NOT trigger.tginitdeferred
       AND trigger.tgnargs=0 AND trigger.tgqual IS NULL AND trigger.tgnewtable IS NULL AND trigger.tgoldtable IS NULL
       AND trigger.tgattr::text='') AS exact
    FROM objects JOIN pg_trigger AS trigger ON trigger.tgrelid=ANY(ARRAY[profiles_oid,retries_oid])
       AND trigger.tgname IN ('mail_role_profiles_mutation_guard','mail_role_profile_idempotency_mutation_guard')
), acl AS (
    SELECT has_table_privilege('punaro_app',profiles_oid,'SELECT,INSERT')
       AND has_table_privilege('punaro_app',retries_oid,'SELECT,INSERT')
       AND NOT has_table_privilege('punaro_app',profiles_oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
       AND NOT has_table_privilege('punaro_app',retries_oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
       AND has_column_privilege('punaro_app',profiles_oid,'display_name','UPDATE')
       AND has_column_privilege('punaro_app',profiles_oid,'direct_addressable','UPDATE')
       AND has_column_privilege('punaro_app',profiles_oid,'updated_at','UPDATE')
       AND NOT has_column_privilege('punaro_app',profiles_oid,'role','UPDATE') AS exact
    FROM objects
)
SELECT profiles_oid IS NOT NULL AND retries_oid IS NOT NULL AND roles_oid IS NOT NULL AND guard_oid IS NOT NULL
   AND relations.exact AND columns.exact AND constraints.exact AND defaults.exact AND guards.exact AND acl.exact
   AND EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid=retries_oid AND attname='request_hash' AND atttypid='bpchar'::regtype AND atttypmod=68)
FROM objects,relations,columns,constraints,defaults,guards,acl`).Scan(&available)
	return available, err
}
