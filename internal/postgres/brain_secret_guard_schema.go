package postgres

import (
	"context"

	"github.com/rock3r/punaro/internal/secretguard"
)

// secretGuardControlsAvailable verifies the exact schema-v15 guard identity,
// metadata shape, mutation fences, ownership, and ACLs.
func secretGuardControlsAvailable(ctx context.Context, q queryer) (bool, error) {
	digest := secretguard.Digest()
	var available bool
	err := q.QueryRowContext(ctx, `WITH objects AS (
    SELECT to_regclass('brain.secret_guard_state') AS state_oid,
           to_regclass('brain.secret_exceptions') AS exceptions_oid,
           to_regclass('brain.secret_exceptions_active_exact') AS exact_index_oid,
           to_regprocedure('jobs.guard_application_mutation()') AS fence_oid
), expected_columns(relation_name,column_name,type_name,not_null,default_expression) AS (
    VALUES
      ('brain.secret_guard_state','singleton','boolean',true,'true'),
      ('brain.secret_guard_state','rule_version','bigint',true,''),
      ('brain.secret_guard_state','rule_digest','bytea',true,''),
      ('brain.secret_guard_state','updated_at','timestamp with time zone',true,'statement_timestamp()'),
      ('brain.secret_exceptions','id','uuid',true,'gen_random_uuid()'),
      ('brain.secret_exceptions','project_id','uuid',true,''),
      ('brain.secret_exceptions','rule_version','bigint',true,''),
      ('brain.secret_exceptions','rule_id','text',true,''),
      ('brain.secret_exceptions','field_path','text',true,''),
      ('brain.secret_exceptions','value_fingerprint','bytea',true,''),
      ('brain.secret_exceptions','approved_by','uuid',true,''),
      ('brain.secret_exceptions','created_at','timestamp with time zone',true,'statement_timestamp()'),
      ('brain.secret_exceptions','revoked_at','timestamp with time zone',false,'')
), actual_columns AS (
    SELECT attribute.attrelid::regclass::text,attribute.attname,format_type(attribute.atttypid,attribute.atttypmod),attribute.attnotnull,
           COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),'')
    FROM pg_attribute AS attribute
    LEFT JOIN pg_attrdef AS default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum, objects
    WHERE attribute.attrelid=ANY(ARRAY[state_oid,exceptions_oid]) AND attribute.attnum>0 AND NOT attribute.attisdropped
), table_safety AS (
    SELECT count(*)=2 AND bool_and(relation.relkind='r' AND relation.relpersistence='p' AND NOT relation.relrowsecurity AND NOT relation.relforcerowsecurity AND pg_get_userbyid(relation.relowner)='punaro_owner') AS exact
    FROM pg_class AS relation, objects WHERE relation.oid=ANY(ARRAY[state_oid,exceptions_oid])
), constraint_safety AS (
    SELECT count(*)=12 AND bool_and(constraint_row.convalidated AND NOT constraint_row.condeferrable AND NOT constraint_row.condeferred) AS exact
    FROM pg_constraint AS constraint_row, objects
    WHERE constraint_row.conrelid=ANY(ARRAY[state_oid,exceptions_oid]) AND constraint_row.contype<>'n'
), index_safety AS (
    SELECT count(*)=3 AND bool_and(index_row.indisvalid AND index_row.indisready) AS exact
    FROM pg_index AS index_row, objects WHERE index_row.indrelid=ANY(ARRAY[state_oid,exceptions_oid])
), fence_safety AS (
    SELECT count(*)=2 AND bool_and(trigger_row.tgenabled='O' AND trigger_row.tgfoid=fence_oid AND trigger_row.tgtype=62) AS exact
    FROM pg_trigger AS trigger_row, objects
    WHERE trigger_row.tgrelid=ANY(ARRAY[state_oid,exceptions_oid]) AND trigger_row.tgname='application_mutation_fence' AND NOT trigger_row.tgisinternal
), expected_table_acl(relation_name,grantee,privilege_type,is_grantable) AS (
    SELECT relation_name,'punaro_owner',privilege_type,false
    FROM (VALUES ('brain.secret_guard_state'),('brain.secret_exceptions')) AS relations(relation_name)
    CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),('REFERENCES'),('TRIGGER'),('MAINTAIN')) AS privileges(privilege_type)
    UNION ALL SELECT relation_name,'punaro_app','SELECT',false
    FROM (VALUES ('brain.secret_guard_state'),('brain.secret_exceptions')) AS relations(relation_name)
), actual_table_acl AS (
    SELECT relation.oid::regclass::text,COALESCE(grantee.rolname,'PUBLIC'),entry.privilege_type,entry.is_grantable
    FROM pg_class AS relation
    CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) AS entry
    LEFT JOIN pg_roles AS grantee ON grantee.oid=entry.grantee, objects
    WHERE relation.oid=ANY(ARRAY[state_oid,exceptions_oid])
), expected_column_acl(relation_name,column_name,grantee,privilege_type,is_grantable) AS (
    SELECT 'brain.secret_exceptions',column_name,'punaro_app','INSERT',false
    FROM (VALUES ('project_id'),('rule_version'),('rule_id'),('field_path'),('value_fingerprint'),('approved_by')) AS columns(column_name)
    UNION ALL SELECT 'brain.secret_exceptions','revoked_at','punaro_app','UPDATE',false
), actual_column_acl AS (
    SELECT attribute.attrelid::regclass::text,attribute.attname,COALESCE(grantee.rolname,'PUBLIC'),entry.privilege_type,entry.is_grantable
    FROM pg_attribute AS attribute
    CROSS JOIN LATERAL aclexplode(attribute.attacl) AS entry
    LEFT JOIN pg_roles AS grantee ON grantee.oid=entry.grantee, objects
    WHERE attribute.attrelid=ANY(ARRAY[state_oid,exceptions_oid])
      AND attribute.attnum>0 AND NOT attribute.attisdropped AND attribute.attacl IS NOT NULL
)
SELECT state_oid IS NOT NULL AND exceptions_oid IS NOT NULL AND exact_index_oid IS NOT NULL AND fence_oid IS NOT NULL
   AND table_safety.exact AND constraint_safety.exact AND index_safety.exact AND fence_safety.exact
   AND NOT EXISTS (SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns)
   AND NOT EXISTS (SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)
   AND NOT EXISTS (SELECT * FROM expected_table_acl EXCEPT SELECT * FROM actual_table_acl)
   AND NOT EXISTS (SELECT * FROM actual_table_acl EXCEPT SELECT * FROM expected_table_acl)
   AND NOT EXISTS (SELECT * FROM expected_column_acl EXCEPT SELECT * FROM actual_column_acl)
   AND NOT EXISTS (SELECT * FROM actual_column_acl EXCEPT SELECT * FROM expected_column_acl)
   AND EXISTS (SELECT 1 FROM brain.secret_guard_state WHERE singleton AND rule_version=$1 AND rule_digest=$2)
   AND EXISTS (SELECT 1 FROM pg_index WHERE indexrelid=exact_index_oid AND indrelid=exceptions_oid
       AND indisunique AND indisvalid AND indisready AND indnkeyatts=5 AND indkey='2 3 4 5 6'::int2vector
       AND indexprs IS NULL AND pg_get_expr(indpred,indrelid)='(revoked_at IS NULL)')
   AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=state_oid AND contype='p' AND conkey=ARRAY[1]::smallint[] AND convalidated)
   AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=state_oid AND contype='c' AND conkey=ARRAY[1]::smallint[] AND convalidated AND pg_get_expr(conbin,conrelid)='singleton')
   AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=state_oid AND contype='c' AND conkey=ARRAY[2]::smallint[] AND convalidated AND pg_get_expr(conbin,conrelid)='(rule_version = 1)')
   AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=state_oid AND contype='c' AND conkey=ARRAY[3]::smallint[] AND convalidated AND pg_get_expr(conbin,conrelid)='(octet_length(rule_digest) = 32)')
   AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=exceptions_oid AND contype='p' AND conkey=ARRAY[1]::smallint[] AND convalidated)
   AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=exceptions_oid AND contype='f' AND conkey=ARRAY[2]::smallint[] AND confrelid='relay.projects'::regclass AND confkey=ARRAY[1]::smallint[] AND confdeltype='a' AND confupdtype='a' AND confmatchtype='s' AND convalidated)
   AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=exceptions_oid AND contype='f' AND conkey=ARRAY[7]::smallint[] AND confrelid='auth.principals'::regclass AND confkey=ARRAY[1]::smallint[] AND confdeltype='a' AND confupdtype='a' AND confmatchtype='s' AND convalidated)
   AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=exceptions_oid AND contype='c' AND conkey=ARRAY[3]::smallint[] AND convalidated AND pg_get_expr(conbin,conrelid)='(rule_version = 1)')
   AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=exceptions_oid AND contype='c' AND conkey=ARRAY[4]::smallint[] AND convalidated AND pg_get_expr(conbin,conrelid)='(rule_id = ANY (ARRAY[''private-key''::text, ''bearer-token''::text, ''credential-assignment''::text, ''sensitive-field''::text]))')
   AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=exceptions_oid AND contype='c' AND conkey=ARRAY[5]::smallint[] AND convalidated AND pg_get_expr(conbin,conrelid)='((octet_length(field_path) >= 1) AND (octet_length(field_path) <= 1024))')
   AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=exceptions_oid AND contype='c' AND conkey=ARRAY[6]::smallint[] AND convalidated AND pg_get_expr(conbin,conrelid)='(octet_length(value_fingerprint) = 32)')
   AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=exceptions_oid AND contype='c' AND conkey=ARRAY[9,8]::smallint[] AND convalidated AND pg_get_expr(conbin,conrelid)='((revoked_at IS NULL) OR (revoked_at >= created_at))')
FROM objects,table_safety,constraint_safety,index_safety,fence_safety`, secretguard.RuleVersion, digest[:]).Scan(&available)
	return available, err
}
