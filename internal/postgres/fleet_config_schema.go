package postgres

import "context"

func fleetControlsAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `
WITH objects AS (
    SELECT to_regnamespace('fleet') AS fleet_namespace_oid,
           to_regclass('fleet.releases') AS releases_oid,
           to_regclass('fleet.desired') AS desired_oid,
           to_regprocedure('jobs.guard_application_mutation()') AS fence_oid
), expected_columns(relation_name, column_name, type_name, not_null, default_expression) AS (
    VALUES
      ('fleet.releases','digest','text',true,''),
      ('fleet.releases','source_commit','text',true,''),
      ('fleet.releases','archive','bytea',true,''),
      ('fleet.releases','skill_count','integer',true,''),
      ('fleet.releases','file_count','integer',true,''),
      ('fleet.releases','total_bytes','bigint',true,''),
      ('fleet.releases','created_at','timestamp with time zone',true,'statement_timestamp()'),
      ('fleet.desired','id','boolean',true,'true'),
      ('fleet.desired','release_digest','text',true,''),
      ('fleet.desired','generation','bigint',true,''),
      ('fleet.desired','published_at','timestamp with time zone',true,'statement_timestamp()'),
      ('fleet.desired','preview_hash','text',true,'')
), actual_columns AS (
    SELECT attribute.attrelid::regclass::text, attribute.attname, format_type(attribute.atttypid, attribute.atttypmod),
           attribute.attnotnull, COALESCE(pg_get_expr(default_value.adbin, default_value.adrelid), '')
    FROM pg_attribute AS attribute
    LEFT JOIN pg_attrdef AS default_value ON default_value.adrelid = attribute.attrelid AND default_value.adnum = attribute.attnum, objects
    WHERE attribute.attrelid = ANY(ARRAY[releases_oid, desired_oid]) AND attribute.attnum > 0 AND NOT attribute.attisdropped
), table_safety AS (
    SELECT count(*) = 2 AND bool_and(relation.relkind = 'r' AND relation.relpersistence = 'p' AND NOT relation.relrowsecurity
           AND NOT relation.relforcerowsecurity AND pg_get_userbyid(relation.relowner) = 'punaro_owner') AS exact
    FROM pg_class AS relation, objects
    WHERE relation.oid = ANY(ARRAY[releases_oid, desired_oid])
), constraint_safety AS (
    SELECT count(*) = 12 AND bool_and(constraint_row.convalidated AND NOT constraint_row.condeferrable AND NOT constraint_row.condeferred) AS exact
    FROM pg_constraint AS constraint_row, objects
    WHERE constraint_row.conrelid = ANY(ARRAY[releases_oid, desired_oid]) AND constraint_row.contype <> 'n'
), index_safety AS (
    SELECT count(*) = 2 AND bool_and(index_row.indisvalid AND index_row.indisready) AS exact
    FROM pg_index AS index_row, objects
    WHERE index_row.indrelid = ANY(ARRAY[releases_oid, desired_oid])
), fence_safety AS (
    SELECT count(*) = 2 AND bool_and(trigger_row.tgenabled = 'O' AND trigger_row.tgfoid = fence_oid AND trigger_row.tgtype = 62) AS exact
    FROM pg_trigger AS trigger_row, objects
    WHERE trigger_row.tgrelid = ANY(ARRAY[releases_oid, desired_oid])
      AND trigger_row.tgname = 'application_mutation_fence' AND NOT trigger_row.tgisinternal
), expected_table_acl(relation_name, grantee, privilege_type, is_grantable) AS (
    SELECT relation_name, 'punaro_owner', privilege_type, false
    FROM (VALUES ('fleet.releases'), ('fleet.desired')) AS relations(relation_name)
    CROSS JOIN (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'), ('TRUNCATE'), ('REFERENCES'), ('TRIGGER'), ('MAINTAIN')) AS privileges(privilege_type)
    UNION ALL SELECT relation_name, 'punaro_app', 'SELECT', false
    FROM (VALUES ('fleet.releases'), ('fleet.desired')) AS relations(relation_name)
), actual_table_acl AS (
    SELECT relation.oid::regclass::text, COALESCE(grantee.rolname, 'PUBLIC'), entry.privilege_type, entry.is_grantable
    FROM pg_class AS relation
    CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl, acldefault('r', relation.relowner))) AS entry
    LEFT JOIN pg_roles AS grantee ON grantee.oid = entry.grantee, objects
    WHERE relation.oid = ANY(ARRAY[releases_oid, desired_oid])
), schema_acl AS (
    SELECT pg_get_userbyid(namespace.nspowner) = 'punaro_owner'
           AND has_schema_privilege('punaro_app', 'fleet', 'USAGE')
           AND NOT has_schema_privilege('punaro_app', 'fleet', 'CREATE') AS exact
    FROM objects
    JOIN pg_namespace AS namespace ON namespace.oid = objects.fleet_namespace_oid
)
SELECT fleet_namespace_oid IS NOT NULL AND releases_oid IS NOT NULL AND desired_oid IS NOT NULL AND fence_oid IS NOT NULL
   AND table_safety.exact AND constraint_safety.exact AND index_safety.exact AND fence_safety.exact AND schema_acl.exact
   AND NOT EXISTS (SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns)
   AND NOT EXISTS (SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)
   AND NOT EXISTS (SELECT * FROM expected_table_acl EXCEPT SELECT * FROM actual_table_acl)
   AND NOT EXISTS (SELECT * FROM actual_table_acl EXCEPT SELECT * FROM expected_table_acl)
   AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = releases_oid AND contype = 'p' AND conkey = ARRAY[1]::smallint[] AND convalidated)
   AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = desired_oid AND contype = 'p' AND conkey = ARRAY[1]::smallint[] AND convalidated)
   AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = desired_oid AND contype = 'f' AND conkey = ARRAY[2]::smallint[] AND confrelid = releases_oid AND convalidated)
FROM objects, table_safety, constraint_safety, index_safety, fence_safety, schema_acl`).Scan(&available)
	return available, err
}
