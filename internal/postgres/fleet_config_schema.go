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
)
SELECT fleet_namespace_oid IS NOT NULL
   AND releases_oid IS NOT NULL
   AND desired_oid IS NOT NULL
   AND fence_oid IS NOT NULL
   AND pg_get_userbyid((SELECT nspowner FROM pg_namespace WHERE oid = fleet_namespace_oid)) = 'punaro_owner'
   AND (SELECT count(*) = 2 AND bool_and(relkind = 'r' AND relpersistence = 'p' AND pg_get_userbyid(relowner) = 'punaro_owner')
        FROM pg_class WHERE oid = ANY(ARRAY[releases_oid, desired_oid]))
   AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = releases_oid AND contype = 'p' AND convalidated)
   AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = desired_oid AND contype = 'p' AND convalidated)
   AND EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = desired_oid AND contype = 'f' AND confrelid = releases_oid AND convalidated)
   AND EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = releases_oid AND attname = 'archive' AND atttypid = 'bytea'::regtype AND attnotnull AND NOT attisdropped)
   AND EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = releases_oid AND attname = 'digest' AND atttypid = 'text'::regtype AND attnotnull AND NOT attisdropped)
   AND EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = desired_oid AND attname = 'release_digest' AND atttypid = 'text'::regtype AND attnotnull AND NOT attisdropped)
   AND EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = desired_oid AND attname = 'generation' AND atttypid = 'bigint'::regtype AND attnotnull AND NOT attisdropped)
   AND EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = desired_oid AND attname = 'preview_hash' AND atttypid = 'text'::regtype AND attnotnull AND NOT attisdropped)
   AND (SELECT count(*) = 2 FROM pg_trigger
        WHERE tgrelid = ANY(ARRAY[releases_oid, desired_oid])
          AND tgname = 'application_mutation_fence' AND NOT tgisinternal AND tgenabled = 'O' AND tgfoid = fence_oid AND tgtype = 62)
   AND has_schema_privilege('punaro_app', 'fleet', 'USAGE')
   AND NOT has_schema_privilege('punaro_app', 'fleet', 'CREATE')
   AND has_table_privilege('punaro_app', 'fleet.releases', 'SELECT')
   AND has_table_privilege('punaro_app', 'fleet.desired', 'SELECT')
   AND NOT has_table_privilege('punaro_app', 'fleet.releases', 'INSERT')
   AND NOT has_table_privilege('punaro_app', 'fleet.desired', 'INSERT')
   AND NOT has_table_privilege('punaro_app', 'fleet.releases', 'UPDATE')
   AND NOT has_table_privilege('punaro_app', 'fleet.desired', 'UPDATE')
   AND NOT has_table_privilege('punaro_app', 'fleet.releases', 'DELETE')
   AND NOT has_table_privilege('punaro_app', 'fleet.desired', 'DELETE')
   AND NOT has_table_privilege('punaro_app', 'fleet.releases', 'TRUNCATE')
   AND NOT has_table_privilege('punaro_app', 'fleet.desired', 'TRUNCATE')
   AND NOT has_table_privilege('punaro_app', 'fleet.releases', 'REFERENCES')
   AND NOT has_table_privilege('punaro_app', 'fleet.desired', 'REFERENCES')
   AND NOT has_table_privilege('punaro_app', 'fleet.releases', 'TRIGGER')
   AND NOT has_table_privilege('punaro_app', 'fleet.desired', 'TRIGGER')
FROM objects`).Scan(&available)
	return available, err
}

func fleetClientStatusControlsAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `
WITH objects AS (
    SELECT to_regclass('fleet.client_status') AS status_oid,
           to_regclass('fleet.client_status_idempotency') AS idempotency_oid,
           to_regprocedure('fleet.put_client_status(text,bigint,text,text,text,text,text,text,bigint,text,text)') AS put_oid,
           to_regprocedure('jobs.guard_application_mutation()') AS fence_oid
)
SELECT status_oid IS NOT NULL AND idempotency_oid IS NOT NULL AND put_oid IS NOT NULL AND fence_oid IS NOT NULL
   AND (SELECT count(*) = 2 AND bool_and(relkind = 'r' AND pg_get_userbyid(relowner) = 'punaro_owner')
        FROM pg_class WHERE oid = ANY(ARRAY[status_oid, idempotency_oid]))
   AND EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = status_oid AND attname = 'machine_id' AND atttypid = 'text'::regtype AND attnotnull AND NOT attisdropped)
   AND EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = status_oid AND attname = 'report_generation' AND atttypid = 'bigint'::regtype AND attnotnull AND NOT attisdropped)
   AND (SELECT prosecdef AND proconfig = ARRAY['search_path=pg_catalog']::text[] AND pg_get_userbyid(proowner) = 'punaro_owner' FROM pg_proc WHERE oid = put_oid)
   AND (SELECT count(*) = 2 FROM pg_trigger
        WHERE tgrelid = ANY(ARRAY[status_oid, idempotency_oid])
          AND tgname = 'application_mutation_fence' AND NOT tgisinternal AND tgenabled = 'O' AND tgfoid = fence_oid AND tgtype = 62)
   AND has_table_privilege('punaro_app', 'fleet.client_status', 'SELECT')
   AND has_function_privilege('punaro_app', put_oid, 'EXECUTE')
   AND NOT has_function_privilege('public', put_oid, 'EXECUTE')
   AND NOT has_table_privilege('punaro_app', 'fleet.client_status', 'INSERT')
   AND NOT has_table_privilege('punaro_app', 'fleet.client_status', 'UPDATE')
   AND NOT has_table_privilege('punaro_app', 'fleet.client_status', 'DELETE')
   AND NOT has_table_privilege('punaro_app', 'fleet.client_status', 'TRUNCATE')
   AND NOT has_table_privilege('punaro_app', 'fleet.client_status', 'REFERENCES')
   AND NOT has_table_privilege('punaro_app', 'fleet.client_status', 'TRIGGER')
   AND NOT has_table_privilege('punaro_app', 'fleet.client_status_idempotency', 'SELECT')
   AND NOT has_table_privilege('punaro_app', 'fleet.client_status_idempotency', 'INSERT')
   AND NOT has_table_privilege('punaro_app', 'fleet.client_status_idempotency', 'UPDATE')
   AND NOT has_table_privilege('punaro_app', 'fleet.client_status_idempotency', 'DELETE')
   AND NOT has_table_privilege('punaro_app', 'fleet.client_status_idempotency', 'TRUNCATE')
   AND NOT has_table_privilege('punaro_app', 'fleet.client_status_idempotency', 'REFERENCES')
   AND NOT has_table_privilege('punaro_app', 'fleet.client_status_idempotency', 'TRIGGER')
FROM objects`).Scan(&available)
	return available, err
}
