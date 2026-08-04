#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
bootstrap_script="$root/deploy/compose/postgres-bootstrap.sh"
fence_line=$(grep -n -m 1 '^ALTER ROLE punaro_app NOLOGIN;$' "$bootstrap_script" | cut -d: -f1)
terminate_line=$(grep -n -m 1 '^SELECT pg_terminate_backend(pid)$' "$bootstrap_script" | cut -d: -f1)
reassign_line=$(grep -n -m 1 '^REASSIGN OWNED BY punaro_app TO punaro_owner;$' "$bootstrap_script" | cut -d: -f1)
public_function_revoke_line=$(grep -n -m 1 -F 'REVOKE ALL PRIVILEGES ON FUNCTION %I.%I(%s) FROM PUBLIC' "$bootstrap_script" | cut -d: -f1)
if [ -z "$fence_line" ] || [ -z "$terminate_line" ] || [ -z "$reassign_line" ] || [ -z "$public_function_revoke_line" ] || [ "$fence_line" -ge "$terminate_line" ] || [ "$terminate_line" -ge "$reassign_line" ]; then
	echo 'production bootstrap does not terminate pre-existing application sessions before ownership cleanup' >&2
	exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
	echo 'production Compose bootstrap test requires Docker Compose v2' >&2
	exit 0
fi
temporary_root=${PUNARO_TEST_TMPDIR:-${TMPDIR:-/tmp}}
temporary=$(mktemp -d "$temporary_root/punaro-production-bootstrap.XXXXXX")
project="punaro-production-bootstrap-${GITHUB_RUN_ID:-local}-$$"
cleanup() {
	docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" down --volumes --remove-orphans >/dev/null 2>&1 || true
	rm -rf "$temporary"
}
trap cleanup EXIT INT TERM
chmod 700 "$temporary"

owner_password="$temporary/owner-password"
app_password="$temporary/app-password"
owner_dsn="$temporary/owner.dsn"
app_dsn="$temporary/app.dsn"
data_dir="$temporary/data"
backup_dir="$temporary/backup"
installation_dir="$temporary/installation"
relay_machines="$temporary/relay-machines.json"
printf '%s\n' 'production-owner-password' >"$owner_password"
printf '%s\n' 'initial-incorrect-app-password' >"$app_password"
printf '%s\n' 'postgres://punaro_owner:production-owner-password@127.0.0.1:5432/punaro?sslmode=disable' >"$owner_dsn"
printf '%s\n' 'postgres://punaro_app:production-app-password@127.0.0.1:5432/punaro?sslmode=disable' >"$app_dsn"
chmod 600 "$owner_password" "$app_password" "$owner_dsn" "$app_dsn"
mkdir -m 700 "$data_dir" "$data_dir/attachments" "$backup_dir"
printf '%s\n' '[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/a/"],"endpoints":[],"attachment_device_id":""}]' >"$relay_machines"
chmod 600 "$relay_machines"

export PUNARO_IMAGE='example.invalid/punaro@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
export PUNARO_RUNTIME_UID="$(id -u)"
export PUNARO_RUNTIME_GID="$(id -g)"
export PUNARO_PUBLIC_URL='https://punaro.example'
export PUNARO_POSTGRES_OWNER_PASSWORD_FILE="$owner_password"
export PUNARO_POSTGRES_APP_PASSWORD_FILE="$app_password"
export PUNARO_POSTGRES_APP_DSN_FILE="$app_dsn"

(
	unset PUNARO_IMAGE PUNARO_RUNTIME_UID PUNARO_RUNTIME_GID PUNARO_PUBLIC_URL PUNARO_POSTGRES_OWNER_PASSWORD_FILE PUNARO_POSTGRES_APP_PASSWORD_FILE PUNARO_POSTGRES_APP_DSN_FILE
	export PUNARO_COMPOSE_PROJECT_NAME="$project"
	"$root/scripts/production-compose" ps
)

docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" up --detach --wait postgres
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap
if docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-app-password' postgres-bootstrap --host 127.0.0.1 --username punaro_app --dbname punaro --tuples-only --no-align --command 'SELECT 1' >/dev/null 2>&1; then
	echo 'production bootstrap unexpectedly accepted a DSN password different from its configured secret' >&2
	exit 1
fi
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command 'ALTER ROLE punaro_app SUPERUSER'
if docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap >/dev/null 2>&1; then
	echo 'production bootstrap accepted an elevated application role' >&2
	exit 1
fi
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command 'ALTER ROLE punaro_app NOSUPERUSER'
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command "CREATE ROLE punaro_owner_member LOGIN PASSWORD 'owner-member-password'; GRANT punaro_owner TO punaro_owner_member"
if docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap >/dev/null 2>&1; then
	echo 'production bootstrap accepted a member of the owner role' >&2
	exit 1
fi
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command 'REVOKE punaro_owner FROM punaro_owner_member; DROP ROLE punaro_owner_member'
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command 'CREATE SCHEMA legacy; CREATE TABLE legacy.unsafe (); ALTER SCHEMA legacy OWNER TO punaro_app; ALTER TABLE legacy.unsafe OWNER TO punaro_app; GRANT USAGE ON SCHEMA legacy TO punaro_app; GRANT SELECT ON legacy.unsafe TO punaro_app'
printf '%s\n' 'production-app-password' >"$app_password"
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command "ALTER ROLE punaro_app SET default_transaction_read_only = on; ALTER ROLE punaro_app IN DATABASE punaro SET default_transaction_read_only = on; ALTER ROLE punaro_app CONNECTION LIMIT 0 VALID UNTIL '2000-01-01'"
if docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap >/dev/null 2>&1; then
	echo 'production bootstrap accepted an application-role grant on a legacy object' >&2
	exit 1
fi
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command 'REVOKE ALL PRIVILEGES ON SCHEMA legacy FROM punaro_app; REVOKE ALL PRIVILEGES ON legacy.unsafe FROM punaro_app'
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command 'CREATE SCHEMA legacy_columns; CREATE TABLE legacy_columns.records (secret text); GRANT USAGE ON SCHEMA legacy_columns TO punaro_app; GRANT UPDATE (secret) ON legacy_columns.records TO punaro_app'
if docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap >/dev/null 2>&1; then
	echo 'production bootstrap accepted an application-role column grant on a legacy object' >&2
	exit 1
fi
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command 'REVOKE ALL PRIVILEGES ON SCHEMA legacy_columns FROM punaro_app; REVOKE ALL PRIVILEGES ON legacy_columns.records FROM punaro_app'
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-app-password' postgres-bootstrap --host 127.0.0.1 --username punaro_app --dbname punaro --tuples-only --no-align --command 'SELECT 1' | grep -Fxq 1
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command "CREATE ROLE punaro_function_grantee LOGIN PASSWORD 'function-grantee-password'; CREATE TABLE public.bootstrap_granted_table (); ALTER TABLE public.bootstrap_granted_table OWNER TO punaro_app; GRANT SELECT ON public.bootstrap_granted_table TO punaro_function_grantee; CREATE FUNCTION public.bootstrap_public_definer() RETURNS name LANGUAGE sql SECURITY DEFINER AS \$\$SELECT current_user\$\$; ALTER FUNCTION public.bootstrap_public_definer() OWNER TO punaro_app; GRANT EXECUTE ON FUNCTION public.bootstrap_public_definer() TO PUBLIC, punaro_function_grantee"
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap
if docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-app-password' postgres-bootstrap --host 127.0.0.1 --username punaro_app --dbname punaro --command 'SELECT public.bootstrap_public_definer()' >/dev/null 2>&1; then
	echo 'production bootstrap retained PUBLIC execution on a reassigned security-definer function' >&2
	exit 1
fi
if docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='function-grantee-password' postgres-bootstrap --host 127.0.0.1 --username punaro_function_grantee --dbname punaro --command 'SELECT * FROM public.bootstrap_granted_table' >/dev/null 2>&1; then
	echo 'production bootstrap retained a role-specific grant on a reassigned table' >&2
	exit 1
fi
if docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='function-grantee-password' postgres-bootstrap --host 127.0.0.1 --username punaro_function_grantee --dbname punaro --command 'SELECT public.bootstrap_public_definer()' >/dev/null 2>&1; then
	echo 'production bootstrap retained a role-specific execution grant on a reassigned security-definer function' >&2
	exit 1
fi
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command 'DROP ROLE punaro_function_grantee'
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command 'ALTER DEFAULT PRIVILEGES GRANT ALL ON TABLES TO punaro_app'
if docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap >/dev/null 2>&1; then
	echo 'production bootstrap accepted unsafe default privileges for the application role' >&2
	exit 1
fi
if ! docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-app-password' postgres-bootstrap --host 127.0.0.1 --username punaro_app --dbname punaro --command 'SELECT 1' >/dev/null 2>&1; then
	echo 'production bootstrap disabled the application role after refusing unsafe default privileges' >&2
	exit 1
fi
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command 'ALTER DEFAULT PRIVILEGES REVOKE ALL ON TABLES FROM punaro_app'
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command 'ALTER DEFAULT PRIVILEGES GRANT ALL ON TABLES TO PUBLIC'
if docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap >/dev/null 2>&1; then
	echo 'production bootstrap accepted unsafe PUBLIC default table privileges' >&2
	exit 1
fi
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command 'ALTER DEFAULT PRIVILEGES REVOKE ALL ON TABLES FROM PUBLIC'
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command "CREATE ROLE punaro_default_function_grantee LOGIN PASSWORD 'default-function-grantee-password'; ALTER DEFAULT PRIVILEGES GRANT EXECUTE ON FUNCTIONS TO punaro_default_function_grantee"
if docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap >/dev/null 2>&1; then
	echo 'production bootstrap accepted unsafe third-party function default privileges' >&2
	exit 1
fi
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command 'ALTER DEFAULT PRIVILEGES REVOKE ALL ON FUNCTIONS FROM punaro_default_function_grantee; DROP ROLE punaro_default_function_grantee'
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command "CREATE ROLE punaro_default_schema_grantee LOGIN PASSWORD 'default-schema-grantee-password'; ALTER DEFAULT PRIVILEGES GRANT CREATE ON SCHEMAS TO punaro_default_schema_grantee"
if docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap >/dev/null 2>&1; then
	echo 'production bootstrap accepted unsafe third-party schema default privileges' >&2
	exit 1
fi
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command 'ALTER DEFAULT PRIVILEGES REVOKE ALL ON SCHEMAS FROM punaro_default_schema_grantee; DROP ROLE punaro_default_schema_grantee'
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command 'GRANT SET ON PARAMETER session_replication_role TO punaro_app'
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap
if docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-app-password' postgres-bootstrap --host 127.0.0.1 --username punaro_app --dbname punaro --command 'SET session_replication_role = replica' >/dev/null 2>&1; then
	echo 'production bootstrap retained an application-role parameter grant' >&2
	exit 1
fi
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command 'GRANT SET ON PARAMETER session_replication_role TO PUBLIC'
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap
if docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-app-password' postgres-bootstrap --host 127.0.0.1 --username punaro_app --dbname punaro --command 'SET session_replication_role = replica' >/dev/null 2>&1; then
	echo 'production bootstrap retained a PUBLIC parameter grant for the application role' >&2
	exit 1
fi
stale_output="$temporary/stale-session"
(docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint env -e PGAPPNAME=production-stale-session -e PGPASSWORD='production-app-password' postgres-bootstrap psql --host 127.0.0.1 --username punaro_app --dbname punaro --command 'SELECT pg_sleep(30)' >"$stale_output" 2>&1) & stale_session=$!
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command "CREATE ROLE punaro_legacy_group NOLOGIN; CREATE ROLE punaro_legacy_member LOGIN PASSWORD 'legacy-member-password'; GRANT punaro_app TO punaro_legacy_group; GRANT punaro_legacy_group TO punaro_legacy_member"
member_stale_output="$temporary/member-stale-session"
(docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint env -e PGAPPNAME=production-member-stale-session -e PGPASSWORD='legacy-member-password' postgres-bootstrap psql --host 127.0.0.1 --username punaro_legacy_member --dbname punaro --command 'SET ROLE punaro_app; SELECT pg_sleep(30)' >"$member_stale_output" 2>&1) & member_stale_session=$!
for attempt in $(seq 1 30); do docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --tuples-only --no-align --command "SELECT 1 FROM pg_stat_activity WHERE application_name = 'production-stale-session'" | grep -Fxq 1 && break; sleep 1; done
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --tuples-only --no-align --command "SELECT 1 FROM pg_stat_activity WHERE application_name = 'production-stale-session'" | grep -Fxq 1 || { echo 'production stale-session test did not authenticate its application client' >&2; exit 1; }
for attempt in $(seq 1 30); do docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --tuples-only --no-align --command "SELECT 1 FROM pg_stat_activity WHERE application_name = 'production-member-stale-session'" | grep -Fxq 1 && break; sleep 1; done
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --tuples-only --no-align --command "SELECT 1 FROM pg_stat_activity WHERE application_name = 'production-member-stale-session'" | grep -Fxq 1 || { echo 'production member stale-session test did not assume its application role' >&2; exit 1; }
printf '%s\n' 'rotated-app-password' >"$app_password"
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap
if wait "$stale_session"; then
	echo 'production bootstrap retained an application session authenticated with the old password' >&2
	exit 1
fi
if wait "$member_stale_session"; then
	echo 'production bootstrap retained a member session that had assumed the application role' >&2
	exit 1
fi
if docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='legacy-member-password' postgres-bootstrap --host 127.0.0.1 --username punaro_legacy_member --dbname punaro --command 'SET ROLE punaro_app' >/dev/null 2>&1; then
	echo 'production bootstrap retained application-role membership for a legacy login role' >&2
	exit 1
fi
printf '%s\n' 'production-app-password' >"$app_password"
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap
if docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-app-password' postgres-bootstrap --host 127.0.0.1 --username punaro_app --dbname punaro --command 'SELECT * FROM legacy.unsafe' >/dev/null 2>&1; then
	echo 'production bootstrap retained an explicit application-role grant on a reassigned legacy object' >&2
	exit 1
fi
if docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-app-password' postgres-bootstrap --host 127.0.0.1 --username punaro_app --dbname postgres --command 'SELECT 1' >/dev/null 2>&1; then

	echo 'production bootstrap left the application role able to connect to the default postgres database' >&2
	exit 1
fi
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname postgres --command 'CREATE DATABASE punaro_bootstrap_other'
if docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-app-password' postgres-bootstrap --host 127.0.0.1 --username punaro_app --dbname punaro_bootstrap_other --command 'SELECT 1' >/dev/null 2>&1; then
	echo 'production HBA allowed the application role to connect outside the Punaro database' >&2
	exit 1
fi
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro_bootstrap_other --command 'CREATE SCHEMA legacy; CREATE TABLE legacy.unsafe (); ALTER SCHEMA legacy OWNER TO punaro_app; ALTER TABLE legacy.unsafe OWNER TO punaro_app'
if docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap >/dev/null 2>&1; then
	echo 'production bootstrap rotated an application role with cross-database ownership' >&2
	exit 1
fi
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname postgres --command 'DROP DATABASE punaro_bootstrap_other WITH (FORCE)'
(cd "$root" && go run ./cmd/punaro init \
	--directory "$installation_dir" \
	--data-dir "$data_dir" \
	--backup-dir "$backup_dir" \
	--image "$PUNARO_IMAGE" \
	--owner-dsn-file "$owner_dsn" \
	--app-dsn-file "$app_dsn" \
	--owner-name 'production bootstrap' \
	--mode proxy \
	--public-url "$PUNARO_PUBLIC_URL" \
	--relay-machines-file "$relay_machines" \
	--trusted-attachments \
	--trusted-attachment-blob-dir "$data_dir/attachments")
test -f "$installation_dir/installation.json"
grep -Fxq 'PUNARO_RELAY_ENABLED=true' "$installation_dir/punarod.env"
grep -Fxq 'PUNARO_RELAY_STORE=postgres' "$installation_dir/punarod.env"
grep -Fxq 'PUNARO_TRUSTED_ATTACHMENTS_ENABLED=true' "$installation_dir/punarod.env"
grep -Fxq 'PUNARO_TRUSTED_ATTACHMENT_BLOB_DIR=/var/lib/punaro/attachments' "$installation_dir/punarod.env"
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-app-password' postgres-bootstrap --host 127.0.0.1 --username punaro_app --dbname punaro --tuples-only --no-align --command 'SELECT 1 FROM auth.installation_owner LIMIT 1' | grep -Fxq 1
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-app-password' postgres-bootstrap --host 127.0.0.1 --username punaro_app --dbname punaro --command 'SELECT 1 FROM relay.projects LIMIT 1'
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command 'GRANT TRUNCATE ON relay.projects TO punaro_app'
if docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap >/dev/null 2>&1; then
	echo 'production bootstrap accepted an excessive application table privilege' >&2
	exit 1
fi
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command 'REVOKE TRUNCATE ON relay.projects FROM punaro_app'
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command "CREATE FUNCTION relay.bootstrap_owner_definer() RETURNS name LANGUAGE sql SECURITY DEFINER AS \$\$SELECT current_user\$\$"
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap
if docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-app-password' postgres-bootstrap --host 127.0.0.1 --username punaro_app --dbname punaro --command 'SELECT relay.bootstrap_owner_definer()' >/dev/null 2>&1; then
	echo 'production bootstrap retained PUBLIC execution on an owner security-definer function' >&2
	exit 1
fi
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command 'CREATE SCHEMA bootstrap_legacy; CREATE VIEW bootstrap_legacy.owner_public_view AS SELECT * FROM relay.projects; ALTER SCHEMA bootstrap_legacy OWNER TO punaro_owner; ALTER VIEW bootstrap_legacy.owner_public_view OWNER TO punaro_owner; GRANT USAGE ON SCHEMA bootstrap_legacy TO PUBLIC; GRANT SELECT ON bootstrap_legacy.owner_public_view TO PUBLIC'
if docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap >/dev/null 2>&1; then
	echo 'production bootstrap accepted PUBLIC access to an owner relation outside Punaro schemas' >&2
	exit 1
fi
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command 'REVOKE ALL PRIVILEGES ON bootstrap_legacy.owner_public_view FROM PUBLIC; REVOKE ALL PRIVILEGES ON SCHEMA bootstrap_legacy FROM PUBLIC'
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command "CREATE FUNCTION relay.bootstrap_app_trigger() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS \$\$ BEGIN RETURN NEW; END \$\$; ALTER FUNCTION relay.bootstrap_app_trigger() OWNER TO punaro_app; CREATE TRIGGER bootstrap_app_trigger BEFORE INSERT ON relay.projects FOR EACH ROW EXECUTE FUNCTION relay.bootstrap_app_trigger()"
if docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap >/dev/null 2>&1; then
	echo 'production bootstrap accepted an application-owned trigger function' >&2
	exit 1
fi
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command 'DROP TRIGGER bootstrap_app_trigger ON relay.projects; DROP FUNCTION relay.bootstrap_app_trigger()'
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command "CREATE FUNCTION relay.bootstrap_app_expression(value text) RETURNS boolean LANGUAGE sql SECURITY DEFINER AS \$\$ SELECT value <> '' \$\$; ALTER FUNCTION relay.bootstrap_app_expression(text) OWNER TO punaro_app; CREATE TABLE relay.bootstrap_expression (value text CHECK (relay.bootstrap_app_expression(value)))"
if docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap >/dev/null 2>&1; then
	echo 'production bootstrap accepted a stored expression using an application-owned function' >&2
	exit 1
fi
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command 'DROP TABLE relay.bootstrap_expression; DROP FUNCTION relay.bootstrap_app_expression(text)'
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command "CREATE FUNCTION relay.bootstrap_app_policy(value text) RETURNS boolean LANGUAGE sql SECURITY DEFINER AS \$\$ SELECT value <> '' \$\$; ALTER FUNCTION relay.bootstrap_app_policy(text) OWNER TO punaro_app; CREATE TABLE relay.bootstrap_policy (value text); ALTER TABLE relay.bootstrap_policy ENABLE ROW LEVEL SECURITY; CREATE POLICY bootstrap_policy ON relay.bootstrap_policy USING (relay.bootstrap_app_policy(value))"
if docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap >/dev/null 2>&1; then
	echo 'production bootstrap accepted an RLS policy using an application-owned function' >&2
	exit 1
fi
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command 'DROP TABLE relay.bootstrap_policy; DROP FUNCTION relay.bootstrap_app_policy(text)'
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command "CREATE ROLE punaro_database_creator LOGIN PASSWORD 'database-creator-password'; GRANT CREATE ON DATABASE punaro TO punaro_database_creator"
if docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap >/dev/null 2>&1; then
	echo 'production bootstrap accepted a non-owner database CREATE grant' >&2
	exit 1
fi
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command 'REVOKE CREATE ON DATABASE punaro FROM punaro_database_creator; DROP ROLE punaro_database_creator'
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command 'GRANT TEMPORARY ON DATABASE punaro TO punaro_app'
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap
if docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-app-password' postgres-bootstrap --host 127.0.0.1 --username punaro_app --dbname punaro --command 'CREATE TEMPORARY TABLE forbidden_temp ()' >/dev/null 2>&1; then
	echo 'production bootstrap retained a TEMPORARY privilege for the application role' >&2
	exit 1
fi
