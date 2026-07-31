#!/bin/sh
set -eu

if ! docker compose version >/dev/null 2>&1; then
	echo 'production Compose bootstrap test requires Docker Compose v2' >&2
	exit 0
fi

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temporary=$(mktemp -d)
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
printf '%s\n' 'production-owner-password' >"$owner_password"
printf '%s\n' 'initial-incorrect-app-password' >"$app_password"
printf '%s\n' 'postgres://punaro_owner:production-owner-password@127.0.0.1:5432/punaro?sslmode=disable' >"$owner_dsn"
printf '%s\n' 'postgres://punaro_app:production-app-password@127.0.0.1:5432/punaro?sslmode=disable' >"$app_dsn"
chmod 600 "$owner_password" "$app_password" "$owner_dsn" "$app_dsn"
mkdir -m 700 "$data_dir" "$backup_dir"

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
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command 'ALTER DEFAULT PRIVILEGES GRANT ALL ON TABLES TO punaro_app'
if docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap >/dev/null 2>&1; then
	echo 'production bootstrap accepted unsafe default privileges for the application role' >&2
	exit 1
fi
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command 'ALTER DEFAULT PRIVILEGES REVOKE ALL ON TABLES FROM punaro_app'
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
	--public-url "$PUNARO_PUBLIC_URL")
test -f "$installation_dir/installation.json"
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-app-password' postgres-bootstrap --host 127.0.0.1 --username punaro_app --dbname punaro --tuples-only --no-align --command 'SELECT 1 FROM auth.installation_owner LIMIT 1' | grep -Fxq 1
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-owner-password' postgres-bootstrap --host 127.0.0.1 --username punaro_owner --dbname punaro --command 'GRANT TEMPORARY ON DATABASE punaro TO punaro_app'
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps postgres-bootstrap
if docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" run --rm --no-deps --entrypoint psql -e PGPASSWORD='production-app-password' postgres-bootstrap --host 127.0.0.1 --username punaro_app --dbname punaro --command 'CREATE TEMPORARY TABLE forbidden_temp ()' >/dev/null 2>&1; then
	echo 'production bootstrap retained a TEMPORARY privilege for the application role' >&2
	exit 1
fi
