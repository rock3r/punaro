#!/bin/sh
set -eu

compose_file=${1:-deploy/compose/production.yaml}

test -f "$compose_file"
test -f docs/production-compose.md
grep -Eq 'pgvector/pgvector:[^[:space:]]+@sha256:[0-9a-f]{64}' "$compose_file"
grep -Fq 'PUNARO_IMAGE:?required' "$compose_file"
grep -Fq 'PUNARO_RUNTIME_UID:?required}:${PUNARO_RUNTIME_GID:?required' "$compose_file"
grep -Fq 'PUNARO_POSTGRES_DSN_FILE: /run/secrets/postgres_app_dsn' "$compose_file"
grep -Fq 'POSTGRES_PASSWORD_FILE: /run/secrets/postgres_owner_password' "$compose_file"
grep -Fq 'POSTGRES_INITDB_ARGS: --auth-host=scram-sha-256' "$compose_file"
grep -Fq 'postgres_app_password' "$compose_file"
if sed -n '/^  postgres:/,/^  postgres-bootstrap:/p' "$compose_file" | grep -Fq 'postgres_app_password'; then
	echo 'postgres must not receive the application password secret' >&2
	exit 1
fi
grep -Fq 'postgres-bootstrap:' "$compose_file"
if [ "$(grep -Fc 'read_only: true' "$compose_file")" -lt 2 ]; then
	echo "production bootstrap and daemon must use read-only filesystems" >&2
	exit 1
fi
if [ "$(grep -Fc 'no-new-privileges:true' "$compose_file")" -lt 2 ]; then
	echo "production bootstrap and daemon must forbid privilege escalation" >&2
	exit 1
fi
grep -Fq '      - DAC_OVERRIDE' "$compose_file"
grep -Fq '      - CHOWN' "$compose_file"
grep -Fq '      - SETUID' "$compose_file"
grep -Fq '      - SETGID' "$compose_file"
grep -Fq 'service_completed_successfully' "$compose_file"
grep -Fq 'pg_isready --host 127.0.0.1 -U punaro_owner -d punaro' "$compose_file"
grep -Fq 'profiles: ["reference-daemon"]' "$compose_file"
grep -Fq "WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'punaro_app')" deploy/compose/postgres-bootstrap.sh
grep -Fq 'REASSIGN OWNED BY punaro_app TO punaro_owner;' deploy/compose/postgres-bootstrap.sh
grep -Fq 'PUBLIC retains CREATE' deploy/compose/postgres-bootstrap.sh
grep -Fq 'PUBLIC table or sequence default privileges' deploy/compose/postgres-bootstrap.sh
grep -Fq 'refusing to rotate elevated punaro_app role attributes' deploy/compose/postgres-bootstrap.sh
grep -Fq '\set app_password `cat /tmp/punaro-bootstrap-secrets/app-password`' deploy/compose/postgres-bootstrap.sh
grep -Fq "ALTER ROLE punaro_app LOGIN PASSWORD :'app_password'" deploy/compose/postgres-bootstrap.sh
grep -Fq 'ALTER ROLE punaro_app RESET ALL;' deploy/compose/postgres-bootstrap.sh
grep -Fq 'ALTER ROLE punaro_app IN DATABASE punaro RESET ALL;' deploy/compose/postgres-bootstrap.sh
if ! sed -n '/^BEGIN;$/,/^COMMIT;$/p' deploy/compose/postgres-bootstrap.sh | grep -Fxq 'ALTER ROLE punaro_app NOLOGIN;'; then
	echo 'production bootstrap must fence application login before the ownership handoff commits' >&2
	exit 1
fi
if grep -Fq -- '--set=app_password=' deploy/compose/postgres-bootstrap.sh; then
	echo "production bootstrap must not expose the application password in psql argv" >&2
	exit 1
fi
grep -Fq 'PUNARO_DEVICE_AUTH_ENABLED: "true"' "$compose_file"
grep -Fq 'PUNARO_RELAY_STORE: sqlite' "$compose_file"
grep -Fq 'read_only: true' "$compose_file"
grep -Fq 'no-new-privileges:true' "$compose_file"
grep -Fq 'cap_drop:' "$compose_file"
if [ "$(grep -Fc 'network_mode: host' "$compose_file")" -ne 3 ]; then
	echo "production services must use the reviewed same-host loopback network" >&2
	exit 1
fi
grep -Fq 'listen_addresses=127.0.0.1' "$compose_file"
grep -Fq 'PUNARO_RUNTIME_UID' docs/production-compose.md
grep -Fq 'PUNARO_RUNTIME_GID' docs/production-compose.md
grep -Fq 'PUNARO_COMPOSE_PROJECT_NAME' docs/production-compose.md
grep -Fq 'pinned by a lowercase sha256 digest' scripts/production-compose
if grep -Eq '^[[:space:]]+ports:' "$compose_file"; then
	echo "production services must not publish host ports" >&2
	exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
	echo "production Compose structure verified; Docker Compose validation requires Docker" >&2
	exit 0
fi

temporary=$(mktemp -d)
cleanup() { rm -rf "$temporary"; }
trap cleanup EXIT INT TERM
chmod 700 "$temporary"
printf '%s\n' 'owner-password' >"$temporary/owner-password"
printf '%s\n' 'app-password' >"$temporary/app-password"
printf '%s\n' 'postgres://punaro_app@postgres:5432/punaro?sslmode=disable' >"$temporary/app.dsn"
chmod 600 "$temporary/owner-password" "$temporary/app-password" "$temporary/app.dsn"
PUNARO_IMAGE='example.invalid/punaro@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
PUNARO_RUNTIME_UID=1000 \
PUNARO_RUNTIME_GID=1000 \
PUNARO_PUBLIC_URL='https://punaro.example' \
PUNARO_POSTGRES_OWNER_PASSWORD_FILE="$temporary/owner-password" \
PUNARO_POSTGRES_APP_PASSWORD_FILE="$temporary/app-password" \
PUNARO_POSTGRES_APP_DSN_FILE="$temporary/app.dsn" \
docker compose -f "$compose_file" config --quiet
