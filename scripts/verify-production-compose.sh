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
grep -Fq 'postgres_app_password' "$compose_file"
grep -Fq '/docker-entrypoint-initdb.d/10-punaro-app-role.sh:ro' "$compose_file"
grep -Fq '/usr/local/bin/punaro-postgres-entrypoint.sh' "$compose_file"
grep -Fq '/run/punaro-secrets:mode=0700,size=1m' "$compose_file"
grep -Fq 'CREATE ROLE punaro_app LOGIN PASSWORD' deploy/compose/postgres-init.sh
grep -Fq '/run/punaro-secrets/postgres_app_password' deploy/compose/postgres-init.sh
grep -Fq 'chown postgres:postgres "$staged_directory"' deploy/compose/postgres-entrypoint.sh
grep -Fq 'chown postgres:postgres "$staged_password"' deploy/compose/postgres-entrypoint.sh
grep -Fq 'PUNARO_DEVICE_AUTH_ENABLED: "true"' "$compose_file"
grep -Fq 'PUNARO_RELAY_STORE: sqlite' "$compose_file"
grep -Fq 'read_only: true' "$compose_file"
grep -Fq 'no-new-privileges:true' "$compose_file"
grep -Fq 'cap_drop:' "$compose_file"
if [ "$(grep -Fc 'network_mode: host' "$compose_file")" -ne 2 ]; then
	echo "production services must use the reviewed same-host loopback network" >&2
	exit 1
fi
grep -Fq 'listen_addresses=127.0.0.1' "$compose_file"
grep -Fq 'PUNARO_RUNTIME_UID' docs/production-compose.md
grep -Fq 'PUNARO_RUNTIME_GID' docs/production-compose.md
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
