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
printf '%s\n' 'production-owner-password' >"$owner_password"
printf '%s\n' 'production-app-password' >"$app_password"
printf '%s\n' 'postgres://punaro_owner:production-owner-password@127.0.0.1:5432/punaro?sslmode=disable' >"$owner_dsn"
printf '%s\n' 'postgres://punaro_app:production-app-password@127.0.0.1:5432/punaro?sslmode=disable' >"$app_dsn"
chmod 600 "$owner_password" "$app_password" "$owner_dsn" "$app_dsn"

export PUNARO_IMAGE='example.invalid/punaro@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
export PUNARO_RUNTIME_UID="$(id -u)"
export PUNARO_RUNTIME_GID="$(id -g)"
export PUNARO_PUBLIC_URL='https://punaro.example'
export PUNARO_POSTGRES_OWNER_PASSWORD_FILE="$owner_password"
export PUNARO_POSTGRES_APP_PASSWORD_FILE="$app_password"
export PUNARO_POSTGRES_APP_DSN_FILE="$app_dsn"

docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" up --detach postgres-bootstrap
docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" wait postgres-bootstrap
PGPASSWORD='production-app-password' docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" exec --no-TTY postgres psql --host 127.0.0.1 --username punaro_app --dbname punaro --tuples-only --no-align --command 'SELECT 1' | grep -Fxq 1
(cd "$root" && go run ./cmd/punaro bootstrap --owner-dsn-file "$owner_dsn" --app-dsn-file "$app_dsn" --owner-name 'production bootstrap')
PGPASSWORD='production-app-password' docker compose --project-name "$project" --file "$root/deploy/compose/production.yaml" exec --no-TTY postgres psql --host 127.0.0.1 --username punaro_app --dbname punaro --tuples-only --no-align --command 'SELECT 1 FROM auth.installation_owner LIMIT 1' | grep -Fxq 1
