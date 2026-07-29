#!/bin/sh
set -eu

app_password=$(cat /run/secrets/postgres_app_password)
owner_password=$(cat /run/secrets/postgres_owner_password)
if [ -z "$app_password" ]; then
	echo 'postgres application password must not be empty' >&2
	exit 1
fi

temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT INT TERM
chmod 700 "$temporary"
escaped_password=$(printf '%s' "$owner_password" | sed 's/\\/\\\\/g; s/:/\\:/g')
printf '127.0.0.1:5432:%s:%s:%s\n' "$POSTGRES_DB" "$POSTGRES_USER" "$escaped_password" >"$temporary/pgpass"
chmod 600 "$temporary/pgpass"
export PGPASSFILE="$temporary/pgpass"

psql --set=ON_ERROR_STOP=1 --host 127.0.0.1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
	--set=app_password="$app_password" <<'SQL'
SELECT format('CREATE ROLE punaro_app LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT', :'app_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'punaro_app')
\gexec
GRANT CONNECT ON DATABASE punaro TO punaro_app;
SQL
