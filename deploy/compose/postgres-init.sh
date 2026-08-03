#!/bin/sh
set -eu

app_password=$(cat /run/punaro-secrets/postgres_app_password)
if [ -z "$app_password" ]; then
	echo 'postgres application password must not be empty' >&2
	exit 1
fi

psql --set=ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
	--set=app_password="$app_password" <<'SQL'
CREATE ROLE punaro_app LOGIN PASSWORD :'app_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
GRANT CONNECT ON DATABASE punaro TO punaro_app;
SQL
