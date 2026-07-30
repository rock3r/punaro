#!/bin/sh
set -eu

owner_password=$(cat /run/secrets/postgres_owner_password)
if [ ! -s /run/secrets/postgres_app_password ]; then
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
	<<'SQL'
\set app_password `cat /run/secrets/postgres_app_password`
BEGIN;
SELECT 'CREATE ROLE punaro_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'punaro_app')
\gexec
REASSIGN OWNED BY punaro_app TO punaro_owner;
ALTER ROLE punaro_app LOGIN PASSWORD :'app_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
DO $$
DECLARE membership record;
BEGIN
  FOR membership IN SELECT parent.rolname FROM pg_auth_members members JOIN pg_roles parent ON parent.oid = members.roleid JOIN pg_roles member ON member.oid = members.member WHERE member.rolname = 'punaro_app' LOOP
    EXECUTE format('REVOKE %I FROM punaro_app', membership.rolname);
  END LOOP;
END $$;
REVOKE CREATE ON DATABASE punaro FROM punaro_app;
DO $$
DECLARE schema_name record;
BEGIN
  FOR schema_name IN SELECT nspname FROM pg_namespace WHERE has_schema_privilege('punaro_app', oid, 'CREATE') LOOP
    EXECUTE format('REVOKE CREATE ON SCHEMA %I FROM punaro_app', schema_name.nspname);
  END LOOP;
END $$;
GRANT CONNECT ON DATABASE punaro TO punaro_app;
COMMIT;
SQL
