#!/bin/sh
set -eu

staging=/tmp/punaro-bootstrap-secrets
if [ "$(id -u)" = 0 ]; then
	(umask 077 && mkdir "$staging")
	cp /run/secrets/postgres_owner_password "$staging/owner-password"
	cp /run/secrets/postgres_app_password "$staging/app-password"
	chmod 700 "$staging"
	chmod 600 "$staging/owner-password" "$staging/app-password"
	chown -R 999:999 "$staging"
	exec gosu 999:999 "$0" "$@"
fi
trap 'rm -rf "$staging"' EXIT INT TERM

owner_password=$(cat "$staging/owner-password")
app_password=$(cat "$staging/app-password")
if [ -z "$app_password" ]; then
	echo 'postgres application password must not be empty' >&2
	exit 1
fi

temporary=$(mktemp -d)
chmod 700 "$temporary"
escaped_password=$(printf '%s' "$owner_password" | sed 's/\\/\\\\/g; s/:/\\:/g')
printf '127.0.0.1:5432:%s:%s:%s\n' "$POSTGRES_DB" "$POSTGRES_USER" "$escaped_password" >"$temporary/pgpass"
chmod 600 "$temporary/pgpass"
export PGPASSFILE="$temporary/pgpass"

psql --set=ON_ERROR_STOP=1 --host 127.0.0.1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
	<<'SQL'
\set app_password `cat /tmp/punaro-bootstrap-secrets/app-password`
BEGIN;
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_database database, aclexplode(coalesce(database.datacl, acldefault('d', database.datdba))) privilege
    WHERE database.datname = current_database() AND privilege.grantee = 0 AND privilege.privilege_type = 'CREATE'
  ) OR EXISTS (
    SELECT 1 FROM pg_namespace schema, aclexplode(coalesce(schema.nspacl, acldefault('n', schema.nspowner))) privilege
    WHERE schema.nspname !~ '^pg_' AND schema.nspname <> 'information_schema' AND privilege.grantee = 0 AND privilege.privilege_type = 'CREATE'
  ) THEN
    RAISE EXCEPTION 'refusing to rotate punaro_app while PUBLIC retains CREATE; revoke it and rerun bootstrap';
  END IF;
END $$;
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_shdepend dependency
    JOIN pg_roles role ON role.oid = dependency.refobjid
    WHERE dependency.refclassid = 'pg_authid'::regclass
      AND dependency.deptype = 'o'
      AND role.rolname = 'punaro_app'
      AND dependency.dbid <> (SELECT oid FROM pg_database WHERE datname = current_database())
  ) THEN
    RAISE EXCEPTION 'refusing to rotate punaro_app while it owns objects outside the punaro database; repair them and rerun bootstrap';
  END IF;
END $$;
SELECT 'CREATE ROLE punaro_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'punaro_app')
\gexec
DO $$
DECLARE object record;
BEGIN
  FOR object IN
    SELECT namespace.nspname, relation.relname, relation.relkind
    FROM pg_class relation
    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
    WHERE relation.relowner = (SELECT oid FROM pg_roles WHERE rolname = 'punaro_app')
      AND relation.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
  LOOP
    IF object.relkind = 'S' THEN
      EXECUTE format('REVOKE ALL PRIVILEGES ON SEQUENCE %I.%I FROM punaro_app', object.nspname, object.relname);
    ELSE
      EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE %I.%I FROM punaro_app', object.nspname, object.relname);
    END IF;
  END LOOP;
  FOR object IN
    SELECT namespace.nspname, procedure.proname, pg_get_function_identity_arguments(procedure.oid) AS arguments, procedure.prokind
    FROM pg_proc procedure
    JOIN pg_namespace namespace ON namespace.oid = procedure.pronamespace
    WHERE procedure.proowner = (SELECT oid FROM pg_roles WHERE rolname = 'punaro_app')
  LOOP
    IF object.prokind = 'p' THEN
      EXECUTE format('REVOKE ALL PRIVILEGES ON PROCEDURE %I.%I(%s) FROM punaro_app', object.nspname, object.proname, object.arguments);
    ELSE
      EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION %I.%I(%s) FROM punaro_app', object.nspname, object.proname, object.arguments);
    END IF;
  END LOOP;
  FOR object IN
    SELECT nspname FROM pg_namespace WHERE nspowner = (SELECT oid FROM pg_roles WHERE rolname = 'punaro_app')
  LOOP
    EXECUTE format('REVOKE ALL PRIVILEGES ON SCHEMA %I FROM punaro_app', object.nspname);
  END LOOP;
END $$;
REASSIGN OWNED BY punaro_app TO punaro_owner;
ALTER ROLE punaro_app NOLOGIN;
COMMIT;
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE usename = 'punaro_app' AND pid <> pg_backend_pid();
BEGIN;
ALTER ROLE punaro_app LOGIN PASSWORD :'app_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1 VALID UNTIL 'infinity';
ALTER ROLE punaro_app RESET ALL;
ALTER ROLE punaro_app IN DATABASE punaro RESET ALL;
DO $$
DECLARE membership record;
BEGIN
  FOR membership IN SELECT parent.rolname FROM pg_auth_members members JOIN pg_roles parent ON parent.oid = members.roleid JOIN pg_roles member ON member.oid = members.member WHERE member.rolname = 'punaro_app' LOOP
    EXECUTE format('REVOKE %I FROM punaro_app', membership.rolname);
  END LOOP;
END $$;
DO $$
DECLARE member_name record;
BEGIN
  FOR member_name IN SELECT member.rolname FROM pg_auth_members members JOIN pg_roles parent ON parent.oid = members.roleid JOIN pg_roles member ON member.oid = members.member WHERE parent.rolname = 'punaro_app' LOOP
    EXECUTE format('REVOKE punaro_app FROM %I', member_name.rolname);
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
