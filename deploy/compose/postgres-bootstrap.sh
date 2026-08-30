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
    SELECT 1
    FROM pg_database database
    WHERE database.datname = current_database()
      AND database.datdba <> (SELECT oid FROM pg_roles WHERE rolname = 'punaro_owner')
  ) OR EXISTS (
    SELECT 1
    FROM pg_database database
    CROSS JOIN LATERAL aclexplode(coalesce(database.datacl, acldefault('d', database.datdba))) privilege
    WHERE database.datname = current_database()
      AND privilege.privilege_type = 'CREATE'
      AND privilege.grantee <> database.datdba
  ) OR EXISTS (
    SELECT 1 FROM pg_namespace schema, aclexplode(coalesce(schema.nspacl, acldefault('n', schema.nspowner))) privilege
    WHERE schema.nspname !~ '^pg_' AND schema.nspname <> 'information_schema' AND privilege.grantee = 0 AND privilege.privilege_type = 'CREATE'
  ) THEN
    RAISE EXCEPTION 'refusing to rotate punaro_app while the database has an unexpected owner or non-owner CREATE grant; repair it and rerun bootstrap';
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
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_roles
    WHERE rolname = 'punaro_app'
      AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls)
  ) THEN
    RAISE EXCEPTION 'refusing to rotate elevated punaro_app role attributes; repair them and rerun bootstrap';
  END IF;
END $$;
SELECT 'CREATE ROLE punaro_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'punaro_app')
\gexec
CREATE TEMPORARY TABLE punaro_app_member_sessions (role_name name PRIMARY KEY) ON COMMIT PRESERVE ROWS;
INSERT INTO punaro_app_member_sessions (role_name)
WITH RECURSIVE app_members(role_oid) AS (
  SELECT members.member
  FROM pg_auth_members members
  JOIN pg_roles parent ON parent.oid = members.roleid
  WHERE parent.rolname = 'punaro_app'
  UNION
  SELECT members.member
  FROM pg_auth_members members
  JOIN app_members ON app_members.role_oid = members.roleid
)
SELECT member.rolname
FROM app_members
JOIN pg_roles member ON member.oid = app_members.role_oid;
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_default_acl default_acl
    CROSS JOIN LATERAL aclexplode(coalesce(default_acl.defaclacl, acldefault(CASE default_acl.defaclobjtype WHEN 'S' THEN 'S'::"char" WHEN 'f' THEN 'f'::"char" WHEN 'n' THEN 'n'::"char" ELSE 'r'::"char" END, default_acl.defaclrole))) privilege
    WHERE privilege.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'punaro_app')
       OR (privilege.grantee = 0 AND default_acl.defaclobjtype IN ('r', 'S', 'f'))
  ) THEN
    RAISE EXCEPTION 'refusing to rotate punaro_app while default privileges grant it access or PUBLIC table, sequence, or function default privileges remain; revoke them and rerun bootstrap';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_default_acl default_acl
    CROSS JOIN LATERAL aclexplode(coalesce(default_acl.defaclacl, acldefault(CASE default_acl.defaclobjtype WHEN 'S' THEN 'S'::"char" WHEN 'f' THEN 'f'::"char" WHEN 'n' THEN 'n'::"char" ELSE 'r'::"char" END, default_acl.defaclrole))) privilege
    WHERE default_acl.defaclobjtype IN ('r', 'S', 'f', 'n')
      AND privilege.grantee NOT IN (0, default_acl.defaclrole, (SELECT oid FROM pg_roles WHERE rolname = 'punaro_app'))
  ) THEN
    RAISE EXCEPTION 'refusing to rotate punaro_app while table, sequence, function, or schema default privileges grant a third-party role access; revoke them and rerun bootstrap';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_class relation JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
    CROSS JOIN LATERAL aclexplode(coalesce(relation.relacl, acldefault(CASE WHEN relation.relkind = 'S' THEN 'S'::"char" ELSE 'r'::"char" END, relation.relowner))) privilege
    WHERE privilege.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'punaro_app')
      AND namespace.nspname NOT IN ('auth', 'relay', 'attachment', 'brain', 'audit', 'jobs', 'fleet', 'public')
  ) THEN
    RAISE EXCEPTION 'refusing to rotate punaro_app while it retains object grants outside Punaro schemas; revoke them and rerun bootstrap';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_class relation JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
    CROSS JOIN LATERAL aclexplode(coalesce(relation.relacl, acldefault(CASE WHEN relation.relkind = 'S' THEN 'S'::"char" ELSE 'r'::"char" END, relation.relowner))) privilege
    WHERE relation.relowner = (SELECT oid FROM pg_roles WHERE rolname = 'punaro_owner')
      AND namespace.nspname NOT IN ('auth', 'relay', 'attachment', 'brain', 'audit', 'jobs', 'fleet', 'public')
      AND namespace.nspname !~ '^pg_'
      AND namespace.nspname <> 'information_schema'
      AND relation.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
      AND privilege.grantee = 0
  ) THEN
    RAISE EXCEPTION 'refusing to rotate punaro_app while an owner relation outside Punaro schemas grants PUBLIC access; revoke it and rerun bootstrap';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_class relation JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
    CROSS JOIN LATERAL aclexplode(coalesce(relation.relacl, acldefault(CASE WHEN relation.relkind = 'S' THEN 'S'::"char" ELSE 'r'::"char" END, relation.relowner))) privilege
    WHERE relation.relowner = (SELECT oid FROM pg_roles WHERE rolname = 'punaro_owner')
      AND namespace.nspname IN ('auth', 'relay', 'attachment', 'brain', 'audit', 'jobs', 'fleet', 'public')
      AND privilege.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'punaro_app')
      AND (privilege.is_grantable OR (relation.relkind = 'S' AND privilege.privilege_type NOT IN ('USAGE', 'SELECT')) OR (relation.relkind <> 'S' AND privilege.privilege_type NOT IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE')))
  ) THEN
    RAISE EXCEPTION 'refusing to rotate punaro_app while it retains an unexpected grant on a Punaro relation; revoke it and rerun bootstrap';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_attribute attribute JOIN pg_class relation ON relation.oid = attribute.attrelid
    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
    CROSS JOIN LATERAL aclexplode(coalesce(attribute.attacl, acldefault('c'::"char", relation.relowner))) privilege
    WHERE attribute.attnum > 0 AND NOT attribute.attisdropped
      AND privilege.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'punaro_app')
      AND namespace.nspname NOT IN ('auth', 'relay', 'attachment', 'brain', 'audit', 'jobs', 'fleet', 'public')
  ) THEN
    RAISE EXCEPTION 'refusing to rotate punaro_app while it retains column grants outside Punaro schemas; revoke them and rerun bootstrap';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_attribute attribute JOIN pg_class relation ON relation.oid = attribute.attrelid
    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
    CROSS JOIN LATERAL aclexplode(coalesce(attribute.attacl, acldefault('c'::"char", relation.relowner))) privilege
    WHERE attribute.attnum > 0 AND NOT attribute.attisdropped
      AND relation.relowner = (SELECT oid FROM pg_roles WHERE rolname = 'punaro_owner')
      AND namespace.nspname IN ('auth', 'relay', 'attachment', 'brain', 'audit', 'jobs', 'fleet', 'public')
      AND privilege.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'punaro_app')
      AND (privilege.is_grantable OR privilege.privilege_type NOT IN ('SELECT', 'INSERT', 'UPDATE'))
  ) THEN
    RAISE EXCEPTION 'refusing to rotate punaro_app while it retains an unexpected column grant on a Punaro relation; revoke it and rerun bootstrap';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_class relation JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname IN ('auth', 'relay', 'attachment', 'brain', 'audit', 'jobs', 'fleet', 'public')
      AND relation.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
      AND relation.relowner NOT IN ((SELECT oid FROM pg_roles WHERE rolname = 'punaro_owner'), (SELECT oid FROM pg_roles WHERE rolname = 'punaro_app'))
  ) THEN
    RAISE EXCEPTION 'refusing to rotate punaro_app while a Punaro relation has an unexpected owner; repair ownership and rerun bootstrap';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid = procedure.pronamespace
    WHERE namespace.nspname IN ('auth', 'relay', 'attachment', 'brain', 'audit', 'jobs', 'fleet', 'public')
      AND procedure.proowner NOT IN ((SELECT oid FROM pg_roles WHERE rolname = 'punaro_owner'), (SELECT oid FROM pg_roles WHERE rolname = 'punaro_app'))
  ) THEN
    RAISE EXCEPTION 'refusing to rotate punaro_app while a Punaro routine has an unexpected owner; repair ownership and rerun bootstrap';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_trigger trigger
    JOIN pg_proc procedure ON procedure.oid = trigger.tgfoid
    WHERE NOT trigger.tgisinternal
      AND procedure.proowner = (SELECT oid FROM pg_roles WHERE rolname = 'punaro_app')
  ) THEN
    RAISE EXCEPTION 'refusing to rotate punaro_app while an application-owned trigger function remains; remove the trigger and rerun bootstrap';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_depend dependency
    JOIN pg_proc procedure ON procedure.oid = dependency.refobjid
    WHERE dependency.refclassid = 'pg_proc'::regclass
      AND dependency.classid IN ('pg_constraint'::regclass, 'pg_attrdef'::regclass, 'pg_class'::regclass, 'pg_policy'::regclass)
      AND procedure.proowner = (SELECT oid FROM pg_roles WHERE rolname = 'punaro_app')
  ) THEN
    RAISE EXCEPTION 'refusing to rotate punaro_app while a stored expression references an application-owned function; remove the dependency and rerun bootstrap';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_event_trigger trigger
    JOIN pg_proc procedure ON procedure.oid = trigger.evtfoid
    WHERE trigger.evtowner = (SELECT oid FROM pg_roles WHERE rolname = 'punaro_app')
       OR procedure.proowner = (SELECT oid FROM pg_roles WHERE rolname = 'punaro_app')
  ) THEN
    RAISE EXCEPTION 'refusing to rotate punaro_app while an application-owned event trigger remains; remove the trigger and rerun bootstrap';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_namespace namespace
    CROSS JOIN LATERAL aclexplode(coalesce(namespace.nspacl, acldefault('n'::"char", namespace.nspowner))) privilege
    WHERE namespace.nspowner = (SELECT oid FROM pg_roles WHERE rolname = 'punaro_owner')
      AND namespace.nspname IN ('auth', 'relay', 'attachment', 'brain', 'audit', 'jobs', 'fleet', 'public')
      AND privilege.grantee NOT IN (namespace.nspowner, (SELECT oid FROM pg_roles WHERE rolname = 'punaro_app'))
  ) THEN
    RAISE EXCEPTION 'refusing to rotate punaro_app while an owner Punaro schema grants a third-party role access; revoke it and rerun bootstrap';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_largeobject_metadata large_object
    CROSS JOIN LATERAL aclexplode(large_object.lomacl) privilege
    WHERE large_object.lomacl IS NOT NULL
      AND large_object.lomowner = (SELECT oid FROM pg_roles WHERE rolname = 'punaro_app')
      AND privilege.grantee <> large_object.lomowner
  ) THEN
    RAISE EXCEPTION 'refusing to rotate punaro_app while its large objects retain non-owner grants; revoke them and rerun bootstrap';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_largeobject_metadata large_object
    CROSS JOIN LATERAL aclexplode(large_object.lomacl) privilege
    WHERE large_object.lomacl IS NOT NULL
      AND large_object.lomowner = (SELECT oid FROM pg_roles WHERE rolname = 'punaro_owner')
      AND privilege.grantee <> large_object.lomowner
  ) THEN
    RAISE EXCEPTION 'refusing to rotate punaro_app while owner large objects retain non-owner grants; revoke them and rerun bootstrap';
  END IF;
END $$;
DO $$
BEGIN
  IF EXISTS (
    WITH RECURSIVE owner_members(role_oid) AS (
      SELECT members.member
      FROM pg_auth_members members
      WHERE members.roleid = (SELECT oid FROM pg_roles WHERE rolname = 'punaro_owner')
      UNION
      SELECT members.member
      FROM pg_auth_members members
      JOIN owner_members ON owner_members.role_oid = members.roleid
    )
    SELECT 1 FROM owner_members
  ) THEN
    RAISE EXCEPTION 'refusing to rotate punaro_app while another role inherits punaro_owner; revoke the membership and rerun bootstrap';
  END IF;
END $$;
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
ALTER ROLE punaro_app NOLOGIN;
REVOKE CREATE ON DATABASE punaro FROM punaro_app;
DO $$
DECLARE schema_name record;
BEGIN
  FOR schema_name IN SELECT nspname FROM pg_namespace WHERE has_schema_privilege('punaro_app', oid, 'CREATE') LOOP
    EXECUTE format('REVOKE CREATE ON SCHEMA %I FROM punaro_app', schema_name.nspname);
  END LOOP;
  FOR schema_name IN
    SELECT nspname
    FROM pg_namespace
    WHERE nspname NOT IN ('auth', 'relay', 'attachment', 'brain', 'audit', 'jobs', 'fleet', 'public', 'information_schema')
      AND nspname !~ '^pg_'
      AND has_schema_privilege('punaro_app', oid, 'USAGE')
  LOOP
    EXECUTE format('REVOKE USAGE ON SCHEMA %I FROM punaro_app', schema_name.nspname);
  END LOOP;
END $$;
COMMIT;
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE (usename = 'punaro_app' OR usename IN (SELECT role_name FROM punaro_app_member_sessions))
  AND pid <> pg_backend_pid();
BEGIN;
DO $$
DECLARE object record;
DECLARE grant_role record;
BEGIN
  FOR object IN
    SELECT namespace.nspname, relation.relname, relation.relkind, relation.relacl, relation.relowner
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
    IF object.relkind = 'S' THEN
      EXECUTE format('REVOKE ALL PRIVILEGES ON SEQUENCE %I.%I FROM PUBLIC', object.nspname, object.relname);
    ELSE
      EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE %I.%I FROM PUBLIC', object.nspname, object.relname);
    END IF;
    FOR grant_role IN
      SELECT role.rolname
      FROM aclexplode(coalesce(object.relacl, acldefault(CASE WHEN object.relkind = 'S' THEN 'S'::"char" ELSE 'r'::"char" END, object.relowner))) privilege
      JOIN pg_roles role ON role.oid = privilege.grantee
      WHERE privilege.grantee <> object.relowner AND privilege.grantee <> 0
    LOOP
      IF object.relkind = 'S' THEN
        EXECUTE format('REVOKE ALL PRIVILEGES ON SEQUENCE %I.%I FROM %I', object.nspname, object.relname, grant_role.rolname);
      ELSE
        EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE %I.%I FROM %I', object.nspname, object.relname, grant_role.rolname);
      END IF;
    END LOOP;
  END LOOP;
  FOR object IN
    SELECT namespace.nspname, relation.relname, relation.relkind, relation.relacl, relation.relowner
    FROM pg_class relation JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
    WHERE relation.relowner = (SELECT oid FROM pg_roles WHERE rolname = 'punaro_owner')
      AND namespace.nspname IN ('auth', 'relay', 'attachment', 'brain', 'audit', 'jobs', 'fleet', 'public')
      AND relation.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
  LOOP
    IF object.relkind = 'S' THEN EXECUTE format('REVOKE ALL PRIVILEGES ON SEQUENCE %I.%I FROM PUBLIC', object.nspname, object.relname);
    ELSE EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE %I.%I FROM PUBLIC', object.nspname, object.relname);
    END IF;
    FOR grant_role IN
      SELECT role.rolname FROM aclexplode(coalesce(object.relacl, acldefault(CASE WHEN object.relkind = 'S' THEN 'S'::"char" ELSE 'r'::"char" END, object.relowner))) privilege JOIN pg_roles role ON role.oid = privilege.grantee
      WHERE privilege.grantee NOT IN (0, object.relowner, (SELECT oid FROM pg_roles WHERE rolname = 'punaro_app'))
    LOOP
      IF object.relkind = 'S' THEN EXECUTE format('REVOKE ALL PRIVILEGES ON SEQUENCE %I.%I FROM %I', object.nspname, object.relname, grant_role.rolname);
      ELSE EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE %I.%I FROM %I', object.nspname, object.relname, grant_role.rolname);
      END IF;
    END LOOP;
  END LOOP;
  FOR object IN
    SELECT namespace.nspname, relation.relname, attribute.attname, attribute.attacl, relation.relowner
    FROM pg_attribute attribute JOIN pg_class relation ON relation.oid = attribute.attrelid JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
    WHERE relation.relowner = (SELECT oid FROM pg_roles WHERE rolname = 'punaro_owner')
      AND namespace.nspname IN ('auth', 'relay', 'attachment', 'brain', 'audit', 'jobs', 'fleet', 'public')
      AND attribute.attnum > 0 AND NOT attribute.attisdropped AND attribute.attacl IS NOT NULL
  LOOP
    EXECUTE format('REVOKE ALL PRIVILEGES (%I) ON TABLE %I.%I FROM PUBLIC', object.attname, object.nspname, object.relname);
    FOR grant_role IN SELECT role.rolname FROM aclexplode(object.attacl) privilege JOIN pg_roles role ON role.oid = privilege.grantee
      WHERE privilege.grantee NOT IN (0, object.relowner, (SELECT oid FROM pg_roles WHERE rolname = 'punaro_app'))
    LOOP
      EXECUTE format('REVOKE ALL PRIVILEGES (%I) ON TABLE %I.%I FROM %I', object.attname, object.nspname, object.relname, grant_role.rolname);
    END LOOP;
  END LOOP;
  FOR object IN
    SELECT namespace.nspname, procedure.proname, pg_get_function_identity_arguments(procedure.oid) AS arguments, procedure.prokind, procedure.proacl, procedure.proowner
    FROM pg_proc procedure JOIN pg_namespace namespace ON namespace.oid = procedure.pronamespace
    WHERE procedure.proowner = (SELECT oid FROM pg_roles WHERE rolname = 'punaro_owner')
      AND namespace.nspname IN ('auth', 'relay', 'attachment', 'brain', 'audit', 'jobs', 'fleet', 'public')
      AND NOT EXISTS (
        SELECT 1 FROM pg_depend dependency
        WHERE dependency.classid = 'pg_proc'::regclass
          AND dependency.objid = procedure.oid
          AND dependency.refclassid = 'pg_extension'::regclass
          AND dependency.deptype = 'e'
      )
  LOOP
    IF object.prokind = 'p' THEN
      EXECUTE format('REVOKE ALL PRIVILEGES ON PROCEDURE %I.%I(%s) FROM PUBLIC', object.nspname, object.proname, object.arguments);
    ELSE
      EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION %I.%I(%s) FROM PUBLIC', object.nspname, object.proname, object.arguments);
    END IF;
    FOR grant_role IN
      SELECT role.rolname FROM aclexplode(coalesce(object.proacl, acldefault('f'::"char", object.proowner))) privilege JOIN pg_roles role ON role.oid = privilege.grantee
      WHERE privilege.grantee NOT IN (0, object.proowner, (SELECT oid FROM pg_roles WHERE rolname = 'punaro_app'))
    LOOP
      IF object.prokind = 'p' THEN
        EXECUTE format('REVOKE ALL PRIVILEGES ON PROCEDURE %I.%I(%s) FROM %I', object.nspname, object.proname, object.arguments, grant_role.rolname);
      ELSE
        EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION %I.%I(%s) FROM %I', object.nspname, object.proname, object.arguments, grant_role.rolname);
      END IF;
    END LOOP;
  END LOOP;
  FOR object IN
    SELECT namespace.nspname, relation.relname, attribute.attname, attribute.attacl, relation.relowner
    FROM pg_attribute attribute
    JOIN pg_class relation ON relation.oid = attribute.attrelid
    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
    WHERE relation.relowner = (SELECT oid FROM pg_roles WHERE rolname = 'punaro_app')
      AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
      AND attribute.attnum > 0 AND NOT attribute.attisdropped AND attribute.attacl IS NOT NULL
  LOOP
    EXECUTE format('REVOKE ALL PRIVILEGES (%I) ON TABLE %I.%I FROM PUBLIC', object.attname, object.nspname, object.relname);
    FOR grant_role IN
      SELECT role.rolname FROM aclexplode(object.attacl) privilege JOIN pg_roles role ON role.oid = privilege.grantee
      WHERE privilege.grantee <> object.relowner AND privilege.grantee <> 0
    LOOP
      EXECUTE format('REVOKE ALL PRIVILEGES (%I) ON TABLE %I.%I FROM %I', object.attname, object.nspname, object.relname, grant_role.rolname);
    END LOOP;
  END LOOP;
  FOR object IN
    SELECT namespace.nspname, procedure.proname, pg_get_function_identity_arguments(procedure.oid) AS arguments, procedure.prokind, procedure.proacl, procedure.proowner
    FROM pg_proc procedure
    JOIN pg_namespace namespace ON namespace.oid = procedure.pronamespace
    WHERE procedure.proowner = (SELECT oid FROM pg_roles WHERE rolname = 'punaro_app')
  LOOP
    IF object.prokind = 'p' THEN
      EXECUTE format('REVOKE ALL PRIVILEGES ON PROCEDURE %I.%I(%s) FROM punaro_app', object.nspname, object.proname, object.arguments);
      EXECUTE format('REVOKE ALL PRIVILEGES ON PROCEDURE %I.%I(%s) FROM PUBLIC', object.nspname, object.proname, object.arguments);
    ELSE
      EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION %I.%I(%s) FROM punaro_app', object.nspname, object.proname, object.arguments);
      EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION %I.%I(%s) FROM PUBLIC', object.nspname, object.proname, object.arguments);
    END IF;
    FOR grant_role IN
      SELECT role.rolname
      FROM aclexplode(coalesce(object.proacl, acldefault('f'::"char", object.proowner))) privilege
      JOIN pg_roles role ON role.oid = privilege.grantee
      WHERE privilege.grantee <> object.proowner AND privilege.grantee <> 0
    LOOP
      IF object.prokind = 'p' THEN
        EXECUTE format('REVOKE ALL PRIVILEGES ON PROCEDURE %I.%I(%s) FROM %I', object.nspname, object.proname, object.arguments, grant_role.rolname);
      ELSE
        EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION %I.%I(%s) FROM %I', object.nspname, object.proname, object.arguments, grant_role.rolname);
      END IF;
    END LOOP;
  END LOOP;
  FOR object IN
    SELECT nspname, nspacl, nspowner FROM pg_namespace WHERE nspowner = (SELECT oid FROM pg_roles WHERE rolname = 'punaro_app')
  LOOP
    EXECUTE format('REVOKE ALL PRIVILEGES ON SCHEMA %I FROM punaro_app', object.nspname);
    EXECUTE format('REVOKE ALL PRIVILEGES ON SCHEMA %I FROM PUBLIC', object.nspname);
    FOR grant_role IN
      SELECT role.rolname FROM aclexplode(coalesce(object.nspacl, acldefault('n'::"char", object.nspowner))) privilege JOIN pg_roles role ON role.oid = privilege.grantee
      WHERE privilege.grantee <> object.nspowner AND privilege.grantee <> 0
    LOOP
      EXECUTE format('REVOKE ALL PRIVILEGES ON SCHEMA %I FROM %I', object.nspname, grant_role.rolname);
    END LOOP;
  END LOOP;
END $$;
REASSIGN OWNED BY punaro_app TO punaro_owner;
COMMIT;
BEGIN;
ALTER ROLE punaro_app LOGIN PASSWORD :'app_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1 VALID UNTIL 'infinity';
ALTER ROLE punaro_app RESET ALL;
ALTER ROLE punaro_app IN DATABASE punaro RESET ALL;
DO $$
DECLARE parameter_name record;
BEGIN
  IF to_regclass('pg_catalog.pg_parameter_acl') IS NOT NULL THEN
    FOR parameter_name IN EXECUTE $query$
      SELECT parameter_acl.parname, privilege.grantee
      FROM pg_parameter_acl parameter_acl
      CROSS JOIN LATERAL aclexplode(parameter_acl.paracl) privilege
      WHERE privilege.grantee IN (0, (SELECT oid FROM pg_roles WHERE rolname = 'punaro_app'))
    $query$ LOOP
      IF parameter_name.grantee = 0 THEN
        EXECUTE format('REVOKE ALL PRIVILEGES ON PARAMETER %I FROM PUBLIC', parameter_name.parname);
      ELSE
        EXECUTE format('REVOKE ALL PRIVILEGES ON PARAMETER %I FROM punaro_app', parameter_name.parname);
      END IF;
    END LOOP;
  END IF;
END $$;
REVOKE TEMPORARY ON DATABASE punaro FROM PUBLIC;
REVOKE TEMPORARY ON DATABASE punaro FROM punaro_app;
GRANT CONNECT ON DATABASE punaro TO punaro_app;
COMMIT;
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE usename = 'punaro_app' AND pid <> pg_backend_pid();
BEGIN;
REASSIGN OWNED BY punaro_app TO punaro_owner;
COMMIT;
SQL
