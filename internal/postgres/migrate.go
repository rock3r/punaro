package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"io/fs"
	"sort"
	"strconv"
	"strings"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

const advisoryLockKey int64 = 0x50554e41524f4d31 // "PUNAROM1"

var migrationCompatibilityFloors = map[int64]int64{
	1: 1,
	2: 2,
	3: 3,
	4: 4,
	5: 5,
}

// CurrentManifest returns the immutable migrations embedded in this binary.
func CurrentManifest() Manifest {
	entries, err := fs.Glob(migrationFiles, "migrations/*.sql")
	if err != nil {
		panic("invalid embedded PostgreSQL migrations")
	}
	sort.Strings(entries)
	migrations := make([]Migration, 0, len(entries))
	for i, path := range entries {
		body, err := migrationFiles.ReadFile(path)
		if err != nil {
			panic("invalid embedded PostgreSQL migration")
		}
		sum := sha256.Sum256(body)
		name := strings.TrimSuffix(strings.TrimPrefix(path, "migrations/"), ".sql")
		if len(name) < 4 || name[3] != '_' {
			panic("invalid embedded PostgreSQL migration name")
		}
		version, err := strconv.ParseInt(name[:3], 10, 64)
		if err != nil || version != int64(i+1) {
			panic("non-contiguous embedded PostgreSQL migrations")
		}
		floor, ok := migrationCompatibilityFloors[version]
		if !ok {
			panic("missing PostgreSQL migration compatibility floor")
		}
		migrations = append(migrations, Migration{Version: version, Name: name, Checksum: hex.EncodeToString(sum[:]), CompatibilityFloor: floor, SQL: string(body)})
	}
	manifest := Manifest{MinSupported: migrations[len(migrations)-1].CompatibilityFloor, MaxSupported: int64(len(migrations)), Migrations: migrations}
	if err := manifest.Validate(); err != nil {
		panic(err)
	}
	return manifest
}

// Migrate applies pending migrations through the dedicated schema-owner role.
func Migrate(ctx context.Context, cfg Config) (SchemaState, error) {
	dsn, err := ReadDSNFile(cfg.DSNFile)
	if err != nil {
		return SchemaState{}, err
	}
	db, err := open(ctx, dsn)
	if err != nil {
		return SchemaState{}, err
	}
	defer func() { _ = db.Close() }()
	return migrate(ctx, db, CurrentManifest())
}

func migrate(ctx context.Context, db *sql.DB, manifest Manifest) (SchemaState, error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return SchemaState{}, errors.New("PostgreSQL migration connection is unavailable")
	}
	defer func() { _ = conn.Close() }()
	return migrateConn(ctx, conn, manifest)
}

func migrateConn(ctx context.Context, conn *sql.Conn, manifest Manifest) (SchemaState, error) {
	if err := manifest.Validate(); err != nil {
		return SchemaState{}, err
	}
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, advisoryLockKey); err != nil {
		return SchemaState{}, errors.New("PostgreSQL migration lock is unavailable")
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), operationTimeout)
		defer cancel()
		_, _ = conn.ExecContext(unlockCtx, `SELECT pg_advisory_unlock($1)`, advisoryLockKey)
	}()
	if err := verifyMigrationRoles(ctx, conn); err != nil {
		return SchemaState{}, err
	}

	snapshot, err := inspect(ctx, conn)
	if err != nil {
		return SchemaState{}, err
	}
	state := Classify(snapshot, manifest)
	if state.Classification == Compatible {
		return state, nil
	}
	if state.Classification != Pristine && state.Classification != UpgradeRequired {
		return state, contentFreeMigrationError(state.Classification)
	}
	if state.Classification == Pristine {
		if err := bootstrapTracker(ctx, conn, manifest.Migrations[0]); err != nil {
			return SchemaState{}, err
		}
		state.Version = 0
	}
	for _, migration := range manifest.Migrations[state.Version:] {
		if migration.Version != 1 {
			if _, err := conn.ExecContext(ctx, `INSERT INTO jobs.schema_migrations (version, name, checksum, compatibility_floor, status) VALUES ($1, $2, $3, $4, 'applying')`, migration.Version, migration.Name, migration.Checksum, migration.CompatibilityFloor); err != nil {
				return SchemaState{}, errors.New("PostgreSQL migration could not be staged")
			}
		}
		if err := applyMigration(ctx, conn, migration); err != nil {
			return SchemaState{}, err
		}
	}
	finalSnapshot, err := inspect(ctx, conn)
	if err != nil {
		return SchemaState{}, err
	}
	final := Classify(finalSnapshot, manifest)
	if final.Classification != Compatible {
		return final, contentFreeMigrationError(final.Classification)
	}
	return final, nil
}

func verifyMigrationRoles(ctx context.Context, conn *sql.Conn) error {
	return verifyMigrationRolesNamed(ctx, conn, "punaro_app")
}

func verifyMigrationRolesNamed(ctx context.Context, conn *sql.Conn, appRole string) error {
	var appExists, appUnsafe, ownerCanCreate bool
	if err := conn.QueryRowContext(ctx, `
SELECT
    EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1),
    EXISTS (
        SELECT 1 FROM pg_roles AS app
        WHERE app.rolname = $1
          AND (app.rolsuper OR app.rolcreatedb OR app.rolcreaterole OR app.rolreplication OR app.rolbypassrls OR app.rolinherit OR NOT app.rolcanlogin
               OR has_database_privilege(app.rolname, current_database(), 'CREATE')
               OR has_schema_privilege(app.rolname, 'public', 'CREATE')
               OR EXISTS (
                   SELECT 1 FROM pg_shdepend
                   WHERE refclassid = 'pg_authid'::regclass AND refobjid = app.oid AND deptype = 'o'
               )
               OR EXISTS (
                   SELECT 1 FROM pg_namespace
                   WHERE nspname !~ '^pg_' AND nspname <> 'information_schema'
                     AND has_schema_privilege(app.rolname, oid, 'CREATE')
               )
               OR EXISTS (
                   SELECT 1 FROM pg_roles AS assumable
                   WHERE assumable.rolname <> $1
                     AND pg_has_role($1, assumable.oid, 'MEMBER')
               )
               OR EXISTS (
                   SELECT 1 FROM pg_namespace
                   WHERE nspname !~ '^pg_' AND nspname <> 'information_schema' AND nspowner = app.oid
               )
               OR EXISTS (
                   SELECT 1 FROM pg_class AS object
                   JOIN pg_namespace AS namespace ON namespace.oid = object.relnamespace
                   WHERE namespace.nspname !~ '^pg_' AND namespace.nspname <> 'information_schema' AND object.relowner = app.oid
               )
               OR EXISTS (
                   SELECT 1 FROM pg_proc AS object
                   JOIN pg_namespace AS namespace ON namespace.oid = object.pronamespace
                   WHERE namespace.nspname !~ '^pg_' AND namespace.nspname <> 'information_schema' AND object.proowner = app.oid
               ))
    ),
    session_user = current_user AND current_user = 'punaro_owner' AND has_database_privilege(current_user, current_database(), 'CREATE')`, appRole).Scan(&appExists, &appUnsafe, &ownerCanCreate); err != nil {
		return errors.New("PostgreSQL migration roles cannot be verified")
	}
	if !appExists || appUnsafe || !ownerCanCreate {
		return errors.New("PostgreSQL migration requires separate safe owner and application roles")
	}
	return nil
}

func bootstrapTracker(ctx context.Context, conn *sql.Conn, first Migration) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("PostgreSQL migration bootstrap could not start")
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `CREATE SCHEMA jobs`); err != nil {
		return errors.New("PostgreSQL migration bootstrap failed")
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE jobs.schema_migrations (
    version bigint PRIMARY KEY,
    name text NOT NULL,
    checksum char(64) NOT NULL,
    compatibility_floor bigint NOT NULL,
    status text NOT NULL CHECK (status IN ('applying', 'applied')),
    started_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    applied_at timestamptz
);`); err != nil {
		return errors.New("PostgreSQL migration bootstrap failed")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO jobs.schema_migrations (version, name, checksum, compatibility_floor, status)
VALUES ($1, $2, $3, $4, 'applying')`, first.Version, first.Name, first.Checksum, first.CompatibilityFloor); err != nil {
		return errors.New("PostgreSQL migration bootstrap failed")
	}
	if err := tx.Commit(); err != nil {
		return errors.New("PostgreSQL migration bootstrap could not commit")
	}
	return nil
}

func applyMigration(ctx context.Context, conn *sql.Conn, migration Migration) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("PostgreSQL migration transaction could not start")
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, migration.SQL); err != nil {
		return errors.New("PostgreSQL migration failed")
	}
	result, err := tx.ExecContext(ctx, `UPDATE jobs.schema_migrations SET status = 'applied', applied_at = statement_timestamp() WHERE version = $1 AND status = 'applying'`, migration.Version)
	if err != nil {
		return errors.New("PostgreSQL migration could not be recorded")
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return errors.New("PostgreSQL migration history changed unexpectedly")
	}
	if err := tx.Commit(); err != nil {
		return errors.New("PostgreSQL migration transaction could not commit")
	}
	return nil
}
