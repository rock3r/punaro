package postgres

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestPostgresPlatformSubstrateIntegration(t *testing.T) {
	ownerDSN := os.Getenv("PUNARO_TEST_POSTGRES_OWNER_DSN")
	appDSN := os.Getenv("PUNARO_TEST_POSTGRES_APP_DSN")
	if ownerDSN == "" || appDSN == "" {
		t.Skip("set PUNARO_TEST_POSTGRES_OWNER_DSN and PUNARO_TEST_POSTGRES_APP_DSN to run PostgreSQL integration tests")
	}
	ctx := context.Background()
	ownerFile := writeTestDSN(t, "owner.dsn", ownerDSN)
	appFile := writeTestDSN(t, "app.dsn", appDSN)

	app, err := OpenApplication(ctx, Config{DSNFile: appFile})
	if err != nil {
		t.Fatal(err)
	}
	state, err := app.SchemaState(ctx)
	if err != nil || state.Classification != Pristine {
		t.Fatalf("initial state=%#v err=%v, want pristine", state, err)
	}
	if err := app.Ready(ctx); err == nil {
		t.Fatal("ordinary application readiness accepted a pristine schema")
	}
	if _, err := Migrate(ctx, Config{DSNFile: appFile}); err == nil {
		t.Fatal("application role was able to bootstrap the schema")
	}
	state, err = app.SchemaState(ctx)
	if err != nil || state.Classification != Pristine {
		t.Fatalf("application migrator attempt mutated state=%#v err=%v", state, err)
	}
	_ = app.Close()

	var wg sync.WaitGroup
	errorsSeen := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, migrateErr := Migrate(ctx, Config{DSNFile: ownerFile})
			errorsSeen <- migrateErr
		}()
	}
	wg.Wait()
	close(errorsSeen)
	for migrateErr := range errorsSeen {
		if migrateErr != nil {
			t.Fatalf("concurrent migration failed: %v", migrateErr)
		}
	}

	app, err = OpenApplication(ctx, Config{DSNFile: appFile})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()
	if err := app.Ready(ctx); err != nil {
		t.Fatalf("migrated application not ready: %v", err)
	}
	before, err := app.InstallationState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	first, err := app.AdvanceChange(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := app.AdvanceChange(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if first.InstallationID != before.InstallationID || first.TimelineID != before.TimelineID || second.ChangeSequence != first.ChangeSequence+1 {
		t.Fatalf("unstable IDs or non-monotonic sequence: before=%#v first=%#v second=%#v", before, first, second)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	app, err = OpenApplication(ctx, Config{DSNFile: appFile})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()
	afterRestart, err := app.InstallationState(ctx)
	if err != nil || afterRestart.InstallationID != before.InstallationID || afterRestart.TimelineID != before.TimelineID || afterRestart.ChangeSequence != second.ChangeSequence {
		t.Fatalf("metadata changed across application restart: after=%#v err=%v", afterRestart, err)
	}

	ownerDB, err := open(ctx, ownerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ownerDB.Close() }()
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `ALTER ROLE punaro_app SET default_transaction_read_only = on`); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenApplication(ctx, Config{DSNFile: appFile}); err == nil {
		t.Fatal("application startup accepted a default read-only session")
	}
	if _, err := ownerDB.ExecContext(ctx, `ALTER ROLE punaro_app RESET default_transaction_read_only`); err != nil {
		t.Fatal(err)
	}
	app, err = OpenApplication(ctx, Config{DSNFile: appFile})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()
	if _, err := ownerDB.ExecContext(ctx, `DROP SCHEMA audit`); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err == nil || !strings.Contains(err.Error(), string(Incompatible)) {
		t.Fatalf("readiness accepted missing required schema: %v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `CREATE SCHEMA audit`); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `ALTER TABLE jobs.server_state RENAME TO server_state_missing`); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err == nil || !strings.Contains(err.Error(), string(Incompatible)) {
		t.Fatalf("readiness accepted missing installation metadata: %v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `ALTER TABLE jobs.server_state_missing RENAME TO server_state`); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err != nil {
		t.Fatalf("readiness did not recover after required objects were restored: %v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `CREATE SCHEMA unsafe_extra; GRANT CREATE ON SCHEMA unsafe_extra TO punaro_app`); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err == nil {
		t.Fatal("application readiness accepted DDL authority on an extra persistent schema")
	}
	if _, err := ownerDB.ExecContext(ctx, `REVOKE CREATE ON SCHEMA unsafe_extra FROM punaro_app; DROP SCHEMA unsafe_extra`); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err != nil {
		t.Fatalf("readiness did not recover after extra-schema DDL was revoked: %v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `GRANT CREATE ON SCHEMA public TO punaro_app; CREATE TYPE public.unsafe_enum AS ENUM ('unsafe'); ALTER TYPE public.unsafe_enum OWNER TO punaro_app; REVOKE CREATE ON SCHEMA public FROM punaro_app`); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err == nil {
		t.Fatal("application readiness accepted ownership of a persistent type")
	}
	if _, err := ownerDB.ExecContext(ctx, `ALTER TYPE public.unsafe_enum OWNER TO punaro_owner; DROP TYPE public.unsafe_enum`); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err != nil {
		t.Fatalf("readiness did not recover after persistent-object ownership was removed: %v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `GRANT DELETE ON jobs.server_state TO punaro_app`); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err == nil {
		t.Fatal("application readiness accepted direct mutation privilege on installation metadata")
	}
	if _, err := ownerDB.ExecContext(ctx, `REVOKE DELETE ON jobs.server_state FROM punaro_app; GRANT UPDATE ON jobs.schema_migrations TO punaro_app`); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err == nil {
		t.Fatal("application readiness accepted direct mutation privilege on migration history")
	}
	if _, err := ownerDB.ExecContext(ctx, `REVOKE UPDATE ON jobs.schema_migrations FROM punaro_app`); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err != nil {
		t.Fatalf("readiness did not recover after metadata mutation privileges were revoked: %v", err)
	}
	ownerConn, err := ownerDB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ownerConn.ExecContext(ctx, `SET ROLE punaro_app`); err != nil {
		_ = ownerConn.Close()
		t.Fatal(err)
	}
	if err := verifyApplicationRole(ctx, ownerConn); err == nil {
		_, _ = ownerConn.ExecContext(ctx, `RESET ROLE`)
		_ = ownerConn.Close()
		t.Fatal("application verification accepted an owner session after SET ROLE")
	}
	if _, err := ownerConn.ExecContext(ctx, `RESET ROLE`); err != nil {
		_ = ownerConn.Close()
		t.Fatal(err)
	}
	if err := ownerConn.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `GRANT punaro_owner TO punaro_app`); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err == nil {
		t.Fatal("application readiness accepted membership in the schema-owner role")
	}
	if _, err := ownerDB.ExecContext(ctx, `REVOKE punaro_owner FROM punaro_app`); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err != nil {
		t.Fatalf("application did not recover after unsafe role membership was revoked: %v", err)
	}
	var count int
	if err := ownerDB.QueryRowContext(ctx, `SELECT count(*) FROM jobs.schema_migrations`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("migration rows=%d err=%v, want exactly one", count, err)
	}
	if _, err := ownerDB.ExecContext(ctx, `CREATE EXTENSION IF NOT EXISTS vector`); err != nil {
		t.Fatalf("pinned pgvector image cannot create vector extension: %v", err)
	}
	var vectorVersion string
	if err := ownerDB.QueryRowContext(ctx, `SELECT extversion FROM pg_extension WHERE extname='vector'`).Scan(&vectorVersion); err != nil || vectorVersion == "" {
		t.Fatalf("pgvector extension version=%q err=%v", vectorVersion, err)
	}
	if _, err := app.db.ExecContext(ctx, `CREATE TABLE jobs.forbidden_by_app(id bigint)`); err == nil {
		t.Fatal("application role received DDL authority")
	}
	if _, err := app.db.ExecContext(ctx, `UPDATE jobs.server_state SET change_sequence = 0 WHERE singleton`); err == nil {
		t.Fatal("application role can directly rewrite the monotonic change sequence")
	}

	if _, err := ownerDB.ExecContext(ctx, `UPDATE jobs.schema_migrations SET status='applying' WHERE version=1`); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err == nil || strings.Contains(err.Error(), ownerDSN) || strings.Contains(err.Error(), appDSN) {
		t.Fatalf("dirty readiness error=%v, want content-free refusal", err)
	}
	if _, err := Migrate(ctx, Config{DSNFile: ownerFile}); err == nil {
		t.Fatal("migrator silently repaired dirty schema")
	}

	if _, err := ownerDB.ExecContext(ctx, `DROP SCHEMA auth, relay, attachment, brain, jobs, audit CASCADE`); err != nil {
		t.Fatal(err)
	}
	broken := Manifest{MinSupported: 1, MaxSupported: 1, Migrations: []Migration{{Version: 1, Name: "broken", Checksum: "broken-checksum", CompatibilityFloor: 1, SQL: `CREATE SCHEMA auth; SELECT deliberately_invalid_migration_statement`}}}
	if _, err := migrate(ctx, ownerDB, broken); err == nil {
		t.Fatal("broken migration unexpectedly succeeded")
	}
	snapshot, err := inspect(ctx, ownerDB)
	if err != nil {
		t.Fatal(err)
	}
	if got := Classify(snapshot, broken).Classification; got != Dirty {
		t.Fatalf("failed migration state=%s, want dirty", got)
	}
	var authSchemaExists bool
	if err := ownerDB.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname='auth')`).Scan(&authSchemaExists); err != nil || authSchemaExists {
		t.Fatalf("failed migration left partial DDL: auth_exists=%t err=%v", authSchemaExists, err)
	}

	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `DROP SCHEMA jobs CASCADE; REVOKE CONNECT ON DATABASE punaro FROM punaro_app; DROP ROLE punaro_app`); err != nil {
		t.Fatal(err)
	}
	if _, err := Migrate(ctx, Config{DSNFile: ownerFile}); err == nil {
		t.Fatal("migrator accepted a missing application role")
	}
	var trackerExists bool
	if err := ownerDB.QueryRowContext(ctx, `SELECT to_regclass('jobs.schema_migrations') IS NOT NULL`).Scan(&trackerExists); err != nil || trackerExists {
		t.Fatalf("missing-role refusal mutated schema: tracker_exists=%t err=%v", trackerExists, err)
	}
}

func writeTestDSN(t *testing.T, name, dsn string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	// #nosec G703 -- path is below the test-owned TempDir and name is static.
	if err := os.WriteFile(path, []byte(dsn), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
