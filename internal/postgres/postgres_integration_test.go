package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
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
	ownerDB, err := open(ctx, ownerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ownerDB.Close() }()
	current := CurrentManifest()
	v1Manifest := Manifest{MinSupported: 1, MaxSupported: 1, Migrations: append([]Migration(nil), current.Migrations[:1]...)}
	if state, err := migrate(ctx, ownerDB, v1Manifest); err != nil || state.Classification != Compatible || state.Version != 1 {
		t.Fatalf("v1 bootstrap state=%#v err=%v", state, err)
	}
	app, err = OpenApplication(ctx, Config{DSNFile: appFile})
	if err != nil {
		t.Fatal(err)
	}
	state, err = app.SchemaState(ctx)
	if err != nil || state.Classification != UpgradeRequired || state.Version != 1 {
		t.Fatalf("intact v1 state=%#v err=%v, want upgrade_required", state, err)
	}
	if _, err := ownerDB.ExecContext(ctx, `ALTER TABLE jobs.server_state RENAME TO server_state_missing`); err != nil {
		t.Fatal(err)
	}
	state, err = app.SchemaState(ctx)
	if err != nil || state.Classification != Incompatible {
		t.Fatalf("damaged v1 state=%#v err=%v, want incompatible", state, err)
	}
	if _, err := ownerDB.ExecContext(ctx, `ALTER TABLE jobs.server_state_missing RENAME TO server_state`); err != nil {
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

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
			logControlPlaneCatalog(ctx, t, ownerDB)
			logDeviceAuthCatalog(ctx, t, ownerDB)
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

	testControlPlaneIntegration(ctx, t, app, ownerDB)
	if administration, err := OpenAdministration(ctx, Config{DSNFile: appFile}); err == nil {
		_ = administration.Close()
		t.Fatal("application role opened host-local administration")
	}
	testDeviceAuthIntegration(ctx, t, app, ownerDB)
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
	if _, err := ownerDB.ExecContext(ctx, `ALTER SCHEMA audit RENAME TO audit_missing`); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err == nil || !strings.Contains(err.Error(), string(Incompatible)) {
		t.Fatalf("readiness accepted missing required schema: %v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `ALTER SCHEMA audit_missing RENAME TO audit`); err != nil {
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
	if _, err := ownerDB.ExecContext(ctx, `ALTER TABLE auth.principals RENAME TO principals_missing`); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err == nil || !strings.Contains(err.Error(), string(Incompatible)) {
		t.Fatalf("readiness accepted missing control-plane object: %v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `ALTER TABLE auth.principals_missing RENAME TO principals`); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err != nil {
		t.Fatalf("readiness did not recover after control-plane object restoration: %v", err)
	}
	var guardDefinition string
	if err := ownerDB.QueryRowContext(ctx, `SELECT pg_get_functiondef('jobs.guard_outbox_capacity_and_state()'::regprocedure)`).Scan(&guardDefinition); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `CREATE OR REPLACE FUNCTION jobs.guard_outbox_capacity_and_state()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $function$ BEGIN RETURN NEW; END $function$`); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err == nil {
		t.Fatal("readiness accepted replacement capacity-trigger function body")
	}
	if _, err := ownerDB.ExecContext(ctx, guardDefinition); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err != nil {
		t.Fatalf("readiness did not recover after capacity-trigger function restoration: %v", err)
	}
	for _, drift := range []struct {
		name    string
		apply   string
		restore string
	}{
		{name: "project truncate", apply: `GRANT TRUNCATE ON relay.projects TO punaro_app`, restore: `REVOKE TRUNCATE ON relay.projects FROM punaro_app`},
		{name: "audit update column", apply: `GRANT UPDATE (outcome) ON audit.events TO punaro_app`, restore: `REVOKE UPDATE (outcome) ON audit.events FROM punaro_app`},
		{name: "audit sequence update", apply: `GRANT UPDATE ON SEQUENCE audit.events_event_id_seq TO punaro_app`, restore: `REVOKE UPDATE ON SEQUENCE audit.events_event_id_seq FROM punaro_app`},
		{name: "active grant index expression", apply: `DROP INDEX auth.capability_grants_active_unique; CREATE UNIQUE INDEX capability_grants_active_unique ON auth.capability_grants (principal_id, scope, COALESCE(id, '00000000-0000-0000-0000-000000000000'::uuid), capability) WHERE revoked_at IS NULL`, restore: `DROP INDEX auth.capability_grants_active_unique; CREATE UNIQUE INDEX capability_grants_active_unique ON auth.capability_grants (principal_id, scope, COALESCE(project_id, '00000000-0000-0000-0000-000000000000'::uuid), capability) WHERE revoked_at IS NULL`},
		{name: "function search path", apply: `ALTER FUNCTION jobs.prune_terminal(timestamptz, integer) RESET ALL`, restore: `ALTER FUNCTION jobs.prune_terminal(timestamptz, integer) SET search_path = pg_catalog`},
		{name: "trigger events", apply: `DROP TRIGGER outbox_capacity_and_state ON jobs.outbox; CREATE TRIGGER outbox_capacity_and_state BEFORE UPDATE ON jobs.outbox FOR EACH ROW EXECUTE FUNCTION jobs.guard_outbox_capacity_and_state()`, restore: `DROP TRIGGER outbox_capacity_and_state ON jobs.outbox; CREATE TRIGGER outbox_capacity_and_state BEFORE INSERT OR UPDATE ON jobs.outbox FOR EACH ROW EXECUTE FUNCTION jobs.guard_outbox_capacity_and_state()`},
		{name: "owner insert privilege", apply: `GRANT INSERT ON auth.installation_owner TO punaro_app`, restore: `REVOKE INSERT ON auth.installation_owner FROM punaro_app`},
		{name: "owner principal column update", apply: `GRANT UPDATE (principal_id) ON auth.installation_owner TO punaro_app`, restore: `REVOKE UPDATE (principal_id) ON auth.installation_owner FROM punaro_app`},
		{name: "enrollment issuer column insert", apply: `GRANT INSERT (issuer_principal_id) ON auth.pending_enrollments TO punaro_app`, restore: `REVOKE INSERT (issuer_principal_id) ON auth.pending_enrollments FROM punaro_app`},
		{name: "credential secret update privilege", apply: `GRANT UPDATE (secret_digest) ON auth.device_credentials TO punaro_app`, restore: `REVOKE UPDATE (secret_digest) ON auth.device_credentials FROM punaro_app`},
		{name: "credential expiry update privilege", apply: `GRANT UPDATE (expires_at) ON auth.device_credentials TO punaro_app`, restore: `REVOKE UPDATE (expires_at) ON auth.device_credentials FROM punaro_app`},
		{name: "credential principal column references", apply: `GRANT REFERENCES (principal_id) ON auth.device_credentials TO punaro_app`, restore: `REVOKE REFERENCES (principal_id) ON auth.device_credentials FROM punaro_app`},
		{name: "legacy enabled column update", apply: `GRANT UPDATE (enabled) ON auth.legacy_auth_state TO punaro_app`, restore: `REVOKE UPDATE (enabled) ON auth.legacy_auth_state FROM punaro_app`},
		{name: "legacy key column update", apply: `GRANT UPDATE (public_key) ON auth.legacy_machines TO punaro_app`, restore: `REVOKE UPDATE (public_key) ON auth.legacy_machines FROM punaro_app`},
		{name: "legacy exchange public execute", apply: `GRANT EXECUTE ON FUNCTION auth.complete_legacy_exchange(uuid, uuid) TO PUBLIC`, restore: `REVOKE EXECUTE ON FUNCTION auth.complete_legacy_exchange(uuid, uuid) FROM PUBLIC`},
		{name: "legacy exchange extra grantee", apply: `GRANT EXECUTE ON FUNCTION auth.complete_legacy_exchange(uuid, uuid) TO pg_monitor`, restore: `REVOKE EXECUTE ON FUNCTION auth.complete_legacy_exchange(uuid, uuid) FROM pg_monitor`},
		{name: "legacy exchange delegated grant", apply: `GRANT EXECUTE ON FUNCTION auth.complete_legacy_exchange(uuid, uuid) TO punaro_app WITH GRANT OPTION`, restore: `REVOKE GRANT OPTION FOR EXECUTE ON FUNCTION auth.complete_legacy_exchange(uuid, uuid) FROM punaro_app`},
		{name: "legacy exchange search path", apply: `ALTER FUNCTION auth.complete_legacy_exchange(uuid, uuid) RESET ALL`, restore: `ALTER FUNCTION auth.complete_legacy_exchange(uuid, uuid) SET search_path = pg_catalog`},
		{name: "pending binding index uniqueness", apply: `DROP INDEX auth.pending_enrollments_active_binding; CREATE UNIQUE INDEX pending_enrollments_active_binding ON auth.pending_enrollments (client_binding) WHERE redeemed_at IS NULL`, restore: `DROP INDEX auth.pending_enrollments_active_binding; CREATE INDEX pending_enrollments_active_binding ON auth.pending_enrollments (client_binding) WHERE redeemed_at IS NULL`},
		{name: "credential digest index", apply: `DROP INDEX auth.device_credentials_secret_digest`, restore: `CREATE UNIQUE INDEX device_credentials_secret_digest ON auth.device_credentials (secret_digest)`},
		{name: "credential generation constraint", apply: `ALTER TABLE auth.device_credentials DROP CONSTRAINT device_credentials_generation_check`, restore: `ALTER TABLE auth.device_credentials ADD CONSTRAINT device_credentials_generation_check CHECK (generation >= 1)`},
		{name: "permissive credential generation constraint", apply: `ALTER TABLE auth.device_credentials DROP CONSTRAINT device_credentials_generation_check; ALTER TABLE auth.device_credentials ADD CONSTRAINT device_credentials_generation_check CHECK (generation >= 1 OR true)`, restore: `ALTER TABLE auth.device_credentials DROP CONSTRAINT device_credentials_generation_check; ALTER TABLE auth.device_credentials ADD CONSTRAINT device_credentials_generation_check CHECK (generation >= 1)`},
		{name: "permissive credential expiry constraint", apply: `ALTER TABLE auth.device_credentials DROP CONSTRAINT device_credentials_check; ALTER TABLE auth.device_credentials ADD CONSTRAINT device_credentials_check CHECK (expires_at IS NULL OR expires_at > created_at OR true)`, restore: `ALTER TABLE auth.device_credentials DROP CONSTRAINT device_credentials_check; ALTER TABLE auth.device_credentials ADD CONSTRAINT device_credentials_check CHECK (expires_at IS NULL OR expires_at > created_at)`},
		{name: "principal auth generation constraint", apply: `ALTER TABLE auth.principals DROP CONSTRAINT principals_auth_generation_check`, restore: `ALTER TABLE auth.principals ADD CONSTRAINT principals_auth_generation_check CHECK (auth_generation >= 0)`},
		{name: "permissive principal auth generation constraint", apply: `ALTER TABLE auth.principals DROP CONSTRAINT principals_auth_generation_check; ALTER TABLE auth.principals ADD CONSTRAINT principals_auth_generation_check CHECK (auth_generation >= 0 OR true)`, restore: `ALTER TABLE auth.principals DROP CONSTRAINT principals_auth_generation_check; ALTER TABLE auth.principals ADD CONSTRAINT principals_auth_generation_check CHECK (auth_generation >= 0)`},
		{name: "audit action value set", apply: `ALTER TABLE audit.events DROP CONSTRAINT events_action_check; ALTER TABLE audit.events ADD CONSTRAINT events_action_check CHECK (action IN ('principal.create', 'project.create', 'grant.create', 'grant.delete', 'job.enqueue', 'job.complete', 'job.retry', 'job.fail', 'owner.bootstrap', 'enrollment.create', 'enrollment.redeem', 'credential.rotate', 'credential.revoke', 'legacy.register', 'legacy.exchange', 'legacy.retire', 'legacy.disable', 'unexpected'))`, restore: `ALTER TABLE audit.events DROP CONSTRAINT events_action_check; ALTER TABLE audit.events ADD CONSTRAINT events_action_check CHECK (action IN ('principal.create', 'project.create', 'grant.create', 'grant.delete', 'job.enqueue', 'job.complete', 'job.retry', 'job.fail', 'owner.bootstrap', 'enrollment.create', 'enrollment.redeem', 'credential.rotate', 'credential.revoke', 'legacy.register', 'legacy.exchange', 'legacy.retire', 'legacy.disable'))`},
		{name: "permissive audit action constraint", apply: `ALTER TABLE audit.events DROP CONSTRAINT events_action_check; ALTER TABLE audit.events ADD CONSTRAINT events_action_check CHECK (action IN ('principal.create', 'project.create', 'grant.create', 'grant.delete', 'job.enqueue', 'job.complete', 'job.retry', 'job.fail', 'owner.bootstrap', 'enrollment.create', 'enrollment.redeem', 'credential.rotate', 'credential.revoke', 'legacy.register', 'legacy.exchange', 'legacy.retire', 'legacy.disable') OR true)`, restore: `ALTER TABLE audit.events DROP CONSTRAINT events_action_check; ALTER TABLE audit.events ADD CONSTRAINT events_action_check CHECK (action IN ('principal.create', 'project.create', 'grant.create', 'grant.delete', 'job.enqueue', 'job.complete', 'job.retry', 'job.fail', 'owner.bootstrap', 'enrollment.create', 'enrollment.redeem', 'credential.rotate', 'credential.revoke', 'legacy.register', 'legacy.exchange', 'legacy.retire', 'legacy.disable'))`},
		{name: "audit target value set", apply: `ALTER TABLE audit.events DROP CONSTRAINT events_target_kind_check; ALTER TABLE audit.events ADD CONSTRAINT events_target_kind_check CHECK (target_kind IN ('principal', 'project', 'grant', 'job', 'enrollment', 'credential', 'legacy_machine', 'unexpected'))`, restore: `ALTER TABLE audit.events DROP CONSTRAINT events_target_kind_check; ALTER TABLE audit.events ADD CONSTRAINT events_target_kind_check CHECK (target_kind IN ('principal', 'project', 'grant', 'job', 'enrollment', 'credential', 'legacy_machine'))`},
		{name: "permissive audit target constraint", apply: `ALTER TABLE audit.events DROP CONSTRAINT events_target_kind_check; ALTER TABLE audit.events ADD CONSTRAINT events_target_kind_check CHECK (target_kind IN ('principal', 'project', 'grant', 'job', 'enrollment', 'credential', 'legacy_machine') OR true)`, restore: `ALTER TABLE audit.events DROP CONSTRAINT events_target_kind_check; ALTER TABLE audit.events ADD CONSTRAINT events_target_kind_check CHECK (target_kind IN ('principal', 'project', 'grant', 'job', 'enrollment', 'credential', 'legacy_machine'))`},
		{name: "legacy machine state value set", apply: `ALTER TABLE auth.legacy_machines DROP CONSTRAINT legacy_machines_state_check; ALTER TABLE auth.legacy_machines ADD CONSTRAINT legacy_machines_state_check CHECK (state IN ('pending', 'migrated', 'retired', 'unexpected'))`, restore: `ALTER TABLE auth.legacy_machines DROP CONSTRAINT legacy_machines_state_check; ALTER TABLE auth.legacy_machines ADD CONSTRAINT legacy_machines_state_check CHECK (state IN ('pending', 'migrated', 'retired'))`},
	} {
		t.Run("readiness rejects "+drift.name, func(t *testing.T) {
			if _, err := ownerDB.ExecContext(ctx, drift.apply); err != nil {
				t.Fatal(err)
			}
			if err := app.Ready(ctx); err == nil {
				t.Fatalf("readiness accepted %s drift", drift.name)
			}
			if _, err := ownerDB.ExecContext(ctx, drift.restore); err != nil {
				t.Fatal(err)
			}
			if err := app.Ready(ctx); err != nil {
				t.Fatalf("readiness did not recover after %s drift: %v", drift.name, err)
			}
		})
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
	if err := ownerDB.QueryRowContext(ctx, `SELECT count(*) FROM jobs.schema_migrations`).Scan(&count); err != nil || count != len(CurrentManifest().Migrations) {
		t.Fatalf("migration rows=%d err=%v, want exactly %d", count, err, len(CurrentManifest().Migrations))
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

func testControlPlaneIntegration(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB) {
	t.Helper()
	principalA, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "device A")
	if err != nil {
		t.Fatal(err)
	}
	principalB, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "device B")
	if err != nil {
		t.Fatal(err)
	}
	// M-3 replaces this fixture with the host-local first-owner bootstrap. M-2
	// seeds the minimum root authority out of band so every public grant mutation
	// can prove actor authorization without adding an unauthenticated back door.
	var creatorGrantID, bootstrapAdminGrantID string
	err = ownerDB.QueryRowContext(ctx, `INSERT INTO auth.capability_grants (principal_id, scope, capability)
VALUES ($1, 'installation', 'project.create') RETURNING id::text`, principalA.ID).Scan(&creatorGrantID)
	if err != nil {
		t.Fatal(err)
	}
	err = ownerDB.QueryRowContext(ctx, `INSERT INTO auth.capability_grants (principal_id, scope, capability)
VALUES ($1, 'all_projects', 'project.administer') RETURNING id::text`, principalA.ID).Scan(&bootstrapAdminGrantID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.GrantCapability(ctx, principalB.ID, Grant{PrincipalID: principalB.ID, Scope: ScopeAllProjects, Capability: CapabilityMemoryRead}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unauthorized self-grant error=%v", err)
	}
	var unauthorizedGrantRows int
	if err := ownerDB.QueryRowContext(ctx, `SELECT count(*) FROM auth.capability_grants
WHERE principal_id = $1 AND scope = 'all_projects' AND capability = 'memory.read'`, principalB.ID).Scan(&unauthorizedGrantRows); err != nil || unauthorizedGrantRows != 0 {
		t.Fatalf("unauthorized grant left rows=%d err=%v", unauthorizedGrantRows, err)
	}
	if _, err := app.GrantCapability(ctx, principalA.ID, Grant{PrincipalID: principalB.ID, Scope: ScopeInstallation, Capability: CapabilityProjectCreate}); err != nil {
		t.Fatal(err)
	}
	if _, err := app.GrantCapability(ctx, principalB.ID, Grant{PrincipalID: principalB.ID, Scope: ScopeAllProjects, Capability: CapabilityMemoryRead}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("ordinary project creator administered grants: %v", err)
	}
	dynamicGrantID, err := app.GrantCapability(ctx, principalA.ID, Grant{PrincipalID: principalB.ID, Scope: ScopeAllProjects, Capability: CapabilityMemoryRead})
	if err != nil {
		t.Fatal(err)
	}
	if err := app.RevokeGrant(ctx, principalB.ID, dynamicGrantID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("ordinary project creator revoked grant: %v", err)
	}
	grantState, err := app.InstallationState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var grantAuditBefore int
	if err := ownerDB.QueryRowContext(ctx, `SELECT count(*) FROM audit.events WHERE target_id = $1 AND action = 'grant.create'`, dynamicGrantID).Scan(&grantAuditBefore); err != nil {
		t.Fatal(err)
	}
	var grantAuditActor string
	if err := ownerDB.QueryRowContext(ctx, `SELECT principal_id::text FROM audit.events WHERE target_id = $1 AND action = 'grant.create'`, dynamicGrantID).Scan(&grantAuditActor); err != nil || grantAuditActor != principalA.ID {
		t.Fatalf("grant audit actor=%q err=%v", grantAuditActor, err)
	}
	type grantResult struct {
		id  string
		err error
	}
	grantResults := make(chan grantResult, 2)
	grantStart := make(chan struct{})
	for range 2 {
		go func() {
			<-grantStart
			id, grantErr := app.GrantCapability(ctx, principalA.ID, Grant{PrincipalID: principalB.ID, Scope: ScopeAllProjects, Capability: CapabilityMemoryRead})
			grantResults <- grantResult{id: id, err: grantErr}
		}()
	}
	close(grantStart)
	grantRetryA, grantRetryB := <-grantResults, <-grantResults
	grantStateAfter, err := app.InstallationState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var grantAuditAfter int
	if err := ownerDB.QueryRowContext(ctx, `SELECT count(*) FROM audit.events WHERE target_id = $1 AND action = 'grant.create'`, dynamicGrantID).Scan(&grantAuditAfter); err != nil {
		t.Fatal(err)
	}
	if grantRetryA.err != nil || grantRetryB.err != nil || grantRetryA.id != dynamicGrantID || grantRetryB.id != dynamicGrantID || grantStateAfter.ChangeSequence != grantState.ChangeSequence || grantAuditAfter != grantAuditBefore {
		t.Fatalf("no-op grant retries changed state: a=%#v b=%#v sequence=%d/%d audit=%d/%d", grantRetryA, grantRetryB, grantState.ChangeSequence, grantStateAfter.ChangeSequence, grantAuditBefore, grantAuditAfter)
	}

	before, err := app.InstallationState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	create := ProjectCreate{PrincipalID: principalA.ID, IdempotencyKey: "33333333-3333-4333-8333-333333333333", DisplayName: "friendly alpha"}
	type createResult struct {
		result ProjectResult
		err    error
	}
	concurrent := make(chan createResult, 2)
	start := make(chan struct{})
	for range 2 {
		go func() {
			<-start
			result, createErr := app.CreateProject(ctx, create)
			concurrent <- createResult{result: result, err: createErr}
		}()
	}
	close(start)
	firstCall, secondCall := <-concurrent, <-concurrent
	if firstCall.err != nil || secondCall.err != nil || firstCall.result != secondCall.result {
		t.Fatalf("concurrent project results=%#v/%#v", firstCall, secondCall)
	}
	first := firstCall.result
	retry, err := app.CreateProject(ctx, create)
	if err != nil || retry != first {
		t.Fatalf("exact project retry=%#v err=%v, want %#v", retry, err, first)
	}
	after, err := app.InstallationState(ctx)
	if err != nil || after.ChangeSequence != before.ChangeSequence+1 || first.ChangeSequence != after.ChangeSequence {
		t.Fatalf("project sequence before=%#v result=%#v after=%#v err=%v", before, first, after, err)
	}
	if err := app.RevokeGrant(ctx, principalA.ID, creatorGrantID); err != nil {
		t.Fatal(err)
	}
	retryAfterRevoke, err := app.CreateProject(ctx, create)
	if err != nil || retryAfterRevoke != first {
		t.Fatalf("exact project retry after authority revocation=%#v err=%v, want %#v", retryAfterRevoke, err, first)
	}
	if _, err := app.GrantCapability(ctx, principalA.ID, Grant{PrincipalID: principalA.ID, Scope: ScopeInstallation, Capability: CapabilityProjectCreate}); err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		principal  string
		project    string
		capability Capability
		want       bool
	}{
		{principalA.ID, first.ProjectID, CapabilityProjectRead, true},
		{principalA.ID, first.ProjectID, CapabilityProjectWrite, true},
		{principalB.ID, first.ProjectID, CapabilityMemoryRead, true},
		{principalB.ID, first.ProjectID, CapabilityProjectWrite, false},
	} {
		got, checkErr := app.HasCapability(ctx, check.principal, check.project, check.capability)
		if checkErr != nil || got != check.want {
			t.Fatalf("HasCapability(%s)=%t err=%v, want %t", check.capability, got, checkErr, check.want)
		}
	}
	if _, err := app.HasCapability(ctx, principalA.ID, "friendly alpha", CapabilityProjectRead); err == nil {
		t.Fatal("friendly project label accepted as authority")
	}
	var capacityBeforeInvalidJobs int
	if err := ownerDB.QueryRowContext(ctx, `SELECT active_count FROM jobs.queue_capacity WHERE singleton`).Scan(&capacityBeforeInvalidJobs); err != nil {
		t.Fatal(err)
	}
	for name, invalidJob := range map[string]EnqueueJob{
		"unknown kind":    {ActorPrincipalID: principalA.ID, Kind: "project.reconcile", ProjectID: first.ProjectID, Payload: json.RawMessage(`{}`), MaxAttempts: 1},
		"missing project": {ActorPrincipalID: principalA.ID, Kind: "project.created", Payload: json.RawMessage(`{}`), MaxAttempts: 1},
	} {
		t.Run("invalid enqueue "+name, func(t *testing.T) {
			tx, txErr := app.db.BeginTx(ctx, nil)
			if txErr != nil {
				t.Fatal(txErr)
			}
			defer func() { _ = tx.Rollback() }()
			if _, enqueueErr := (&ControlTx{tx: tx}).EnqueueJob(ctx, invalidJob); enqueueErr == nil {
				t.Fatal("invalid job was enqueued")
			}
		})
	}
	var capacityAfterInvalidJobs, invalidJobRows int
	if err := ownerDB.QueryRowContext(ctx, `SELECT
		(SELECT active_count FROM jobs.queue_capacity WHERE singleton),
		(SELECT count(*) FROM jobs.outbox WHERE kind = 'project.reconcile' OR project_id IS NULL)`).Scan(&capacityAfterInvalidJobs, &invalidJobRows); err != nil {
		t.Fatal(err)
	}
	if capacityAfterInvalidJobs != capacityBeforeInvalidJobs || invalidJobRows != 0 {
		t.Fatalf("invalid enqueue changed capacity %d/%d or left %d rows", capacityBeforeInvalidJobs, capacityAfterInvalidJobs, invalidJobRows)
	}

	changed := create
	changed.DisplayName = "changed body"
	if _, err := app.CreateProject(ctx, changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed idempotent body error=%v", err)
	}
	if _, err := app.GrantCapability(ctx, principalA.ID, Grant{PrincipalID: principalB.ID, Scope: ScopeInstallation, Capability: CapabilityProjectCreate}); err != nil {
		t.Fatal(err)
	}
	changed = create
	changed.PrincipalID = principalB.ID
	if _, err := app.CreateProject(ctx, changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed idempotent principal error=%v", err)
	}
	if _, err := app.executeIdempotent(ctx, IdempotencyRequest{PrincipalID: principalA.ID, Operation: "project.rename", Key: create.IdempotencyKey, Body: []byte(`{}`)}, func(*ControlTx) (IdempotencyOutcome, error) {
		return IdempotencyOutcome{Status: OutcomeSucceeded, Result: json.RawMessage(`{}`)}, nil
	}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed idempotent operation error=%v", err)
	}

	principalC, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "device C")
	if err != nil {
		t.Fatal(err)
	}
	unauthorized := ProjectCreate{PrincipalID: principalC.ID, IdempotencyKey: "44444444-4444-4444-8444-444444444444", DisplayName: "forbidden"}
	if _, err := app.CreateProject(ctx, unauthorized); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unauthorized project error=%v", err)
	}
	var unauthorizedRecords int
	if err := ownerDB.QueryRowContext(ctx, `SELECT
        (SELECT count(*) FROM relay.projects WHERE display_name = 'forbidden')
      + (SELECT count(*) FROM relay.idempotency_records WHERE key = '44444444-4444-4444-8444-444444444444')
      + (SELECT count(*) FROM audit.events WHERE principal_id = $1 AND action = 'project.create')`, principalC.ID).Scan(&unauthorizedRecords); err != nil || unauthorizedRecords != 0 {
		t.Fatalf("unauthorized mutation left %d rows err=%v", unauthorizedRecords, err)
	}

	secondCreate := ProjectCreate{PrincipalID: principalA.ID, IdempotencyKey: "55555555-5555-4555-8555-555555555555", DisplayName: "future beta"}
	second, err := app.CreateProject(ctx, secondCreate)
	if err != nil {
		t.Fatal(err)
	}
	if allowed, err := app.HasCapability(ctx, principalB.ID, second.ProjectID, CapabilityMemoryRead); err != nil || !allowed {
		t.Fatalf("dynamic all-projects grant did not cover future project: allowed=%t err=%v", allowed, err)
	}
	if _, err := app.GrantCapability(ctx, principalA.ID, Grant{PrincipalID: principalB.ID, Scope: ScopeProject, ProjectID: first.ProjectID, Capability: CapabilityProjectAdminister}); err != nil {
		t.Fatal(err)
	}
	exactProjectGrantID, err := app.GrantCapability(ctx, principalB.ID, Grant{PrincipalID: principalB.ID, Scope: ScopeProject, ProjectID: first.ProjectID, Capability: CapabilityMemoryWrite})
	if err != nil {
		t.Fatalf("exact-project administrator could not grant in its project: %v", err)
	}
	for name, forbiddenGrant := range map[string]Grant{
		"other project": {PrincipalID: principalB.ID, Scope: ScopeProject, ProjectID: second.ProjectID, Capability: CapabilityMemoryWrite},
		"installation":  {PrincipalID: principalB.ID, Scope: ScopeInstallation, Capability: CapabilityProjectCreate},
		"all projects":  {PrincipalID: principalB.ID, Scope: ScopeAllProjects, Capability: CapabilityMemoryWrite},
	} {
		if _, err := app.GrantCapability(ctx, principalB.ID, forbiddenGrant); !errors.Is(err, ErrForbidden) {
			t.Fatalf("exact-project administrator mutated %s scope: %v", name, err)
		}
	}
	if err := app.RevokeGrant(ctx, principalB.ID, exactProjectGrantID); err != nil {
		t.Fatalf("exact-project administrator could not revoke in its project: %v", err)
	}
	if err := app.RevokeGrant(ctx, principalA.ID, dynamicGrantID); err != nil {
		t.Fatal(err)
	}
	if allowed, err := app.HasCapability(ctx, principalB.ID, second.ProjectID, CapabilityMemoryRead); err != nil || allowed {
		t.Fatalf("revoked dynamic grant remained effective: allowed=%t err=%v", allowed, err)
	}
	adminGrantIDs := make(map[string]string, 2)
	for _, principalID := range []string{principalA.ID, principalB.ID} {
		grantID, err := app.GrantCapability(ctx, principalA.ID, Grant{PrincipalID: principalID, Scope: ScopeAllProjects, Capability: CapabilityProjectAdminister})
		if err != nil {
			t.Fatal(err)
		}
		adminGrantIDs[principalID] = grantID
	}
	if unauthorizedJobs, err := app.ClaimJobs(ctx, ClaimJobs{Kind: "project.created", Holder: principalC.ID, Limit: 1, LeaseDuration: time.Minute}); err != nil || len(unauthorizedJobs) != 0 {
		t.Fatalf("unauthorized worker received jobs=%#v err=%v", unauthorizedJobs, err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE auth.principals SET disabled_at = statement_timestamp() WHERE id = $1`, principalA.ID); err != nil {
		t.Fatal(err)
	}
	if disabledJobs, err := app.ClaimJobs(ctx, ClaimJobs{Kind: "project.created", Holder: principalA.ID, Limit: 1, LeaseDuration: time.Minute}); err != nil || len(disabledJobs) != 0 {
		t.Fatalf("disabled worker received jobs=%#v err=%v", disabledJobs, err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE auth.principals SET disabled_at = NULL WHERE id = $1`, principalA.ID); err != nil {
		t.Fatal(err)
	}

	type claimResult struct {
		jobs []LeasedJob
		err  error
	}
	claimResults := make(chan claimResult, 2)
	claimStart := make(chan struct{})
	for _, holder := range []string{principalA.ID, principalB.ID} {
		go func() {
			<-claimStart
			claimed, claimErr := app.ClaimJobs(ctx, ClaimJobs{Kind: "project.created", Holder: holder, Limit: 1, LeaseDuration: time.Minute})
			claimResults <- claimResult{jobs: claimed, err: claimErr}
		}()
	}
	close(claimStart)
	firstClaim, secondClaim := <-claimResults, <-claimResults
	if firstClaim.err != nil || secondClaim.err != nil || len(firstClaim.jobs) != 1 || len(secondClaim.jobs) != 1 || firstClaim.jobs[0].ID == secondClaim.jobs[0].ID {
		t.Fatalf("concurrent disjoint claims=%#v/%#v", firstClaim, secondClaim)
	}
	jobs, otherJobs := firstClaim.jobs, secondClaim.jobs
	if _, err := ownerDB.ExecContext(ctx, `UPDATE auth.principals SET disabled_at = statement_timestamp() WHERE id = $1`, jobs[0].Holder); err != nil {
		t.Fatal(err)
	}
	if err := app.CompleteJob(ctx, jobs[0].Lease()); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("disabled holder completed leased job: %v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE auth.principals SET disabled_at = NULL WHERE id = $1`, jobs[0].Holder); err != nil {
		t.Fatal(err)
	}
	if err := app.CompleteJob(ctx, jobs[0].Lease()); err != nil {
		t.Fatal(err)
	}
	stale := otherJobs[0].Lease()
	if _, err := ownerDB.ExecContext(ctx, `UPDATE jobs.outbox SET lease_until = statement_timestamp() - interval '1 second' WHERE id = $1`, otherJobs[0].ID); err != nil {
		t.Fatal(err)
	}
	reclaimed, err := app.ClaimJobs(ctx, ClaimJobs{Kind: "project.created", Holder: principalA.ID, Limit: 1, LeaseDuration: time.Minute})
	if err != nil || len(reclaimed) != 1 || reclaimed[0].ID != otherJobs[0].ID || reclaimed[0].Generation <= stale.Generation || reclaimed[0].Token == stale.Token {
		t.Fatalf("reclaimed=%#v err=%v, stale=%#v", reclaimed, err, stale)
	}
	if err := app.CompleteJob(ctx, stale); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("stale completion error=%v", err)
	}
	revocationActor := principalB.ID
	if reclaimed[0].Holder == principalB.ID {
		revocationActor = principalA.ID
	}
	if err := app.RevokeGrant(ctx, revocationActor, adminGrantIDs[reclaimed[0].Holder]); err != nil {
		t.Fatal(err)
	}
	if err := app.RetryJob(ctx, JobRetry{Lease: reclaimed[0].Lease(), ErrorCode: "transient", Delay: time.Minute}); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("revoked holder retried leased job: %v", err)
	}
	replacementGrantID, err := app.GrantCapability(ctx, revocationActor, Grant{PrincipalID: reclaimed[0].Holder, Scope: ScopeAllProjects, Capability: CapabilityProjectAdminister})
	if err != nil {
		t.Fatal(err)
	}
	adminGrantIDs[reclaimed[0].Holder] = replacementGrantID
	if err := app.RetryJob(ctx, JobRetry{Lease: reclaimed[0].Lease(), ErrorCode: "transient", Delay: time.Minute}); err != nil {
		t.Fatal(err)
	}
	if premature, err := app.ClaimJobs(ctx, ClaimJobs{Kind: "project.created", Holder: principalB.ID, Limit: 1, LeaseDuration: time.Minute}); err != nil || len(premature) != 0 {
		t.Fatalf("backoff job claimed before availability: jobs=%#v err=%v", premature, err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE jobs.outbox SET available_at = statement_timestamp() - interval '1 second' WHERE id = $1`, reclaimed[0].ID); err != nil {
		t.Fatal(err)
	}

	var activeBefore, projectsBefore, auditBefore, idempotencyBefore int
	if err := ownerDB.QueryRowContext(ctx, `SELECT active_count FROM jobs.queue_capacity WHERE singleton`).Scan(&activeBefore); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE jobs.queue_capacity SET max_depth = active_count WHERE singleton`); err != nil {
		t.Fatal(err)
	}
	if err := ownerDB.QueryRowContext(ctx, `SELECT
        (SELECT count(*) FROM relay.projects),
        (SELECT count(*) FROM audit.events),
        (SELECT count(*) FROM relay.idempotency_records)`).Scan(&projectsBefore, &auditBefore, &idempotencyBefore); err != nil {
		t.Fatal(err)
	}
	full := ProjectCreate{PrincipalID: principalA.ID, IdempotencyKey: "66666666-6666-4666-8666-666666666666", DisplayName: "queue full rollback"}
	if _, err := app.CreateProject(ctx, full); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("queue-full project error=%v", err)
	}
	var projectsAfter, auditAfter, idempotencyAfter, activeAfter int
	if err := ownerDB.QueryRowContext(ctx, `SELECT
        (SELECT count(*) FROM relay.projects),
        (SELECT count(*) FROM audit.events),
        (SELECT count(*) FROM relay.idempotency_records),
        (SELECT active_count FROM jobs.queue_capacity WHERE singleton)`).Scan(&projectsAfter, &auditAfter, &idempotencyAfter, &activeAfter); err != nil {
		t.Fatal(err)
	}
	if projectsAfter != projectsBefore || auditAfter != auditBefore || idempotencyAfter != idempotencyBefore || activeAfter != activeBefore {
		t.Fatalf("queue-full rollback changed projects %d/%d audit %d/%d idempotency %d/%d active %d/%d", projectsBefore, projectsAfter, auditBefore, auditAfter, idempotencyBefore, idempotencyAfter, activeBefore, activeAfter)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE jobs.queue_capacity SET max_depth = 10000 WHERE singleton`); err != nil {
		t.Fatal(err)
	}

	if err := app.CompleteJob(ctx, reclaimed[0].Lease()); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("retried lease remained publishable: %v", err)
	}
	claimedAgain, err := app.ClaimJobs(ctx, ClaimJobs{Kind: "project.created", Holder: principalB.ID, Limit: 1, LeaseDuration: time.Minute})
	if err != nil || len(claimedAgain) != 1 {
		t.Fatalf("retry claim=%#v err=%v", claimedAgain, err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE jobs.outbox SET attempts = max_attempts WHERE id = $1`, claimedAgain[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := app.RetryJob(ctx, JobRetry{Lease: claimedAgain[0].Lease(), ErrorCode: "terminal", Delay: 0}); err != nil {
		t.Fatalf("terminal retry failed: %v", err)
	}
	var terminalState string
	if err := ownerDB.QueryRowContext(ctx, `SELECT state FROM jobs.outbox WHERE id = $1`, claimedAgain[0].ID).Scan(&terminalState); err != nil || terminalState != "failed" {
		t.Fatalf("terminal retry state=%q err=%v", terminalState, err)
	}
	exhaustionProject, err := app.CreateProject(ctx, ProjectCreate{PrincipalID: principalA.ID, IdempotencyKey: "77777777-7777-4777-8777-777777777777", DisplayName: "exhaustion audit"})
	if err != nil {
		t.Fatal(err)
	}
	exhaustionJobs, err := app.ClaimJobs(ctx, ClaimJobs{Kind: "project.created", Holder: principalB.ID, Limit: 1, LeaseDuration: time.Minute})
	if err != nil || len(exhaustionJobs) != 1 || exhaustionJobs[0].ProjectID != exhaustionProject.ProjectID {
		t.Fatalf("exhaustion setup jobs=%#v err=%v", exhaustionJobs, err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE jobs.outbox SET attempts = max_attempts, lease_until = statement_timestamp() - interval '1 second' WHERE id = $1`, exhaustionJobs[0].ID); err != nil {
		t.Fatal(err)
	}
	if jobs, err := app.ClaimJobs(ctx, ClaimJobs{Kind: "project.created", Holder: principalC.ID, Limit: 1, LeaseDuration: time.Minute}); err != nil || len(jobs) != 0 {
		t.Fatalf("exhausted job was reclaimed: jobs=%#v err=%v", jobs, err)
	}
	if err := ownerDB.QueryRowContext(ctx, `SELECT state FROM jobs.outbox WHERE id = $1`, exhaustionJobs[0].ID).Scan(&terminalState); err != nil || terminalState != "failed" {
		t.Fatalf("exhausted state=%q err=%v", terminalState, err)
	}
	var enqueueAudits, completionAudits, retryAudits, failureAudits int
	if err := ownerDB.QueryRowContext(ctx, `SELECT
		count(*) FILTER (WHERE action = 'job.enqueue'),
		count(*) FILTER (WHERE action = 'job.complete'),
		count(*) FILTER (WHERE action = 'job.retry'),
		count(*) FILTER (WHERE action = 'job.fail')
		FROM audit.events WHERE target_kind = 'job'`).Scan(&enqueueAudits, &completionAudits, &retryAudits, &failureAudits); err != nil {
		t.Fatal(err)
	}
	if enqueueAudits != 3 || completionAudits != 1 || retryAudits != 1 || failureAudits != 2 {
		t.Fatalf("job audit counts enqueue=%d complete=%d retry=%d fail=%d", enqueueAudits, completionAudits, retryAudits, failureAudits)
	}
	var exhaustedAuditActor string
	if err := ownerDB.QueryRowContext(ctx, `SELECT principal_id::text FROM audit.events
		WHERE target_id = $1 AND action = 'job.fail'`, exhaustionJobs[0].ID).Scan(&exhaustedAuditActor); err != nil || exhaustedAuditActor != exhaustionJobs[0].Holder {
		t.Fatalf("exhausted audit actor=%q err=%v", exhaustedAuditActor, err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE jobs.outbox SET completed_at = statement_timestamp() - interval '2 hours' WHERE id = $1`, claimedAgain[0].ID); err == nil {
		t.Fatal("terminal job was mutable")
	}
	pruned, err := app.PruneTerminalJobs(ctx, time.Now().Add(time.Hour), 1)
	if err != nil || pruned != 1 {
		t.Fatalf("pruned=%d err=%v", pruned, err)
	}
}

func logControlPlaneCatalog(ctx context.Context, t *testing.T, db *sql.DB) {
	t.Helper()
	rows, err := db.QueryContext(ctx, `SELECT oid::regprocedure::text, pg_get_userbyid(proowner), prosecdef, proconfig::text, md5(btrim(prosrc))
FROM pg_proc WHERE oid = ANY(ARRAY[
    to_regprocedure('jobs.guard_outbox_capacity_and_state()'),
    to_regprocedure('audit.prune_events(timestamp with time zone,integer)'),
    to_regprocedure('jobs.prune_terminal(timestamp with time zone,integer)')
]) ORDER BY oid::regprocedure::text`)
	if err != nil {
		t.Logf("control-plane function diagnostics unavailable: %v", err)
	} else {
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var name, owner, config, hash string
			var securityDefiner bool
			if err := rows.Scan(&name, &owner, &securityDefiner, &config, &hash); err != nil {
				t.Logf("control-plane function diagnostic malformed: %v", err)
				break
			}
			t.Logf("control-plane function name=%s owner=%s security_definer=%t config=%v body_md5=%s", name, owner, securityDefiner, config, hash)
		}
	}
	var indexKeys, indexExpression, indexPredicate string
	var indexUnique, indexValid, indexReady bool
	if err := db.QueryRowContext(ctx, `SELECT indkey::text, pg_get_expr(indexprs, indrelid), pg_get_expr(indpred, indrelid), indisunique, indisvalid, indisready
FROM pg_index WHERE indexrelid = to_regclass('auth.capability_grants_active_unique')`).Scan(&indexKeys, &indexExpression, &indexPredicate, &indexUnique, &indexValid, &indexReady); err != nil {
		t.Logf("control-plane index diagnostics unavailable: %v", err)
	} else {
		t.Logf("control-plane index keys=%s expression=%q predicate=%q unique=%t valid=%t ready=%t", indexKeys, indexExpression, indexPredicate, indexUnique, indexValid, indexReady)
	}
	var triggerType int
	var triggerEnabled string
	if err := db.QueryRowContext(ctx, `SELECT tgtype, tgenabled::text FROM pg_trigger WHERE tgrelid = to_regclass('jobs.outbox') AND tgname = 'outbox_capacity_and_state'`).Scan(&triggerType, &triggerEnabled); err != nil {
		t.Logf("control-plane trigger diagnostics unavailable: %v", err)
	} else {
		t.Logf("control-plane trigger type=%d enabled=%s", triggerType, triggerEnabled)
	}
}

func logDeviceAuthCatalog(ctx context.Context, t *testing.T, db *sql.DB) {
	t.Helper()
	rows, err := db.QueryContext(ctx, `SELECT conrelid::regclass::text, conname, conkey::text, pg_get_expr(conbin, conrelid)
FROM pg_constraint
WHERE contype = 'c' AND conrelid = ANY(ARRAY[
    to_regclass('auth.principals'),
    to_regclass('auth.installation_owner'),
    to_regclass('auth.pending_enrollments'),
    to_regclass('auth.pending_enrollment_grants'),
    to_regclass('auth.device_credentials'),
    to_regclass('auth.legacy_machines'),
    to_regclass('audit.events')
]) ORDER BY conrelid::regclass::text, conname`)
	if err != nil {
		t.Logf("device-auth constraint diagnostics unavailable: %v", err)
		return
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var relation, name, keys, expression string
		if err := rows.Scan(&relation, &name, &keys, &expression); err != nil {
			t.Logf("device-auth constraint diagnostic malformed: %v", err)
			return
		}
		t.Logf("device-auth constraint relation=%s name=%s keys=%s expression=%q", relation, name, keys, expression)
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
