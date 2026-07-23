package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rock3r/punaro/internal/relay"
	"github.com/rock3r/punaro/internal/relay/contracttest"
)

func TestPostgresPlatformSubstrateIntegration(t *testing.T) {
	ownerDSN := os.Getenv("PUNARO_TEST_POSTGRES_OWNER_DSN")
	appDSN := os.Getenv("PUNARO_TEST_POSTGRES_APP_DSN")
	if ownerDSN == "" || appDSN == "" {
		t.Skip("set PUNARO_TEST_POSTGRES_OWNER_DSN and PUNARO_TEST_POSTGRES_APP_DSN to run PostgreSQL integration tests")
	}
	otherOwnerDSN := os.Getenv("PUNARO_TEST_POSTGRES_OTHER_OWNER_DSN")
	pairOwnerDSN := os.Getenv("PUNARO_TEST_POSTGRES_PAIR_OWNER_DSN")
	pairAppDSN := os.Getenv("PUNARO_TEST_POSTGRES_PAIR_APP_DSN")
	if otherOwnerDSN == "" || pairOwnerDSN == "" || pairAppDSN == "" {
		t.Fatal("PostgreSQL integration requires the distinct-target and pair-migration DSNs")
	}
	ctx := context.Background()
	ownerFile := writeTestDSN(t, "owner.dsn", ownerDSN)
	appFile := writeTestDSN(t, "app.dsn", appDSN)
	otherOwnerFile := writeTestDSN(t, "other-owner.dsn", otherOwnerDSN)
	pairOwnerFile := writeTestDSN(t, "pair-owner.dsn", pairOwnerDSN)
	pairAppFile := writeTestDSN(t, "pair-app.dsn", pairAppDSN)
	if _, err := withPristinePair(ctx, Config{DSNFile: appFile}, Config{DSNFile: otherOwnerFile}, func(*sql.Conn) (SchemaState, error) {
		t.Fatal("distinct database pair reached the migration action")
		return SchemaState{}, nil
	}); !errors.Is(err, ErrMigrationNotAttempted) {
		t.Fatalf("distinct database pair error=%v, want pre-migration refusal", err)
	}
	if _, err := withPristinePair(ctx, Config{DSNFile: appFile}, Config{DSNFile: ownerFile}, func(*sql.Conn) (SchemaState, error) {
		return SchemaState{Classification: Pristine}, nil
	}); err != nil {
		t.Fatalf("pristine DSN pair proof failed: %v", err)
	}
	if state, err := MigratePristinePair(ctx, Config{DSNFile: pairAppFile}, Config{DSNFile: pairOwnerFile}); err != nil || state.Classification != Compatible {
		t.Fatalf("connection-bound pair migration state=%#v err=%v catalog=%s", state, err, m6CatalogDiagnostic(ctx, pairOwnerDSN))
	}
	pairDB, err := open(ctx, pairOwnerDSN)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pairDB.ExecContext(ctx, `DROP SCHEMA auth, relay, attachment, brain, jobs, audit CASCADE; REVOKE CONNECT ON DATABASE punaro_pair FROM punaro_app; REVOKE CONNECT ON DATABASE punaro_other FROM punaro_app`); err != nil {
		_ = pairDB.Close()
		t.Fatalf("auxiliary pair cleanup failed: %v", err)
	}
	if err := pairDB.Close(); err != nil {
		t.Fatal(err)
	}

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

	testV5UpdateBridgeIntegration(ctx, t, ownerDB, ownerFile, appFile)

	app, err = OpenApplication(ctx, Config{DSNFile: appFile})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()
	if _, err := ownerDB.ExecContext(ctx, `ALTER FUNCTION jobs.maintenance_active() PARALLEL SAFE`); err != nil {
		t.Fatal(err)
	}
	if drifted, driftErr := app.SchemaState(ctx); driftErr != nil || drifted.Classification != Incompatible {
		t.Fatalf("drifted update routine state=%#v err=%v", drifted, driftErr)
	}
	if _, err := ownerDB.ExecContext(ctx, `ALTER FUNCTION jobs.maintenance_active() PARALLEL UNSAFE`); err != nil {
		t.Fatal(err)
	}
	var phaseConstraint string
	if err := ownerDB.QueryRowContext(ctx, `SELECT conname FROM pg_constraint WHERE conrelid='jobs.update_transactions'::regclass AND contype='c' AND conkey=ARRAY[18]::smallint[]`).Scan(&phaseConstraint); err != nil {
		t.Fatal(err)
	}
	quotedConstraint := `"` + strings.ReplaceAll(phaseConstraint, `"`, `""`) + `"`
	if _, err := ownerDB.ExecContext(ctx, `ALTER TABLE jobs.update_transactions DROP CONSTRAINT `+quotedConstraint+`; ALTER TABLE jobs.update_transactions ADD CONSTRAINT `+quotedConstraint+` CHECK (phase IS NOT NULL)`); err != nil { // #nosec G202 -- identifier is read from PostgreSQL and quoted.
		t.Fatal(err)
	}
	if drifted, driftErr := app.SchemaState(ctx); driftErr != nil || drifted.Classification != Incompatible {
		t.Fatalf("permissive update constraint state=%#v err=%v", drifted, driftErr)
	}
	if _, err := ownerDB.ExecContext(ctx, `ALTER TABLE jobs.update_transactions DROP CONSTRAINT `+quotedConstraint+`; ALTER TABLE jobs.update_transactions ADD CONSTRAINT `+quotedConstraint+` CHECK (phase IN ('fenced','writers_stopped','backup_verified','migration_started','migrated','candidate_ready','doctor_passed','config_published','recovery_required','recovery_ready','recovery_doctor_passed','recovery_config_published','committed','recovered','aborted'))`); err != nil { // #nosec G202 -- identifier is read from PostgreSQL and quoted.
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err != nil {
		t.Fatalf("migrated application not ready: %v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `ALTER TABLE relay.mail_messages DISABLE TRIGGER mail_messages_mutation_guard`); err != nil {
		t.Fatal(err)
	}
	if drifted, driftErr := app.SchemaState(ctx); driftErr != nil || drifted.Classification != Incompatible {
		t.Fatalf("disabled relay mutation guard state=%#v err=%v", drifted, driftErr)
	}
	if _, err := ownerDB.ExecContext(ctx, `ALTER TABLE relay.mail_messages ENABLE TRIGGER mail_messages_mutation_guard`); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err != nil {
		t.Fatalf("relay guard restoration did not recover readiness: %v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `DROP TRIGGER mail_messages_mutation_guard ON relay.mail_messages; CREATE TRIGGER mail_messages_mutation_guard BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_messages FOR EACH STATEMENT WHEN (false) EXECUTE FUNCTION relay.guard_mail_mutation()`); err != nil {
		t.Fatal(err)
	}
	if drifted, driftErr := app.SchemaState(ctx); driftErr != nil || drifted.Classification != Incompatible {
		t.Fatalf("conditional relay mutation guard state=%#v err=%v", drifted, driftErr)
	}
	if _, err := ownerDB.ExecContext(ctx, `DROP TRIGGER mail_messages_mutation_guard ON relay.mail_messages; CREATE TRIGGER mail_messages_mutation_guard BEFORE INSERT OR UPDATE OR DELETE ON relay.mail_messages FOR EACH STATEMENT EXECUTE FUNCTION relay.guard_mail_mutation()`); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err != nil {
		t.Fatalf("unconditional relay guard restoration did not recover readiness: %v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `ALTER TABLE relay.mail_cutover_epochs DROP CONSTRAINT mail_cutover_epochs_phase_check; ALTER TABLE relay.mail_cutover_epochs ADD CONSTRAINT mail_cutover_epochs_phase_check CHECK (phase IS NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if drifted, driftErr := app.SchemaState(ctx); driftErr != nil || drifted.Classification != Incompatible {
		t.Fatalf("permissive mail-cutover phase constraint state=%#v err=%v", drifted, driftErr)
	}
	if _, err := ownerDB.ExecContext(ctx, `ALTER TABLE relay.mail_cutover_epochs DROP CONSTRAINT mail_cutover_epochs_phase_check; ALTER TABLE relay.mail_cutover_epochs ADD CONSTRAINT mail_cutover_epochs_phase_check CHECK (phase IN ('importing','verified','active','aborted'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `DROP INDEX relay.mail_cutover_epochs_one_authority; CREATE UNIQUE INDEX mail_cutover_epochs_one_authority ON relay.mail_cutover_epochs ((true)) WHERE phase='importing'`); err != nil {
		t.Fatal(err)
	}
	if drifted, driftErr := app.SchemaState(ctx); driftErr != nil || drifted.Classification != Incompatible {
		t.Fatalf("weakened mail-cutover authority index state=%#v err=%v", drifted, driftErr)
	}
	if _, err := ownerDB.ExecContext(ctx, `DROP INDEX relay.mail_cutover_epochs_one_authority; CREATE UNIQUE INDEX mail_cutover_epochs_one_authority ON relay.mail_cutover_epochs ((true)) WHERE phase IN ('importing','verified','active')`); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `GRANT SELECT ON relay.mail_cutover_staging TO PUBLIC`); err != nil {
		t.Fatal(err)
	}
	if drifted, driftErr := app.SchemaState(ctx); driftErr != nil || drifted.Classification != Incompatible {
		t.Fatalf("mail-cutover extra grantee state=%#v err=%v", drifted, driftErr)
	}
	if _, err := ownerDB.ExecContext(ctx, `REVOKE SELECT ON relay.mail_cutover_staging FROM PUBLIC`); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `ALTER TABLE relay.mail_cutover_epochs ADD CONSTRAINT mail_cutover_epochs_unexpected_unique UNIQUE(epoch_id,source_id) DEFERRABLE`); err != nil {
		t.Fatal(err)
	}
	if drifted, driftErr := app.SchemaState(ctx); driftErr != nil || drifted.Classification != Incompatible {
		t.Fatalf("mail-cutover extra constraint state=%#v err=%v", drifted, driftErr)
	}
	if _, err := ownerDB.ExecContext(ctx, `ALTER TABLE relay.mail_cutover_epochs DROP CONSTRAINT mail_cutover_epochs_unexpected_unique`); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `CREATE TRIGGER mail_endpoints_unexpected_guard BEFORE INSERT ON relay.mail_endpoints FOR EACH STATEMENT EXECUTE FUNCTION relay.guard_mail_mutation()`); err != nil {
		t.Fatal(err)
	}
	if drifted, driftErr := app.SchemaState(ctx); driftErr != nil || drifted.Classification != Incompatible {
		t.Fatalf("mail-cutover extra trigger state=%#v err=%v", drifted, driftErr)
	}
	if _, err := ownerDB.ExecContext(ctx, `DROP TRIGGER mail_endpoints_unexpected_guard ON relay.mail_endpoints`); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err != nil {
		t.Fatalf("mail-cutover catalog restoration did not recover readiness: %v", err)
	}
	var nonceDefinition string
	if err := ownerDB.QueryRowContext(ctx, `SELECT pg_get_functiondef('relay.consume_mail_request_nonce(text,text,timestamptz,timestamptz)'::regprocedure)`).Scan(&nonceDefinition); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `CREATE OR REPLACE FUNCTION relay.consume_mail_request_nonce(requested_machine_id text,requested_nonce text,requested_now timestamptz,requested_expires_at timestamptz)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$ BEGIN RETURN true; END $function$`); err != nil {
		t.Fatal(err)
	}
	if drifted, driftErr := app.SchemaState(ctx); driftErr != nil || drifted.Classification != Incompatible {
		t.Fatalf("permissive relay nonce routine state=%#v err=%v", drifted, driftErr)
	}
	if _, err := ownerDB.ExecContext(ctx, nonceDefinition); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err != nil {
		t.Fatalf("relay nonce routine restoration did not recover readiness: %v", err)
	}
	var bodyConstraint string
	if err := ownerDB.QueryRowContext(ctx, `SELECT conname FROM pg_constraint WHERE conrelid='relay.mail_messages'::regclass AND contype='c' AND conkey=ARRAY[5]::smallint[]`).Scan(&bodyConstraint); err != nil {
		t.Fatal(err)
	}
	quotedBodyConstraint := `"` + strings.ReplaceAll(bodyConstraint, `"`, `""`) + `"`
	if _, err := ownerDB.ExecContext(ctx, `ALTER TABLE relay.mail_messages DROP CONSTRAINT `+quotedBodyConstraint+`; ALTER TABLE relay.mail_messages ADD CONSTRAINT `+quotedBodyConstraint+` CHECK (body IS NOT NULL)`); err != nil { // #nosec G202 -- catalog identifier is quoted.
		t.Fatal(err)
	}
	if drifted, driftErr := app.SchemaState(ctx); driftErr != nil || drifted.Classification != Incompatible {
		t.Fatalf("permissive relay body constraint state=%#v err=%v", drifted, driftErr)
	}
	if _, err := ownerDB.ExecContext(ctx, `ALTER TABLE relay.mail_messages DROP CONSTRAINT `+quotedBodyConstraint+`; ALTER TABLE relay.mail_messages ADD CONSTRAINT `+quotedBodyConstraint+` CHECK (octet_length(body) <= 32768)`); err != nil { // #nosec G202 -- catalog identifier is quoted.
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `GRANT SELECT ON relay.mail_messages TO pg_monitor`); err != nil {
		t.Fatal(err)
	}
	if drifted, driftErr := app.SchemaState(ctx); driftErr != nil || drifted.Classification != Incompatible {
		t.Fatalf("extra relay table grantee state=%#v err=%v", drifted, driftErr)
	}
	if _, err := ownerDB.ExecContext(ctx, `REVOKE SELECT ON relay.mail_messages FROM pg_monitor`); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `GRANT SELECT ON relay.mail_messages TO PUBLIC`); err != nil {
		t.Fatal(err)
	}
	if drifted, driftErr := app.SchemaState(ctx); driftErr != nil || drifted.Classification != Incompatible {
		t.Fatalf("public relay table grant state=%#v err=%v", drifted, driftErr)
	}
	if _, err := ownerDB.ExecContext(ctx, `REVOKE SELECT ON relay.mail_messages FROM PUBLIC`); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `GRANT UPDATE (body) ON relay.mail_messages TO punaro_app`); err != nil {
		t.Fatal(err)
	}
	if drifted, driftErr := app.SchemaState(ctx); driftErr != nil || drifted.Classification != Incompatible {
		t.Fatalf("extra relay column privilege state=%#v err=%v", drifted, driftErr)
	}
	if _, err := ownerDB.ExecContext(ctx, `REVOKE UPDATE (body) ON relay.mail_messages FROM punaro_app`); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `REVOKE INSERT ON relay.mail_messages FROM punaro_app`); err != nil {
		t.Fatal(err)
	}
	if drifted, driftErr := app.SchemaState(ctx); driftErr != nil || drifted.Classification != Incompatible {
		t.Fatalf("missing relay insert privilege state=%#v err=%v", drifted, driftErr)
	}
	if _, err := ownerDB.ExecContext(ctx, `GRANT INSERT ON relay.mail_messages TO punaro_app`); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err != nil {
		t.Fatalf("relay constraint and ACL restoration did not recover readiness: %v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `ALTER TABLE attachment.uploads DROP CONSTRAINT uploads_size_bytes_check; ALTER TABLE attachment.uploads ADD CONSTRAINT uploads_size_bytes_check CHECK (size_bytes > 0)`); err != nil {
		t.Fatal(err)
	}
	if drifted, driftErr := app.SchemaState(ctx); driftErr != nil || drifted.Classification != Incompatible {
		t.Fatalf("permissive trusted-attachment size constraint state=%#v err=%v", drifted, driftErr)
	}
	if _, err := ownerDB.ExecContext(ctx, `ALTER TABLE attachment.uploads DROP CONSTRAINT uploads_size_bytes_check; ALTER TABLE attachment.uploads ADD CONSTRAINT uploads_size_bytes_check CHECK (size_bytes BETWEEN 1 AND 17179869184)`); err != nil {
		t.Fatal(err)
	}
	var reserveDefinition string
	if err := ownerDB.QueryRowContext(ctx, `SELECT pg_get_functiondef('attachment.reserve_upload(uuid,uuid,uuid,bytea,bigint,text,text,text,interval)'::regprocedure)`).Scan(&reserveDefinition); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `CREATE OR REPLACE FUNCTION attachment.reserve_upload(requested_principal uuid,requested_project uuid,request_key uuid,request_hash bytea,requested_size bigint,requested_sha256 text,requested_display_name text,requested_media_type text,requested_lifetime interval) RETURNS TABLE (artifact_id uuid,project_id uuid,principal_id uuid,timeline_id uuid,size_bytes bigint,sha256 text,display_name text,media_type text,state text,attempt_generation bigint,expires_at timestamptz,ready_at timestamptz) LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS 'SELECT NULL::uuid,NULL::uuid,NULL::uuid,NULL::uuid,1::bigint,repeat(''0'',64),'''',''application/octet-stream'',''reserved'',0::bigint,statement_timestamp(),NULL::timestamptz'`); err != nil {
		t.Fatal(err)
	}
	if drifted, driftErr := app.SchemaState(ctx); driftErr != nil || drifted.Classification != Incompatible {
		t.Fatalf("permissive trusted-attachment routine state=%#v err=%v", drifted, driftErr)
	}
	if _, err := ownerDB.ExecContext(ctx, reserveDefinition); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `GRANT SELECT ON attachment.uploads TO punaro_app`); err != nil {
		t.Fatal(err)
	}
	if drifted, driftErr := app.SchemaState(ctx); driftErr != nil || drifted.Classification != Incompatible {
		t.Fatalf("trusted-attachment direct read grant state=%#v err=%v", drifted, driftErr)
	}
	if _, err := ownerDB.ExecContext(ctx, `REVOKE SELECT ON attachment.uploads FROM punaro_app`); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err != nil {
		t.Fatalf("trusted-attachment catalog restoration did not recover readiness: %v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `ALTER TABLE attachment.deletions DROP CONSTRAINT deletions_lifecycle_check; ALTER TABLE attachment.deletions ADD CONSTRAINT deletions_lifecycle_check CHECK (state IS NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if drifted, driftErr := app.SchemaState(ctx); driftErr != nil || drifted.Classification != Incompatible {
		t.Fatalf("permissive attachment-deletion lifecycle state=%#v err=%v", drifted, driftErr)
	}
	if _, err := ownerDB.ExecContext(ctx, `ALTER TABLE attachment.deletions DROP CONSTRAINT deletions_lifecycle_check; ALTER TABLE attachment.deletions ADD CONSTRAINT deletions_lifecycle_check CHECK ((state = 'tombstoned' AND gc_token IS NULL AND gc_lease_until IS NULL AND deleted_at IS NULL) OR (state = 'gc_claimed' AND gc_token IS NOT NULL AND gc_lease_until IS NOT NULL AND deleted_at IS NULL) OR (state = 'deleted' AND gc_token IS NOT NULL AND gc_lease_until IS NULL AND deleted_at IS NOT NULL))`); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `DROP INDEX attachment.deletions_gc_order; CREATE INDEX deletions_gc_order ON attachment.deletions (gc_after,state,artifact_id)`); err != nil {
		t.Fatal(err)
	}
	if drifted, driftErr := app.SchemaState(ctx); driftErr != nil || drifted.Classification != Incompatible {
		t.Fatalf("attachment-deletion GC index drift state=%#v err=%v", drifted, driftErr)
	}
	if _, err := ownerDB.ExecContext(ctx, `DROP INDEX attachment.deletions_gc_order; CREATE INDEX deletions_gc_order ON attachment.deletions (state,gc_after,artifact_id)`); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `GRANT SELECT ON attachment.deletions TO punaro_app`); err != nil {
		t.Fatal(err)
	}
	if drifted, driftErr := app.SchemaState(ctx); driftErr != nil || drifted.Classification != Incompatible {
		t.Fatalf("attachment-deletion direct read grant state=%#v err=%v", drifted, driftErr)
	}
	if _, err := ownerDB.ExecContext(ctx, `REVOKE SELECT ON attachment.deletions FROM punaro_app`); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err != nil {
		t.Fatalf("attachment-deletion catalog restoration did not recover readiness: %v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `ALTER TABLE attachment.endpoint_principals DROP CONSTRAINT endpoint_principals_credential_generation_check; ALTER TABLE attachment.endpoint_principals ADD CONSTRAINT endpoint_principals_credential_generation_check CHECK (credential_generation >= 1 OR true)`); err != nil {
		t.Fatal(err)
	}
	if drifted, driftErr := app.SchemaState(ctx); driftErr != nil || drifted.Classification != Incompatible {
		t.Fatalf("permissive recipient credential-generation constraint state=%#v err=%v", drifted, driftErr)
	}
	if _, err := ownerDB.ExecContext(ctx, `ALTER TABLE attachment.endpoint_principals DROP CONSTRAINT endpoint_principals_credential_generation_check; ALTER TABLE attachment.endpoint_principals ADD CONSTRAINT endpoint_principals_credential_generation_check CHECK (credential_generation >= 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `DROP INDEX attachment.recipient_grants_principal; CREATE INDEX recipient_grants_principal ON attachment.recipient_grants (artifact_id,recipient_principal_id)`); err != nil {
		t.Fatal(err)
	}
	if drifted, driftErr := app.SchemaState(ctx); driftErr != nil || drifted.Classification != Incompatible {
		t.Fatalf("recipient grant lookup index drift state=%#v err=%v", drifted, driftErr)
	}
	if _, err := ownerDB.ExecContext(ctx, `DROP INDEX attachment.recipient_grants_principal; CREATE INDEX recipient_grants_principal ON attachment.recipient_grants (recipient_principal_id,artifact_id)`); err != nil {
		t.Fatal(err)
	}
	var downloadDefinition string
	if err := ownerDB.QueryRowContext(ctx, `SELECT pg_get_functiondef('attachment.authorize_download(uuid,uuid,bigint,uuid)'::regprocedure)`).Scan(&downloadDefinition); err != nil {
		t.Fatal(err)
	}
	driftedDownloadDefinition := strings.Replace(downloadDefinition, "TABLE(artifact_id uuid", "TABLE(wrong_artifact_id uuid", 1)
	if driftedDownloadDefinition == downloadDefinition {
		t.Fatal("download function definition did not expose the expected TABLE result signature")
	}
	if _, err := ownerDB.ExecContext(ctx, `DROP FUNCTION attachment.authorize_download(uuid,uuid,bigint,uuid)`); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, driftedDownloadDefinition); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `REVOKE ALL ON FUNCTION attachment.authorize_download(uuid,uuid,bigint,uuid) FROM PUBLIC; GRANT EXECUTE ON FUNCTION attachment.authorize_download(uuid,uuid,bigint,uuid) TO punaro_app`); err != nil {
		t.Fatal(err)
	}
	if drifted, driftErr := app.SchemaState(ctx); driftErr != nil || drifted.Classification != Incompatible {
		t.Fatalf("attachment download result-signature drift state=%#v err=%v", drifted, driftErr)
	}
	if _, err := ownerDB.ExecContext(ctx, `DROP FUNCTION attachment.authorize_download(uuid,uuid,bigint,uuid)`); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, downloadDefinition); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `REVOKE ALL ON FUNCTION attachment.authorize_download(uuid,uuid,bigint,uuid) FROM PUBLIC; GRANT EXECUTE ON FUNCTION attachment.authorize_download(uuid,uuid,bigint,uuid) TO punaro_app`); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err != nil {
		t.Fatalf("attachment-recipient catalog restoration did not recover readiness: %v", err)
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
	testTrustedAttachmentIntegration(ctx, t, app, ownerDB)
	testProjectIdentityIntegration(ctx, t, app, ownerDB)
	testCanonicalBrainSchemaDriftIntegration(ctx, t, app, ownerDB)
	testSecretGuardSchemaDriftIntegration(ctx, t, app, ownerDB)
	testMemoryQuarantineSchemaDriftIntegration(ctx, t, app, ownerDB)
	testMemoryEvidenceSchemaDriftIntegration(ctx, t, app, ownerDB)
	testMemoryProposalSchemaDriftIntegration(ctx, t, app, ownerDB)
	testMemoryLexicalSchemaDriftIntegration(ctx, t, app, ownerDB)
	testMemoryUsageSchemaDriftIntegration(ctx, t, app, ownerDB)
	testCanonicalBrainIntegration(ctx, t, app, ownerDB)
	testMemoryLexicalSearchIntegration(ctx, t, app, ownerDB)
	testMemoryPromptBriefIntegration(ctx, t, app, ownerDB)
	testMemoryDuplicateDetectionIntegration(ctx, t, app, ownerDB)
	testMemoryUsageAndArchiveCandidatesIntegration(ctx, t, app, ownerDB)
	testMemoryEvidenceIntegration(ctx, t, app, ownerDB)
	testMemoryProposalIntegration(ctx, t, app, ownerDB)
	testBackupRestoreIntegration(ctx, t, app, ownerDB, ownerFile, appFile)
	testTransactionalUpdateFenceIntegration(ctx, t, app, ownerDB)
	testMailCutoverSubstrate(ctx, t, app, ownerDB)
	testRelayIntegration(t, app)
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
		{name: "enrollment invalidation update", apply: `REVOKE UPDATE (invalidated_at) ON auth.pending_enrollments FROM punaro_app`, restore: `GRANT UPDATE (invalidated_at) ON auth.pending_enrollments TO punaro_app`},
		{name: "enrollment invalidation trigger", apply: `ALTER TABLE auth.pending_enrollments DISABLE TRIGGER pending_enrollment_invalidation_guard`, restore: `ALTER TABLE auth.pending_enrollments ENABLE TRIGGER pending_enrollment_invalidation_guard`},
		{name: "credential secret update privilege", apply: `GRANT UPDATE (secret_digest) ON auth.device_credentials TO punaro_app`, restore: `REVOKE UPDATE (secret_digest) ON auth.device_credentials FROM punaro_app`},
		{name: "credential expiry update privilege", apply: `GRANT UPDATE (expires_at) ON auth.device_credentials TO punaro_app`, restore: `REVOKE UPDATE (expires_at) ON auth.device_credentials FROM punaro_app`},
		{name: "credential principal column references", apply: `GRANT REFERENCES (principal_id) ON auth.device_credentials TO punaro_app`, restore: `REVOKE REFERENCES (principal_id) ON auth.device_credentials FROM punaro_app`},
		{name: "legacy enabled column update", apply: `GRANT UPDATE (enabled) ON auth.legacy_auth_state TO punaro_app`, restore: `REVOKE UPDATE (enabled) ON auth.legacy_auth_state FROM punaro_app`},
		{name: "legacy key column update", apply: `GRANT UPDATE (public_key) ON auth.legacy_machines TO punaro_app`, restore: `REVOKE UPDATE (public_key) ON auth.legacy_machines FROM punaro_app`},
		{name: "legacy exchange public execute", apply: `GRANT EXECUTE ON FUNCTION auth.complete_legacy_exchange(uuid, uuid) TO PUBLIC`, restore: `REVOKE EXECUTE ON FUNCTION auth.complete_legacy_exchange(uuid, uuid) FROM PUBLIC`},
		{name: "legacy exchange extra grantee", apply: `GRANT EXECUTE ON FUNCTION auth.complete_legacy_exchange(uuid, uuid) TO pg_monitor`, restore: `REVOKE EXECUTE ON FUNCTION auth.complete_legacy_exchange(uuid, uuid) FROM pg_monitor`},
		{name: "legacy exchange delegated grant", apply: `GRANT EXECUTE ON FUNCTION auth.complete_legacy_exchange(uuid, uuid) TO punaro_app WITH GRANT OPTION`, restore: `REVOKE GRANT OPTION FOR EXECUTE ON FUNCTION auth.complete_legacy_exchange(uuid, uuid) FROM punaro_app`},
		{name: "legacy exchange search path", apply: `ALTER FUNCTION auth.complete_legacy_exchange(uuid, uuid) RESET ALL`, restore: `ALTER FUNCTION auth.complete_legacy_exchange(uuid, uuid) SET search_path = pg_catalog`},
		{name: "pending binding index uniqueness", apply: `DROP INDEX auth.pending_enrollments_active_binding; CREATE UNIQUE INDEX pending_enrollments_active_binding ON auth.pending_enrollments (client_binding) WHERE redeemed_at IS NULL AND invalidated_at IS NULL`, restore: `DROP INDEX auth.pending_enrollments_active_binding; CREATE INDEX pending_enrollments_active_binding ON auth.pending_enrollments (client_binding) WHERE redeemed_at IS NULL AND invalidated_at IS NULL`},
		{name: "credential digest index", apply: `DROP INDEX auth.device_credentials_secret_digest`, restore: `CREATE UNIQUE INDEX device_credentials_secret_digest ON auth.device_credentials (secret_digest)`},
		{name: "credential generation constraint", apply: `ALTER TABLE auth.device_credentials DROP CONSTRAINT device_credentials_generation_check`, restore: `ALTER TABLE auth.device_credentials ADD CONSTRAINT device_credentials_generation_check CHECK (generation >= 1)`},
		{name: "permissive credential generation constraint", apply: `ALTER TABLE auth.device_credentials DROP CONSTRAINT device_credentials_generation_check; ALTER TABLE auth.device_credentials ADD CONSTRAINT device_credentials_generation_check CHECK (generation >= 1 OR true)`, restore: `ALTER TABLE auth.device_credentials DROP CONSTRAINT device_credentials_generation_check; ALTER TABLE auth.device_credentials ADD CONSTRAINT device_credentials_generation_check CHECK (generation >= 1)`},
		{name: "permissive credential expiry constraint", apply: `ALTER TABLE auth.device_credentials DROP CONSTRAINT device_credentials_check; ALTER TABLE auth.device_credentials ADD CONSTRAINT device_credentials_check CHECK (expires_at IS NULL OR expires_at > created_at OR true)`, restore: `ALTER TABLE auth.device_credentials DROP CONSTRAINT device_credentials_check; ALTER TABLE auth.device_credentials ADD CONSTRAINT device_credentials_check CHECK (expires_at IS NULL OR expires_at > created_at)`},
		{name: "principal auth generation constraint", apply: `ALTER TABLE auth.principals DROP CONSTRAINT principals_auth_generation_check`, restore: `ALTER TABLE auth.principals ADD CONSTRAINT principals_auth_generation_check CHECK (auth_generation >= 0)`},
		{name: "permissive principal auth generation constraint", apply: `ALTER TABLE auth.principals DROP CONSTRAINT principals_auth_generation_check; ALTER TABLE auth.principals ADD CONSTRAINT principals_auth_generation_check CHECK (auth_generation >= 0 OR true)`, restore: `ALTER TABLE auth.principals DROP CONSTRAINT principals_auth_generation_check; ALTER TABLE auth.principals ADD CONSTRAINT principals_auth_generation_check CHECK (auth_generation >= 0)`},
		{name: "audit action value set", apply: `ALTER TABLE audit.events DROP CONSTRAINT events_action_check; ALTER TABLE audit.events ADD CONSTRAINT events_action_check CHECK (action IN ('principal.create', 'project.create', 'grant.create', 'grant.delete', 'job.enqueue', 'job.complete', 'job.retry', 'job.fail', 'owner.bootstrap', 'enrollment.create', 'enrollment.redeem', 'credential.rotate', 'credential.revoke', 'legacy.register', 'legacy.exchange', 'legacy.retire', 'legacy.disable', 'project.identity.attach', 'project.merge.preview', 'project.merge', 'memory.create', 'memory.evidence_create', 'memory.update', 'memory.archive', 'memory.restore', 'memory.delete', 'memory.secret_exception.create', 'memory.secret_exception.revoke', 'memory.secret_rescan', 'memory.quarantine', 'memory.quarantine_release', 'memory.proposal.create', 'memory.proposal.approve', 'memory.proposal.reject', 'memory.proposal.expire', 'memory.proposal.prune', 'unexpected'))`, restore: `ALTER TABLE audit.events DROP CONSTRAINT events_action_check; ALTER TABLE audit.events ADD CONSTRAINT events_action_check CHECK (action IN ('principal.create', 'project.create', 'grant.create', 'grant.delete', 'job.enqueue', 'job.complete', 'job.retry', 'job.fail', 'owner.bootstrap', 'enrollment.create', 'enrollment.redeem', 'credential.rotate', 'credential.revoke', 'legacy.register', 'legacy.exchange', 'legacy.retire', 'legacy.disable', 'project.identity.attach', 'project.merge.preview', 'project.merge', 'memory.create', 'memory.evidence_create', 'memory.update', 'memory.archive', 'memory.restore', 'memory.delete', 'memory.secret_exception.create', 'memory.secret_exception.revoke', 'memory.secret_rescan', 'memory.quarantine', 'memory.quarantine_release', 'memory.proposal.create', 'memory.proposal.approve', 'memory.proposal.reject', 'memory.proposal.expire', 'memory.proposal.prune'))`},
		{name: "permissive audit action constraint", apply: `ALTER TABLE audit.events DROP CONSTRAINT events_action_check; ALTER TABLE audit.events ADD CONSTRAINT events_action_check CHECK (action IN ('principal.create', 'project.create', 'grant.create', 'grant.delete', 'job.enqueue', 'job.complete', 'job.retry', 'job.fail', 'owner.bootstrap', 'enrollment.create', 'enrollment.redeem', 'credential.rotate', 'credential.revoke', 'legacy.register', 'legacy.exchange', 'legacy.retire', 'legacy.disable', 'project.identity.attach', 'project.merge.preview', 'project.merge', 'memory.create', 'memory.evidence_create', 'memory.update', 'memory.archive', 'memory.restore', 'memory.delete', 'memory.secret_exception.create', 'memory.secret_exception.revoke', 'memory.secret_rescan', 'memory.quarantine', 'memory.quarantine_release', 'memory.proposal.create', 'memory.proposal.approve', 'memory.proposal.reject', 'memory.proposal.expire', 'memory.proposal.prune') OR true)`, restore: `ALTER TABLE audit.events DROP CONSTRAINT events_action_check; ALTER TABLE audit.events ADD CONSTRAINT events_action_check CHECK (action IN ('principal.create', 'project.create', 'grant.create', 'grant.delete', 'job.enqueue', 'job.complete', 'job.retry', 'job.fail', 'owner.bootstrap', 'enrollment.create', 'enrollment.redeem', 'credential.rotate', 'credential.revoke', 'legacy.register', 'legacy.exchange', 'legacy.retire', 'legacy.disable', 'project.identity.attach', 'project.merge.preview', 'project.merge', 'memory.create', 'memory.evidence_create', 'memory.update', 'memory.archive', 'memory.restore', 'memory.delete', 'memory.secret_exception.create', 'memory.secret_exception.revoke', 'memory.secret_rescan', 'memory.quarantine', 'memory.quarantine_release', 'memory.proposal.create', 'memory.proposal.approve', 'memory.proposal.reject', 'memory.proposal.expire', 'memory.proposal.prune'))`},
		{name: "audit target value set", apply: `ALTER TABLE audit.events DROP CONSTRAINT events_target_kind_check; ALTER TABLE audit.events ADD CONSTRAINT events_target_kind_check CHECK (target_kind IN ('principal', 'project', 'grant', 'job', 'enrollment', 'credential', 'legacy_machine', 'project_identity', 'project_merge', 'memory_item', 'memory_proposal', 'unexpected'))`, restore: `ALTER TABLE audit.events DROP CONSTRAINT events_target_kind_check; ALTER TABLE audit.events ADD CONSTRAINT events_target_kind_check CHECK (target_kind IN ('principal', 'project', 'grant', 'job', 'enrollment', 'credential', 'legacy_machine', 'project_identity', 'project_merge', 'memory_item', 'memory_proposal'))`},
		{name: "permissive audit target constraint", apply: `ALTER TABLE audit.events DROP CONSTRAINT events_target_kind_check; ALTER TABLE audit.events ADD CONSTRAINT events_target_kind_check CHECK (target_kind IN ('principal', 'project', 'grant', 'job', 'enrollment', 'credential', 'legacy_machine', 'project_identity', 'project_merge', 'memory_item', 'memory_proposal') OR true)`, restore: `ALTER TABLE audit.events DROP CONSTRAINT events_target_kind_check; ALTER TABLE audit.events ADD CONSTRAINT events_target_kind_check CHECK (target_kind IN ('principal', 'project', 'grant', 'job', 'enrollment', 'credential', 'legacy_machine', 'project_identity', 'project_merge', 'memory_item', 'memory_proposal'))`},
		{name: "legacy machine state value set", apply: `ALTER TABLE auth.legacy_machines DROP CONSTRAINT legacy_machines_state_check; ALTER TABLE auth.legacy_machines ADD CONSTRAINT legacy_machines_state_check CHECK (state IN ('pending', 'migrated', 'retired', 'unexpected'))`, restore: `ALTER TABLE auth.legacy_machines DROP CONSTRAINT legacy_machines_state_check; ALTER TABLE auth.legacy_machines ADD CONSTRAINT legacy_machines_state_check CHECK (state IN ('pending', 'migrated', 'retired'))`},
		{name: "project identity lookup index", apply: `DROP INDEX relay.project_identities_project`, restore: `CREATE INDEX project_identities_project ON relay.project_identities (project_id, id)`},
		{name: "preview prune index expression", apply: `DROP INDEX relay.project_merge_previews_prune; CREATE INDEX project_merge_previews_prune ON relay.project_merge_previews (COALESCE(created_at, expires_at), id)`, restore: `DROP INDEX relay.project_merge_previews_prune; CREATE INDEX project_merge_previews_prune ON relay.project_merge_previews (COALESCE(consumed_at, expires_at), id)`},
		{name: "identity locator update privilege", apply: `GRANT UPDATE (normalized_locator) ON relay.project_identities TO punaro_app`, restore: `REVOKE UPDATE (normalized_locator) ON relay.project_identities FROM punaro_app`},
		{name: "preview actor update privilege", apply: `GRANT UPDATE (actor_principal_id) ON relay.project_merge_previews TO punaro_app`, restore: `REVOKE UPDATE (actor_principal_id) ON relay.project_merge_previews FROM punaro_app`},
		{name: "project broad update privilege", apply: `GRANT UPDATE ON relay.projects TO punaro_app`, restore: `REVOKE UPDATE ON relay.projects FROM punaro_app; GRANT UPDATE (identity_generation, acl_generation, content_generation, merged_into, merged_at) ON relay.projects TO punaro_app`},
		{name: "project broad insert privilege", apply: `GRANT INSERT ON relay.projects TO punaro_app`, restore: `REVOKE INSERT ON relay.projects FROM punaro_app; GRANT INSERT (display_name, created_by) ON relay.projects TO punaro_app`},
		{name: "global ACL constraint", apply: `ALTER TABLE auth.project_acl_state DROP CONSTRAINT project_acl_state_global_generation_check`, restore: `ALTER TABLE auth.project_acl_state ADD CONSTRAINT project_acl_state_global_generation_check CHECK (global_generation >= 0)`},
		{name: "project content generation constraint", apply: `ALTER TABLE relay.projects DROP CONSTRAINT projects_content_generation_check`, restore: `ALTER TABLE relay.projects ADD CONSTRAINT projects_content_generation_check CHECK (content_generation >= 0)`},
		{name: "identity locator bound", apply: `ALTER TABLE relay.project_identities DROP CONSTRAINT project_identities_locator_max_check`, restore: `ALTER TABLE relay.project_identities ADD CONSTRAINT project_identities_locator_max_check CHECK (char_length(normalized_locator) <= 2048)`},
		{name: "preview identity count bound", apply: `ALTER TABLE relay.project_merge_previews DROP CONSTRAINT project_merge_previews_identity_count_max_check`, restore: `ALTER TABLE relay.project_merge_previews ADD CONSTRAINT project_merge_previews_identity_count_max_check CHECK (identity_count <= 100)`},
		{name: "preview result bound", apply: `ALTER TABLE relay.project_merge_previews DROP CONSTRAINT project_merge_previews_result_check`, restore: `ALTER TABLE relay.project_merge_previews ADD CONSTRAINT project_merge_previews_result_check CHECK (result IS NULL OR octet_length(result::text) <= 4096)`},
		{name: "preview consumption integrity", apply: `ALTER TABLE relay.project_merge_previews DROP CONSTRAINT project_merge_previews_consumption_check`, restore: `ALTER TABLE relay.project_merge_previews ADD CONSTRAINT project_merge_previews_consumption_check CHECK ((consumed_at IS NULL AND result IS NULL) OR (consumed_at IS NOT NULL AND result IS NOT NULL))`},
		{name: "alias canonical foreign key replacement", apply: `ALTER TABLE relay.project_lookup_aliases DROP CONSTRAINT project_lookup_aliases_canonical_project_id_fkey; ALTER TABLE relay.project_lookup_aliases ADD CONSTRAINT project_lookup_aliases_canonical_project_id_replacement_fkey FOREIGN KEY (alias_project_id) REFERENCES relay.projects(id)`, restore: `ALTER TABLE relay.project_lookup_aliases DROP CONSTRAINT project_lookup_aliases_canonical_project_id_replacement_fkey; ALTER TABLE relay.project_lookup_aliases ADD CONSTRAINT project_lookup_aliases_canonical_project_id_fkey FOREIGN KEY (canonical_project_id) REFERENCES relay.projects(id)`},
		{name: "preview identity foreign key replacement", apply: `ALTER TABLE relay.project_merge_previews DROP CONSTRAINT project_merge_previews_identity_id_fkey; ALTER TABLE relay.project_merge_previews ADD CONSTRAINT project_merge_previews_identity_id_replacement_fkey FOREIGN KEY (source_project_id) REFERENCES relay.projects(id)`, restore: `ALTER TABLE relay.project_merge_previews DROP CONSTRAINT project_merge_previews_identity_id_replacement_fkey; ALTER TABLE relay.project_merge_previews ADD CONSTRAINT project_merge_previews_identity_id_fkey FOREIGN KEY (identity_id) REFERENCES relay.project_identities(id)`},
		{name: "alias cascading foreign key", apply: `ALTER TABLE relay.project_lookup_aliases DROP CONSTRAINT project_lookup_aliases_canonical_project_id_fkey; ALTER TABLE relay.project_lookup_aliases ADD CONSTRAINT project_lookup_aliases_canonical_project_id_fkey FOREIGN KEY (canonical_project_id) REFERENCES relay.projects(id) ON DELETE CASCADE`, restore: `ALTER TABLE relay.project_lookup_aliases DROP CONSTRAINT project_lookup_aliases_canonical_project_id_fkey; ALTER TABLE relay.project_lookup_aliases ADD CONSTRAINT project_lookup_aliases_canonical_project_id_fkey FOREIGN KEY (canonical_project_id) REFERENCES relay.projects(id)`},
	} {
		t.Run("readiness rejects "+drift.name, func(t *testing.T) {
			if _, err := ownerDB.ExecContext(ctx, drift.apply); err != nil {
				t.Fatal(err)
			}
			driftErr := app.Ready(ctx)
			if _, err := ownerDB.ExecContext(ctx, drift.restore); err != nil {
				t.Fatal(err)
			}
			if driftErr == nil {
				t.Fatalf("readiness accepted %s drift", drift.name)
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
	if _, err := ownerDB.ExecContext(ctx, `DROP SCHEMA jobs CASCADE`); err != nil {
		t.Fatal(err)
	}
	ownerConn, err = ownerDB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	const missingRole = "punaro_guaranteed_missing_app"
	var missingRoleExists bool
	if err := ownerConn.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=$1)`, missingRole).Scan(&missingRoleExists); err != nil || missingRoleExists {
		_ = ownerConn.Close()
		t.Fatalf("missing-role fixture collision=%t err=%v", missingRoleExists, err)
	}
	if _, err := migrateConnExpectedAppRole(ctx, ownerConn, CurrentManifest(), missingRole, false); err == nil {
		_ = ownerConn.Close()
		t.Fatal("migrator accepted a missing application role")
	}
	if err := ownerConn.Close(); err != nil {
		t.Fatal(err)
	}
	var trackerExists bool
	if err := ownerDB.QueryRowContext(ctx, `SELECT to_regclass('jobs.schema_migrations') IS NOT NULL`).Scan(&trackerExists); err != nil || trackerExists {
		t.Fatalf("missing-role refusal mutated schema: tracker_exists=%t err=%v", trackerExists, err)
	}
}

func testMailCutoverSubstrate(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB) {
	t.Helper()
	admin := &Administration{db: ownerDB}
	var actor string
	if err := ownerDB.QueryRowContext(ctx, `SELECT principal_id::text FROM auth.installation_owner`).Scan(&actor); err != nil {
		t.Fatal(err)
	}
	targetIdentity, err := app.Identity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	request := MailCutoverRequest{
		EpochID:           "019f7f07-4b88-7c12-a394-b663274a6555",
		SourceID:          "019f7f07-5b88-7c12-a394-b663274a6555",
		TargetIdentity:    targetIdentity,
		SourceFingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	manifest := relay.MigrationSourceManifest{
		Version: 1, SourceID: request.SourceID, Phase: relay.MigrationSourcePrepared, EpochID: request.EpochID,
		TargetIdentity: request.TargetIdentity, Fingerprint: request.SourceFingerprint,
		TableSHA256: relay.MigrationSourceHashes{
			Endpoints: emptyMailCutoverDigest, Conversations: emptyMailCutoverDigest, Memberships: emptyMailCutoverDigest,
			Messages: emptyMailCutoverDigest, Deliveries: emptyMailCutoverDigest, RecipientCursors: emptyMailCutoverDigest,
			MessageIdempotency: emptyMailCutoverDigest, ConversationIdempotency: emptyMailCutoverDigest, RequestNonces: emptyMailCutoverDigest,
		},
	}
	canonicalManifest, _ := json.Marshal(manifest)
	request.Manifest, _ = json.MarshalIndent(manifest, "", "  ")
	manifestDigest := sha256.Sum256(canonicalManifest)
	request.ManifestSHA256 = hex.EncodeToString(manifestDigest[:])
	if _, err := admin.BeginMailCutover(ctx, uuid.NewString(), request); err == nil {
		t.Fatal("non-owner began mail cutover")
	}
	wrongTarget := request
	wrongTarget.TargetIdentity = strings.Repeat("f", 64)
	manifest.TargetIdentity = wrongTarget.TargetIdentity
	wrongCanonical, _ := json.Marshal(manifest)
	wrongTarget.Manifest = wrongCanonical
	wrongDigest := sha256.Sum256(wrongCanonical)
	wrongTarget.ManifestSHA256 = hex.EncodeToString(wrongDigest[:])
	if _, err := admin.BeginMailCutover(ctx, actor, wrongTarget); err == nil {
		t.Fatal("mail cutover accepted the wrong target identity")
	}
	manifest.TargetIdentity = request.TargetIdentity
	var rejectedEpochs int
	if err := ownerDB.QueryRowContext(ctx, `SELECT count(*) FROM relay.mail_cutover_epochs`).Scan(&rejectedEpochs); err != nil || rejectedEpochs != 0 {
		t.Fatalf("rejected cutover created epochs=%d err=%v", rejectedEpochs, err)
	}
	tombstoneRequest := request
	tombstoneRequest.EpochID = "019f7f07-3b88-7c12-a394-b663274a6555"
	tombstoneManifest := manifest
	tombstoneManifest.EpochID = tombstoneRequest.EpochID
	tombstoneCanonical, _ := json.Marshal(tombstoneManifest)
	tombstoneRequest.Manifest = tombstoneCanonical
	tombstoneDigest := sha256.Sum256(tombstoneCanonical)
	tombstoneRequest.ManifestSHA256 = hex.EncodeToString(tombstoneDigest[:])
	tombstone, err := admin.ReserveMailCutoverAbort(ctx, actor, tombstoneRequest)
	if err != nil || tombstone.Phase != MailCutoverAborted || !tombstone.AbortedAt.Valid {
		t.Fatalf("absent abort reservation=%#v err=%v", tombstone, err)
	}
	if repeated, err := admin.ReserveMailCutoverAbort(ctx, actor, tombstoneRequest); err != nil || !reflect.DeepEqual(repeated, tombstone) {
		t.Fatalf("repeated absent abort reservation=%#v err=%v", repeated, err)
	}
	if delayed, err := admin.BeginMailCutover(ctx, actor, tombstoneRequest); err != nil || delayed.Phase != MailCutoverAborted {
		t.Fatalf("delayed begin after abort reservation=%#v err=%v", delayed, err)
	}
	if err := admin.AbortMailCutover(ctx, actor, tombstoneRequest.EpochID, tombstoneRequest.SourceFingerprint); err != nil {
		t.Fatalf("reserved absent abort completion err=%v", err)
	}
	writer, err := app.relayPool().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.ExecContext(ctx, `INSERT INTO relay.mail_endpoints(endpoint,machine_id,lease_until) VALUES('agent/cutover/draining','cutover-draining-machine',statement_timestamp()+interval '1 minute')`); err != nil {
		_ = writer.Rollback()
		t.Fatal(err)
	}
	type beginResult struct {
		epoch MailCutoverEpoch
		err   error
	}
	beginDone := make(chan beginResult, 1)
	go func() {
		epoch, err := admin.BeginMailCutover(ctx, actor, request)
		beginDone <- beginResult{epoch: epoch, err: err}
	}()
	waitDeadline := time.Now().Add(2 * time.Second)
	for {
		var waiting bool
		if err := ownerDB.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE usename='punaro_owner' AND wait_event='advisory' AND query LIKE 'SELECT pg_advisory_xact_lock(%')`).Scan(&waiting); err != nil {
			_ = writer.Rollback()
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case result := <-beginDone:
			_ = writer.Rollback()
			t.Fatalf("cutover begin escaped an uncommitted application writer: epoch=%#v err=%v", result.epoch, result.err)
		default:
		}
		if time.Now().After(waitDeadline) {
			_ = writer.Rollback()
			t.Fatal("cutover begin did not wait for the application writer")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
	result := <-beginDone
	if result.err == nil {
		t.Fatalf("cutover accepted a target populated by a drained writer: %#v", result.epoch)
	}
	if _, err := admin.MailCutoverStatus(ctx, actor, request.EpochID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rejected pre-insert cutover status err=%v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `DELETE FROM relay.mail_endpoints WHERE endpoint='agent/cutover/draining'`); err != nil {
		t.Fatal(err)
	}
	epoch, err := admin.BeginMailCutover(ctx, actor, request)
	if err != nil || epoch.Phase != MailCutoverImporting || epoch.EpochID != request.EpochID {
		t.Fatalf("begin cutover epoch=%#v err=%v", epoch, err)
	}
	durableDigest := sha256.Sum256(epoch.Manifest)
	if hex.EncodeToString(durableDigest[:]) != request.ManifestSHA256 || string(epoch.Manifest) != string(canonicalManifest) {
		t.Fatalf("durable manifest=%s digest=%x", epoch.Manifest, durableDigest)
	}
	var postgresMajor int
	if err := ownerDB.QueryRowContext(ctx, `SELECT current_setting('server_version_num')::integer / 10000`).Scan(&postgresMajor); err != nil {
		t.Fatal(err)
	}
	updateRequest := UpdateRequest{
		UpdateID: "019f7f07-6b88-7c12-a394-b663274a6555", SourceRelease: "cutover-source", TargetRelease: "cutover-target",
		SourceImage:  "ghcr.io/rock3r/punaro@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TargetImage:  "ghcr.io/rock3r/punaro@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		SourceSchema: CurrentManifest().MaxSupported, TargetSchema: CurrentManifest().MaxSupported, SchemaMin: 8, SchemaMax: CurrentManifest().MaxSupported, RollbackFloor: 8, PostgresMajor: postgresMajor,
		ReleaseSHA256: strings.Repeat("1", 64), ComposeSHA256: strings.Repeat("2", 64), MigrationManifestSHA256: MigrationManifestSHA256(),
	}
	if _, err := admin.BeginUpdate(ctx, updateRequest); !errors.Is(err, ErrUpdateConflict) {
		t.Fatalf("update overlapped importing mail epoch: %v", err)
	}
	repeated, err := admin.BeginMailCutover(ctx, actor, request)
	if err != nil || !reflect.DeepEqual(repeated, epoch) {
		t.Fatalf("repeat cutover epoch=%#v err=%v", repeated, err)
	}
	changed := request
	changed.SourceFingerprint = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	changedManifest := manifest
	changedManifest.Fingerprint = changed.SourceFingerprint
	changedCanonical, _ := json.Marshal(changedManifest)
	changed.Manifest = changedCanonical
	changedDigest := sha256.Sum256(changedCanonical)
	changed.ManifestSHA256 = hex.EncodeToString(changedDigest[:])
	if _, err := admin.BeginMailCutover(ctx, actor, changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed cutover retry err=%v", err)
	}
	if err := app.AdvertiseEndpoints("cutover-fenced-machine", []string{"agent/cutover/fenced"}, time.Now().UTC(), time.Minute); !errors.Is(err, relay.ErrMaintenance) {
		t.Fatalf("application mail write during inactive cutover err=%v", err)
	}
	for _, table := range []string{"mail_endpoints", "mail_conversations", "mail_memberships", "mail_messages", "mail_deliveries", "mail_recipient_cursors", "mail_message_idempotency", "mail_conversation_idempotency"} {
		if _, err := app.relayPool().ExecContext(ctx, `INSERT INTO relay.`+table+` DEFAULT VALUES`); !isMaintenanceError(err) { // #nosec G202 -- table comes only from the fixed test allowlist.
			t.Fatalf("application cutover guard table=%s err=%v", table, err)
		}
	}
	if err := app.ConsumeRequestNonce("cutover-fenced-machine", "cutover-fenced-nonce", time.Now().UTC(), time.Now().UTC().Add(time.Minute)); !errors.Is(err, relay.ErrMaintenance) {
		t.Fatalf("application nonce write during cutover err=%v", err)
	}
	for _, table := range mailCutoverTables {
		checkpoint, err := admin.StageMailCutoverBatch(ctx, actor, MailCutoverBatch{EpochID: request.EpochID, Table: table, Done: true})
		if err != nil || checkpoint.RowCount != 0 || checkpoint.RollingSHA256 != emptyMailCutoverDigest {
			t.Fatalf("empty cutover checkpoint table=%s checkpoint=%#v err=%v", table, checkpoint, err)
		}
	}
	verified, err := admin.VerifyMailCutover(ctx, actor, request.EpochID, request.SourceFingerprint)
	if err != nil || verified.Phase != MailCutoverVerified || !verified.VerifiedAt.Valid {
		t.Fatalf("verified empty cutover=%#v err=%v", verified, err)
	}
	if _, err := admin.VerifyMailCutover(ctx, actor, request.EpochID, request.SourceFingerprint); err != nil {
		t.Fatalf("idempotent cutover verification: %v", err)
	}
	if err := admin.AbortMailCutover(ctx, actor, request.EpochID, request.SourceFingerprint); err != nil {
		t.Fatal(err)
	}
	if err := admin.AbortMailCutover(ctx, actor, request.EpochID, request.SourceFingerprint); err != nil {
		t.Fatalf("idempotent cutover abort err=%v", err)
	}
	status, err := admin.MailCutoverStatus(ctx, actor, request.EpochID)
	if err != nil || status.Phase != MailCutoverAborted {
		t.Fatalf("aborted cutover status=%#v err=%v", status, err)
	}
	update, err := admin.BeginUpdate(ctx, updateRequest)
	if err != nil || update.Phase != UpdateFenced {
		t.Fatalf("begin update after mail abort=%#v err=%v", update, err)
	}
	if err := admin.AbortMailCutover(ctx, actor, request.EpochID, request.SourceFingerprint); !errors.Is(err, ErrMaintenance) {
		t.Fatalf("mail abort overlapped active update: %v", err)
	}
	changedEpoch := request
	changedEpoch.EpochID = "019f7f07-7b88-7c12-a394-b663274a6555"
	manifest.EpochID = changedEpoch.EpochID
	changedEpochCanonical, _ := json.Marshal(manifest)
	changedEpoch.Manifest = changedEpochCanonical
	changedEpochDigest := sha256.Sum256(changedEpochCanonical)
	changedEpoch.ManifestSHA256 = hex.EncodeToString(changedEpochDigest[:])
	if _, err := admin.BeginMailCutover(ctx, actor, changedEpoch); !errors.Is(err, ErrMaintenance) {
		t.Fatalf("mail begin overlapped active update: %v", err)
	}
	if update, err = admin.AdvanceUpdate(ctx, updateRequest.UpdateID, UpdateFenced, UpdateAborted, nil); err != nil || update.Phase != UpdateAborted {
		t.Fatalf("abort update after cutover exclusion=%#v err=%v", update, err)
	}
	if err := app.AdvertiseEndpoints("cutover-unfenced-machine", []string{"agent/cutover/unfenced"}, time.Now().UTC(), time.Minute); err != nil {
		t.Fatalf("mail write after abort: %v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `DELETE FROM relay.mail_endpoints WHERE endpoint='agent/cutover/unfenced'`); err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(t.TempDir(), "relay.db")
	source, err := relay.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	migrationNow := time.Date(2026, time.July, 21, 2, 0, 0, 0, time.UTC)
	if err := source.AdvertiseEndpoints("cutover-machine-a", []string{"agent/cutover/source-a"}, migrationNow, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := source.AdvertiseEndpoints("cutover-machine-b", []string{"agent/cutover/source-b"}, migrationNow, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := source.CreateConversationIdempotent(relay.CreateConversationInput{MachineID: "cutover-machine-a", IdempotencyKey: "cutover-conversation", CreatorEndpoint: "agent/cutover/source-a", Now: migrationNow, Members: []relay.Member{{Endpoint: "agent/cutover/source-a", Capabilities: relay.CapSend | relay.CapReceive | relay.CapAdmin}, {Endpoint: "agent/cutover/source-b", Capabilities: relay.CapReceive}}})
	if err != nil {
		t.Fatal(err)
	}
	message, duplicate, err := source.AppendMessage(relay.AppendInput{ConversationID: conversation.ID, SenderMachineID: "cutover-machine-a", FromEndpoint: "agent/cutover/source-a", Body: "preserved cutover body", IdempotencyKey: "cutover-message", Now: migrationNow})
	if err != nil || duplicate {
		t.Fatalf("source message=%#v duplicate=%t err=%v", message, duplicate, err)
	}
	if err := source.ConsumeRequestNonce("cutover-machine-a", "cutover-nonce", migrationNow, migrationNow.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	activeSource, err := relay.InspectMigrationSource(ctx, sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	activationEpoch := "019f7f07-8b88-7c12-a394-b663274a6555"
	activationManifest, err := relay.PrepareMigrationSource(ctx, sourcePath, activationEpoch, targetIdentity, activeSource.Fingerprint, migrationNow.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	activationRequest := MailCutoverRequest{EpochID: activationEpoch, SourceID: activationManifest.SourceID, TargetIdentity: targetIdentity, SourceFingerprint: activationManifest.Fingerprint}
	activationRequest.Manifest, _ = json.Marshal(activationManifest)
	activationDigest := sha256.Sum256(activationRequest.Manifest)
	activationRequest.ManifestSHA256 = hex.EncodeToString(activationDigest[:])
	if _, err := admin.BeginMailCutover(ctx, actor, activationRequest); err != nil {
		t.Fatal(err)
	}
	for _, table := range mailCutoverTables {
		after := ""
		for {
			batch, err := relay.ReadMigrationSourceBatch(ctx, sourcePath, table, after, 1)
			if err != nil {
				t.Fatalf("source batch table=%s after=%q err=%v", table, after, err)
			}
			if _, err := admin.StageMailCutoverBatch(ctx, actor, MailCutoverBatch{EpochID: activationRequest.EpochID, Table: table, AfterKey: after, Rows: batch.Rows, Done: batch.Done}); err != nil {
				t.Fatalf("activation staging table=%s err=%v", table, err)
			}
			if batch.Done {
				break
			}
			after = batch.NextKey
		}
	}
	if _, err := admin.VerifyMailCutover(ctx, actor, activationRequest.EpochID, activationRequest.SourceFingerprint); err != nil {
		t.Fatal(err)
	}
	type activationEnrollmentRecord struct {
		ID        string   `json:"id"`
		PublicKey string   `json:"public_key"`
		Endpoints []string `json:"endpoints"`
	}
	var activationRecords []activationEnrollmentRecord
	existingMigrated, err := ownerDB.QueryContext(ctx, `SELECT public_key FROM auth.legacy_machines WHERE state='migrated' ORDER BY public_key_digest`)
	if err != nil {
		t.Fatal(err)
	}
	for existingMigrated.Next() {
		var publicKey []byte
		if err := existingMigrated.Scan(&publicKey); err != nil {
			_ = existingMigrated.Close()
			t.Fatal(err)
		}
		index := strconv.Itoa(len(activationRecords))
		activationRecords = append(activationRecords, activationEnrollmentRecord{ID: "cutover-existing-" + index, PublicKey: base64.RawURLEncoding.EncodeToString(publicKey), Endpoints: []string{"agent/cutover/existing-" + index}})
	}
	if err := existingMigrated.Close(); err != nil || existingMigrated.Err() != nil {
		t.Fatalf("existing migrated inventory err=%v close=%v", existingMigrated.Err(), err)
	}
	migratedKey := make([]byte, 32)
	migratedKey[0] = 73
	migratedKeyDigest := sha256.Sum256(migratedKey)
	migratedDeviceID, migratedLookupID, migratedLegacyID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	migratedSecretDigest := sha256.Sum256([]byte(migratedLookupID))
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.principals(id,kind,display_name) VALUES($1,'device','cutover migrated device'),($2,'legacy_machine','cutover migrated legacy')`, migratedDeviceID, migratedLegacyID); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.device_credentials(lookup_id,principal_id,label,secret_digest) VALUES($1,$2,'cutover migrated device',$3)`, migratedLookupID, migratedDeviceID, migratedSecretDigest[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.legacy_machines(principal_id,public_key,public_key_digest,state,migrated_credential_lookup_id) VALUES($1,$2,$3,'migrated',$4)`, migratedLegacyID, migratedKey, migratedKeyDigest[:], migratedLookupID); err != nil {
		t.Fatal(err)
	}
	retiredKey := make([]byte, 32)
	retiredKey[0] = 74
	retiredKeyDigest := sha256.Sum256(retiredKey)
	retiredLegacyID := uuid.NewString()
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.principals(id,kind,display_name) VALUES($1,'legacy_machine','cutover retired legacy')`, retiredLegacyID); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.legacy_machines(principal_id,public_key,public_key_digest,state) VALUES($1,$2,$3,'retired')`, retiredLegacyID, retiredKey, retiredKeyDigest[:]); err != nil {
		t.Fatal(err)
	}
	activationRecords = append(activationRecords,
		activationEnrollmentRecord{ID: "cutover-machine-a", PublicKey: base64.RawURLEncoding.EncodeToString(migratedKey), Endpoints: []string{"agent/cutover/source-a"}},
		activationEnrollmentRecord{ID: "cutover-machine-b", PublicKey: base64.RawURLEncoding.EncodeToString(retiredKey), Endpoints: []string{"agent/cutover/source-b"}},
	)
	activationEnrollmentJSON, err := json.Marshal(activationRecords)
	if err != nil {
		t.Fatal(err)
	}
	activationEnrollment := string(activationEnrollmentJSON)
	mismatchedKey := append([]byte(nil), migratedKey...)
	mismatchedKey[0]++
	mismatchedRecords := append([]activationEnrollmentRecord(nil), activationRecords...)
	mismatchedRecords[len(mismatchedRecords)-2].PublicKey = base64.RawURLEncoding.EncodeToString(mismatchedKey)
	mismatchedEnrollmentJSON, err := json.Marshal(mismatchedRecords)
	if err != nil {
		t.Fatal(err)
	}
	mismatchedEnrollment := string(mismatchedEnrollmentJSON)
	if err := admin.CheckMailCutoverActivationReadiness(ctx, actor, activationRequest.EpochID, activationRequest.SourceFingerprint, mismatchedEnrollment); err == nil {
		t.Fatal("activation readiness accepted a static enrollment key that did not match migrated inventory")
	}
	if err := admin.CheckMailCutoverActivationReadiness(ctx, uuid.NewString(), activationRequest.EpochID, activationRequest.SourceFingerprint, activationEnrollment); err == nil {
		t.Fatal("non-owner passed activation readiness")
	}
	pendingLegacyKey := make([]byte, 32)
	pendingLegacyKey[0] = 42
	pendingLegacyDigest := sha256.Sum256(pendingLegacyKey)
	var pendingLegacyID string
	if err := ownerDB.QueryRowContext(ctx, `INSERT INTO auth.principals(kind,display_name) VALUES('legacy_machine','cutover readiness fixture') RETURNING id::text`).Scan(&pendingLegacyID); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.legacy_machines(principal_id,public_key,public_key_digest) VALUES($1,$2,$3)`, pendingLegacyID, pendingLegacyKey, pendingLegacyDigest[:]); err != nil {
		t.Fatal(err)
	}
	if err := admin.CheckMailCutoverActivationReadiness(ctx, actor, activationRequest.EpochID, activationRequest.SourceFingerprint, activationEnrollment); err == nil {
		t.Fatal("activation readiness accepted a pending legacy machine")
	}
	if sourceState, err := relay.InspectMigrationSource(ctx, sourcePath); err != nil || sourceState.Phase != relay.MigrationSourcePrepared {
		t.Fatalf("readiness failure retired source state=%#v err=%v", sourceState, err)
	}
	if err := admin.RetireLegacyMachine(ctx, actor, pendingLegacyID); err != nil {
		t.Fatal(err)
	}
	if err := admin.CheckMailCutoverActivationReadiness(ctx, actor, activationRequest.EpochID, activationRequest.SourceFingerprint, activationEnrollment); err != nil {
		t.Fatalf("resolved activation readiness: %v", err)
	}
	if err := admin.RetireLegacyMachine(ctx, actor, migratedLegacyID); err == nil {
		t.Fatal("migrated legacy mapping was retired after cutover readiness")
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE auth.legacy_auth_state SET enabled=true,changed_at=statement_timestamp() WHERE singleton`); err != nil {
		t.Fatal(err)
	}
	registrationResult := make(chan error, 1)
	go func() {
		key := make([]byte, 32)
		key[0] = 84
		_, registerErr := admin.RegisterLegacyMachine(ctx, actor, "cutover readiness race", key)
		registrationResult <- registerErr
	}()
	if err := admin.CheckMailCutoverActivationReadiness(ctx, actor, activationRequest.EpochID, activationRequest.SourceFingerprint, activationEnrollment); err != nil {
		t.Fatalf("concurrent activation readiness: %v", err)
	}
	if err := <-registrationResult; err == nil {
		t.Fatal("legacy registration crossed a verified mail cutover")
	}
	var pendingAfterReadiness bool
	if err := ownerDB.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM auth.legacy_machines WHERE state='pending')`).Scan(&pendingAfterReadiness); err != nil || pendingAfterReadiness {
		t.Fatalf("pending legacy inventory crossed readiness pending=%t err=%v", pendingAfterReadiness, err)
	}
	if sourceState, err := relay.InspectMigrationSource(ctx, sourcePath); err != nil || sourceState.Phase != relay.MigrationSourcePrepared {
		t.Fatalf("registration race retired source state=%#v err=%v", sourceState, err)
	}
	retiredManifest, err := relay.RetirePreparedMigrationSource(ctx, sourcePath, activationRequest.EpochID, targetIdentity, activationRequest.SourceFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	active, err := admin.ActivateMailCutover(ctx, actor, activationRequest.EpochID, activationRequest.SourceFingerprint, retiredManifest)
	if err != nil || active.Phase != MailCutoverActive || !active.ActivatedAt.Valid {
		t.Fatalf("active mail cutover=%#v err=%v", active, err)
	}
	if repeated, err := admin.ActivateMailCutover(ctx, actor, activationRequest.EpochID, activationRequest.SourceFingerprint, retiredManifest); err != nil || repeated.Phase != MailCutoverActive {
		t.Fatalf("idempotent activation=%#v err=%v", repeated, err)
	}
	if err := admin.AbortMailCutover(ctx, actor, activationRequest.EpochID, activationRequest.SourceFingerprint); err == nil {
		t.Fatal("active mail cutover was abortable")
	}
	if err := app.AdvertiseEndpoints("cutover-active-machine", []string{"agent/cutover/active"}, time.Now().UTC(), time.Minute); err != nil {
		t.Fatalf("PostgreSQL writes did not reopen after activation: %v", err)
	}
	var migratedBody string
	if err := ownerDB.QueryRowContext(ctx, `SELECT body FROM relay.mail_messages WHERE id=$1`, message.ID).Scan(&migratedBody); err != nil || migratedBody != "preserved cutover body" {
		t.Fatalf("migrated message body=%q err=%v", migratedBody, err)
	}
	var migratedEndpoints, migratedMessages, migratedNonces int64
	if err := ownerDB.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM relay.mail_endpoints),(SELECT count(*) FROM relay.mail_messages),(SELECT count(*) FROM relay.mail_request_nonces)`).Scan(&migratedEndpoints, &migratedMessages, &migratedNonces); err != nil || migratedEndpoints != activationManifest.Counts.Endpoints+1 || migratedMessages != activationManifest.Counts.Messages || migratedNonces != activationManifest.Counts.RequestNonces {
		t.Fatalf("migrated counts endpoints=%d messages=%d nonces=%d manifest=%#v err=%v", migratedEndpoints, migratedMessages, migratedNonces, activationManifest.Counts, err)
	}
}

func testRelayIntegration(t *testing.T, app *Database) {
	t.Helper()
	contracttest.Run(t, app, "postgres-contract")
	testRecipientCursorDoesNotCrossUncommittedAppend(t, app)
	testEndpointAdvertisementUsesCanonicalLockOrder(t, app)
}

func testRecipientCursorDoesNotCrossUncommittedAppend(t *testing.T, app *Database) {
	t.Helper()
	now := time.Date(2026, time.July, 20, 15, 0, 0, 0, time.UTC)
	const (
		machineA  = "postgres-cursor-lock-machine-a"
		machineB  = "postgres-cursor-lock-machine-b"
		endpointA = "agent/postgres-cursor-lock/a"
		endpointB = "agent/postgres-cursor-lock/b"
	)
	if err := app.AdvertiseEndpoints(machineA, []string{endpointA}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := app.AdvertiseEndpoints(machineB, []string{endpointB}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := app.CreateConversationIdempotent(relay.CreateConversationInput{
		MachineID: machineA, IdempotencyKey: "postgres-cursor-lock-create", CreatorEndpoint: endpointA, Now: now,
		Members: []relay.Member{
			{Endpoint: endpointA, Capabilities: relay.CapSend | relay.CapReceive | relay.CapAdmin},
			{Endpoint: endpointB, Capabilities: relay.CapReceive},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	appendTx, appendCancel, err := app.beginRelayTransaction(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer appendCancel()
	defer func() { _ = appendTx.Rollback() }()
	messageID := uuid.NewString()
	var sequence int64
	if err := appendTx.QueryRowContext(context.Background(), `UPDATE relay.mail_conversations SET next_sequence=next_sequence+1 WHERE id=$1::uuid RETURNING next_sequence`, conversation.ID).Scan(&sequence); err != nil {
		t.Fatal(err)
	}
	if _, err := appendTx.ExecContext(context.Background(), `INSERT INTO relay.mail_messages(id,conversation_id,sequence,from_endpoint,body,created_at) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6)`, messageID, conversation.ID, sequence, endpointA, "must remain pending", now); err != nil {
		t.Fatal(err)
	}
	if _, err := appendTx.ExecContext(context.Background(), `INSERT INTO relay.mail_deliveries(message_id,recipient_endpoint) VALUES($1::uuid,$2)`, messageID, endpointB); err != nil {
		t.Fatal(err)
	}
	cursorTx, cursorCancel, err := app.beginRelayTransaction(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cursorCancel()
	defer func() { _ = cursorTx.Rollback() }()
	if err := postgresAdvanceRecipientCursor(cursorTx, endpointB, conversation.ID); err != nil {
		t.Fatalf("advance cursor alongside uncommitted append: %v", err)
	}
	if err := cursorTx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := appendTx.Commit(); err != nil {
		t.Fatal(err)
	}
	if cursor, err := app.RecipientCursor(machineB, endpointB, conversation.ID, now); err != nil || cursor != 0 {
		t.Fatalf("cursor crossed concurrent append: cursor=%d err=%v", cursor, err)
	}
	page, err := app.LeaseDeliveries(machineB, "postgres-cursor-lock-consumer", endpointB, conversation.ID, now, time.Minute, 10)
	if err != nil || len(page.Deliveries) != 1 || page.Deliveries[0].Message.Sequence != 1 {
		t.Fatalf("concurrent delivery page=%#v err=%v", page, err)
	}
}

func testEndpointAdvertisementUsesCanonicalLockOrder(t *testing.T, app *Database) {
	t.Helper()
	now := time.Date(2026, time.July, 20, 16, 0, 0, 0, time.UTC)
	const (
		machineID = "postgres-advertisement-lock-machine"
		endpointA = "agent/postgres-advertisement-lock/a"
		endpointZ = "agent/postgres-advertisement-lock/z"
	)
	if err := app.AdvertiseEndpoints(machineID, []string{endpointA, endpointZ}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	blocker, blockerCancel, err := app.beginRelayTransaction(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blockerCancel()
	defer func() { _ = blocker.Rollback() }()
	if _, err := blocker.ExecContext(context.Background(), `SELECT endpoint FROM relay.mail_endpoints WHERE endpoint=$1 FOR UPDATE`, endpointA); err != nil {
		t.Fatal(err)
	}
	advertisementResult := make(chan error, 1)
	go func() {
		advertisementResult <- app.AdvertiseEndpoints(machineID, []string{endpointA}, now.Add(time.Second), time.Hour)
	}()
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer waitCancel()
	for {
		var waiting bool
		err := app.relayPool().QueryRowContext(waitCtx, `SELECT EXISTS (
			SELECT 1 FROM pg_stat_activity
			WHERE datname=current_database() AND usename=current_user AND wait_event_type='Lock'
			  AND query LIKE 'SELECT endpoint FROM relay.mail_endpoints%'
		)`).Scan(&waiting)
		if err != nil {
			t.Fatalf("inspect advertisement lock wait: %v", err)
		}
		if waiting {
			break
		}
		select {
		case advertiseErr := <-advertisementResult:
			t.Fatalf("advertisement escaped first endpoint lock: %v", advertiseErr)
		case <-waitCtx.Done():
			t.Fatal("advertisement did not wait on the first ordered endpoint")
		case <-time.After(10 * time.Millisecond):
		}
	}
	probe, probeCancel, err := app.beginRelayTransaction(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer probeCancel()
	defer func() { _ = probe.Rollback() }()
	if _, err := probe.ExecContext(context.Background(), `SELECT endpoint FROM relay.mail_endpoints WHERE endpoint=$1 FOR UPDATE NOWAIT`, endpointZ); err != nil {
		t.Fatalf("advertisement locked a later endpoint before the first: %v", err)
	}
	if err := probe.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := blocker.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-advertisementResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ordered endpoint advertisement did not complete")
	}
}

func testV5UpdateBridgeIntegration(ctx context.Context, t *testing.T, ownerDB *sql.DB, ownerFile, appFile string) {
	t.Helper()
	current := CurrentManifest()
	v5Manifest := Manifest{MinSupported: 5, MaxSupported: 5, Migrations: append([]Migration(nil), current.Migrations[:5]...)}
	stagingConn, err := ownerDB.Conn(ctx)
	if err != nil {
		t.Fatalf("open v5 staging connection: %v", err)
	}
	stagingState, stagingErr := migrateConnExpectedAppRole(ctx, stagingConn, v5Manifest, "punaro_app", true)
	if closeErr := stagingConn.Close(); closeErr != nil {
		t.Fatalf("close v5 staging connection: %v", closeErr)
	}
	if stagingErr != nil || stagingState.Classification != Compatible || stagingState.Version != 5 {
		t.Fatalf("v5 staging state=%#v err=%v", stagingState, stagingErr)
	}
	var bridgeOwnerID string
	if err := ownerDB.QueryRowContext(ctx, `INSERT INTO auth.principals (kind,display_name) VALUES ('owner','v5 bridge owner') RETURNING id::text`).Scan(&bridgeOwnerID); err != nil {
		t.Fatalf("stage v5 bridge owner: %v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.installation_owner (principal_id) VALUES ($1)`, bridgeOwnerID); err != nil {
		t.Fatalf("install v5 bridge owner: %v", err)
	}
	if _, err := Migrate(ctx, Config{DSNFile: ownerFile}); err == nil || !strings.Contains(err.Error(), "supported update transaction") {
		t.Fatalf("ordinary migrator accepted v5 upgrade: %v", err)
	}
	var postgresMajor int
	if err := ownerDB.QueryRowContext(ctx, `SELECT current_setting('server_version_num')::integer / 10000`).Scan(&postgresMajor); err != nil {
		t.Fatal(err)
	}
	request := UpdateRequest{
		UpdateID:                "019b4eb0-798c-7a52-8d29-8560fcbb2083",
		SourceRelease:           "v0.6.0",
		TargetRelease:           "v0.7.0",
		SourceImage:             "ghcr.io/rock3r/punaro@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TargetImage:             "ghcr.io/rock3r/punaro@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		SourceSchema:            5,
		TargetSchema:            6,
		SchemaMin:               5,
		SchemaMax:               6,
		RollbackFloor:           5,
		PostgresMajor:           postgresMajor,
		ReleaseSHA256:           "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		ComposeSHA256:           "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		MigrationManifestSHA256: migrationManifestSHA256(Manifest{MinSupported: 6, MaxSupported: 6, Migrations: append([]Migration(nil), current.Migrations[:6]...)}),
	}
	bridge, err := BeginV5UpdateBridge(ctx, Config{DSNFile: ownerFile}, request)
	if err != nil {
		t.Fatalf("begin abortable bridge: %v", err)
	}
	if err := bridge.Abort(); err != nil {
		t.Fatalf("abort uncommitted bridge: %v", err)
	}
	snapshot, err := inspect(ctx, ownerDB)
	if err != nil || Classify(snapshot, v5Manifest).Classification != Compatible {
		t.Fatalf("aborted bridge changed v5 compatibility: state=%#v err=%v", Classify(snapshot, v5Manifest), err)
	}
	bridge, err = BeginV5UpdateBridge(ctx, Config{DSNFile: ownerFile}, request)
	if err != nil {
		t.Fatalf("begin durable bridge: %v", err)
	}
	transaction, err := bridge.CommitWritersStopped(ctx)
	if err != nil || transaction.Phase != UpdateWritersStopped {
		t.Fatalf("commit bridge transaction=%#v err=%v", transaction, err)
	}
	snapshot, err = inspect(ctx, ownerDB)
	if err != nil || Classify(snapshot, v5Manifest).Classification != Compatible {
		t.Fatalf("active bridge broke old-image schema compatibility: state=%#v err=%v", Classify(snapshot, v5Manifest), err)
	}
	admin, err := OpenAdministration(ctx, Config{DSNFile: ownerFile})
	if err != nil {
		t.Fatalf("resume bridge administration: %v", err)
	}
	defer func() { _ = admin.Close() }()
	if transaction, err = admin.AdvanceUpdate(ctx, request.UpdateID, UpdateWritersStopped, UpdateAborted, nil); err != nil || transaction.Phase != UpdateAborted {
		t.Fatalf("abort durable bridge transaction=%#v err=%v", transaction, err)
	}
	request.UpdateID = "019b4eb0-798c-7a52-8d29-8560fcbb2084"
	bridge, err = BeginV5UpdateBridge(ctx, Config{DSNFile: ownerFile}, request)
	if err != nil {
		t.Fatalf("retry bridge with exact installed controls: %v", err)
	}
	transaction, err = bridge.CommitWritersStopped(ctx)
	if err != nil || transaction.Phase != UpdateWritersStopped {
		t.Fatalf("commit retried bridge transaction=%#v err=%v", transaction, err)
	}
	var state InstallationState
	if err := ownerDB.QueryRowContext(ctx, `SELECT installation_id::text,timeline_id::text,change_sequence FROM jobs.server_state WHERE singleton`).Scan(&state.InstallationID, &state.TimelineID, &state.ChangeSequence); err != nil {
		t.Fatal(err)
	}
	marker := &UpdateBackupMarker{
		UpdateID: request.UpdateID, BackupID: "019b4eb0-5317-79a6-a0de-fd97719910fb",
		InstallationID: state.InstallationID, TimelineID: state.TimelineID, ChangeSequence: state.ChangeSequence,
		SourceSchema: request.SourceSchema, TargetRelease: request.TargetRelease,
		TargetImageDigest:  "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ExportedSnapshotID: "00000003-0000001B-1",
		ManifestSHA256:     "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}
	if transaction, err = admin.AdvanceUpdate(ctx, request.UpdateID, UpdateWritersStopped, UpdateBackupVerified, marker); err != nil || transaction.Phase != UpdateBackupVerified {
		t.Fatalf("bind bridge backup transaction=%#v err=%v", transaction, err)
	}
	if transaction, err = admin.AdvanceUpdate(ctx, request.UpdateID, UpdateBackupVerified, UpdateMigrationStarted, nil); err != nil || transaction.Phase != UpdateMigrationStarted {
		t.Fatalf("start bridge migration transaction=%#v err=%v", transaction, err)
	}
	authorization := UpdateMigrationAuthorization{
		UpdateID: request.UpdateID, BackupID: marker.BackupID, TargetRelease: request.TargetRelease,
		TargetImage: request.TargetImage, TargetSchema: request.TargetSchema,
		ExportedSnapshotID: marker.ExportedSnapshotID, ManifestSHA256: marker.ManifestSHA256,
	}
	v6Manifest := Manifest{MinSupported: 6, MaxSupported: 6, Migrations: append([]Migration(nil), current.Migrations[:6]...)}
	if state, err := migrateUpdateManifest(ctx, Config{DSNFile: ownerFile}, authorization, v6Manifest); err != nil || state.Classification != Compatible || state.Version != 6 {
		logControlPlaneCatalog(ctx, t, ownerDB)
		logDeviceAuthCatalog(ctx, t, ownerDB)
		t.Fatalf("bridge migration state=%#v err=%v", state, err)
	}
	for _, phases := range [][2]UpdatePhase{{UpdateMigrationStarted, UpdateMigrated}, {UpdateMigrated, UpdateCandidateReady}, {UpdateCandidateReady, UpdateDoctorPassed}, {UpdateDoctorPassed, UpdateConfigPublished}, {UpdateConfigPublished, UpdateCommitted}} {
		transaction, err = admin.AdvanceUpdate(ctx, request.UpdateID, phases[0], phases[1], nil)
		if err != nil || transaction.Phase != phases[1] {
			t.Fatalf("bridge phase %s -> %s transaction=%#v err=%v", phases[0], phases[1], transaction, err)
		}
	}
	v7Manifest := Manifest{MinSupported: 7, MaxSupported: 7, Migrations: append([]Migration(nil), current.Migrations[:7]...)}
	v8Manifest := Manifest{MinSupported: 8, MaxSupported: 8, Migrations: append([]Migration(nil), current.Migrations[:8]...)}
	v9Manifest := Manifest{MinSupported: 8, MaxSupported: 9, Migrations: append([]Migration(nil), current.Migrations[:9]...)}
	v10Manifest := Manifest{MinSupported: 9, MaxSupported: 10, Migrations: append([]Migration(nil), current.Migrations[:10]...)}
	request = UpdateRequest{
		UpdateID:                "019b4eb0-798c-7a52-8d29-8560fcbb2085",
		SourceRelease:           "v0.7.0",
		TargetRelease:           "v0.8.0",
		SourceImage:             "ghcr.io/rock3r/punaro@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		TargetImage:             "ghcr.io/rock3r/punaro@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		SourceSchema:            6,
		TargetSchema:            7,
		SchemaMin:               6,
		SchemaMax:               7,
		RollbackFloor:           6,
		PostgresMajor:           postgresMajor,
		ReleaseSHA256:           "abababababababababababababababababababababababababababababababab",
		ComposeSHA256:           "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
		MigrationManifestSHA256: migrationManifestSHA256(v7Manifest),
	}
	transaction, err = admin.BeginUpdate(ctx, request)
	if err != nil || transaction.Phase != UpdateFenced {
		t.Fatalf("begin v7 update transaction=%#v err=%v", transaction, err)
	}
	transaction, err = admin.AdvanceUpdate(ctx, request.UpdateID, UpdateFenced, UpdateWritersStopped, nil)
	if err != nil || transaction.Phase != UpdateWritersStopped {
		t.Fatalf("stop v7 writers transaction=%#v err=%v", transaction, err)
	}
	if err := ownerDB.QueryRowContext(ctx, `SELECT installation_id::text,timeline_id::text,change_sequence FROM jobs.server_state WHERE singleton`).Scan(&state.InstallationID, &state.TimelineID, &state.ChangeSequence); err != nil {
		t.Fatal(err)
	}
	marker = &UpdateBackupMarker{
		UpdateID: request.UpdateID, BackupID: "019b4eb0-5317-79a6-a0de-fd97719910fc",
		InstallationID: state.InstallationID, TimelineID: state.TimelineID, ChangeSequence: state.ChangeSequence,
		SourceSchema: request.SourceSchema, TargetRelease: request.TargetRelease,
		TargetImageDigest:  "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		ExportedSnapshotID: "00000003-0000001B-2",
		ManifestSHA256:     "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef",
	}
	transaction, err = admin.AdvanceUpdate(ctx, request.UpdateID, UpdateWritersStopped, UpdateBackupVerified, marker)
	if err != nil || transaction.Phase != UpdateBackupVerified {
		t.Fatalf("bind v7 backup transaction=%#v err=%v", transaction, err)
	}
	transaction, err = admin.AdvanceUpdate(ctx, request.UpdateID, UpdateBackupVerified, UpdateMigrationStarted, nil)
	if err != nil || transaction.Phase != UpdateMigrationStarted {
		t.Fatalf("start v7 migration transaction=%#v err=%v", transaction, err)
	}
	authorization = UpdateMigrationAuthorization{
		UpdateID: request.UpdateID, BackupID: marker.BackupID, TargetRelease: request.TargetRelease,
		TargetImage: request.TargetImage, TargetSchema: request.TargetSchema,
		ExportedSnapshotID: marker.ExportedSnapshotID, ManifestSHA256: marker.ManifestSHA256,
	}
	if state, err := migrateUpdateManifest(ctx, Config{DSNFile: ownerFile}, authorization, v7Manifest); err != nil || state.Classification != Compatible || state.Version != 7 {
		t.Fatalf("v7 migration state=%#v err=%v", state, err)
	}
	for _, phases := range [][2]UpdatePhase{{UpdateMigrationStarted, UpdateMigrated}, {UpdateMigrated, UpdateCandidateReady}, {UpdateCandidateReady, UpdateDoctorPassed}, {UpdateDoctorPassed, UpdateConfigPublished}, {UpdateConfigPublished, UpdateCommitted}} {
		transaction, err = admin.AdvanceUpdate(ctx, request.UpdateID, phases[0], phases[1], nil)
		if err != nil || transaction.Phase != phases[1] {
			t.Fatalf("v7 phase %s -> %s transaction=%#v err=%v", phases[0], phases[1], transaction, err)
		}
	}
	request = UpdateRequest{
		UpdateID:                "019b4eb0-798c-7a52-8d29-8560fcbb2086",
		SourceRelease:           "v0.8.0",
		TargetRelease:           "v0.9.0",
		SourceImage:             "ghcr.io/rock3r/punaro@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		TargetImage:             "ghcr.io/rock3r/punaro@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		SourceSchema:            7,
		TargetSchema:            8,
		SchemaMin:               7,
		SchemaMax:               8,
		RollbackFloor:           7,
		PostgresMajor:           postgresMajor,
		ReleaseSHA256:           "1212121212121212121212121212121212121212121212121212121212121212",
		ComposeSHA256:           "3434343434343434343434343434343434343434343434343434343434343434",
		MigrationManifestSHA256: migrationManifestSHA256(v8Manifest),
	}
	transaction, err = admin.BeginUpdate(ctx, request)
	if err != nil || transaction.Phase != UpdateFenced {
		t.Fatalf("begin v8 update transaction=%#v err=%v", transaction, err)
	}
	transaction, err = admin.AdvanceUpdate(ctx, request.UpdateID, UpdateFenced, UpdateWritersStopped, nil)
	if err != nil || transaction.Phase != UpdateWritersStopped {
		t.Fatalf("stop v8 writers transaction=%#v err=%v", transaction, err)
	}
	if err := ownerDB.QueryRowContext(ctx, `SELECT installation_id::text,timeline_id::text,change_sequence FROM jobs.server_state WHERE singleton`).Scan(&state.InstallationID, &state.TimelineID, &state.ChangeSequence); err != nil {
		t.Fatal(err)
	}
	marker = &UpdateBackupMarker{
		UpdateID: request.UpdateID, BackupID: "019b4eb0-5317-79a6-a0de-fd97719910fd",
		InstallationID: state.InstallationID, TimelineID: state.TimelineID, ChangeSequence: state.ChangeSequence,
		SourceSchema: request.SourceSchema, TargetRelease: request.TargetRelease,
		TargetImageDigest:  "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		ExportedSnapshotID: "00000003-0000001B-3",
		ManifestSHA256:     "5656565656565656565656565656565656565656565656565656565656565656",
	}
	transaction, err = admin.AdvanceUpdate(ctx, request.UpdateID, UpdateWritersStopped, UpdateBackupVerified, marker)
	if err != nil || transaction.Phase != UpdateBackupVerified {
		t.Fatalf("bind v8 backup transaction=%#v err=%v", transaction, err)
	}
	transaction, err = admin.AdvanceUpdate(ctx, request.UpdateID, UpdateBackupVerified, UpdateMigrationStarted, nil)
	if err != nil || transaction.Phase != UpdateMigrationStarted {
		t.Fatalf("start v8 migration transaction=%#v err=%v", transaction, err)
	}
	authorization = UpdateMigrationAuthorization{
		UpdateID: request.UpdateID, BackupID: marker.BackupID, TargetRelease: request.TargetRelease,
		TargetImage: request.TargetImage, TargetSchema: request.TargetSchema,
		ExportedSnapshotID: marker.ExportedSnapshotID, ManifestSHA256: marker.ManifestSHA256,
	}
	if state, err := migrateUpdateManifest(ctx, Config{DSNFile: ownerFile}, authorization, v8Manifest); err != nil || state.Classification != Compatible || state.Version != 8 {
		t.Fatalf("v8 migration state=%#v err=%v", state, err)
	}
	for _, phases := range [][2]UpdatePhase{{UpdateMigrationStarted, UpdateMigrated}, {UpdateMigrated, UpdateCandidateReady}, {UpdateCandidateReady, UpdateDoctorPassed}, {UpdateDoctorPassed, UpdateConfigPublished}, {UpdateConfigPublished, UpdateCommitted}} {
		transaction, err = admin.AdvanceUpdate(ctx, request.UpdateID, phases[0], phases[1], nil)
		if err != nil || transaction.Phase != phases[1] {
			t.Fatalf("v8 phase %s -> %s transaction=%#v err=%v", phases[0], phases[1], transaction, err)
		}
	}
	if snapshot, inspectErr := inspect(ctx, ownerDB); inspectErr != nil {
		t.Fatalf("inspect v8 schema with current manifest: %v", inspectErr)
	} else if state := Classify(snapshot, current); state.Classification != UpgradeRequired || state.Version != 8 {
		t.Fatalf("current manifest did not require the v8 to v9 bridge: %#v", state)
	}
	if err := admin.CheckMailCutoverSchemaReadiness(ctx); err == nil {
		t.Fatal("mail cutover accepted exact v8 schema before migration 009")
	}
	if _, err := Migrate(ctx, Config{DSNFile: ownerFile}); err == nil || !strings.Contains(err.Error(), "supported update transaction") {
		t.Fatalf("ordinary migrator accepted compatible-but-pending v9 upgrade: %v", err)
	}
	ordinaryConn, err := ownerDB.Conn(ctx)
	if err != nil {
		t.Fatalf("open ordinary migration engine connection: %v", err)
	}
	if state, migrateErr := migrateConnExpectedAppRole(ctx, ordinaryConn, current, "punaro_app", false); migrateErr == nil || !strings.Contains(migrateErr.Error(), "supported update transaction") || state.Classification != UpgradeRequired || state.Version != 8 {
		_ = ordinaryConn.Close()
		t.Fatalf("ordinary locked migration engine accepted compatible-but-pending v9 upgrade: state=%#v err=%v", state, migrateErr)
	}
	if err := ordinaryConn.Close(); err != nil {
		t.Fatalf("close ordinary migration engine connection: %v", err)
	}

	request = UpdateRequest{
		UpdateID:                "019b4eb0-798c-7a52-8d29-8560fcbb2087",
		SourceRelease:           "v0.8.0",
		TargetRelease:           "v0.9.0",
		SourceImage:             "ghcr.io/rock3r/punaro@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		TargetImage:             "ghcr.io/rock3r/punaro@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		SourceSchema:            8,
		TargetSchema:            9,
		SchemaMin:               8,
		SchemaMax:               9,
		RollbackFloor:           8,
		PostgresMajor:           postgresMajor,
		ReleaseSHA256:           "7878787878787878787878787878787878787878787878787878787878787878",
		ComposeSHA256:           "8989898989898989898989898989898989898989898989898989898989898989",
		MigrationManifestSHA256: migrationManifestSHA256(v9Manifest),
	}
	transaction, err = admin.BeginUpdate(ctx, request)
	if err != nil || transaction.Phase != UpdateFenced {
		t.Fatalf("begin v9 update transaction=%#v err=%v", transaction, err)
	}
	transaction, err = admin.AdvanceUpdate(ctx, request.UpdateID, UpdateFenced, UpdateWritersStopped, nil)
	if err != nil || transaction.Phase != UpdateWritersStopped {
		t.Fatalf("stop v9 writers transaction=%#v err=%v", transaction, err)
	}
	if err := ownerDB.QueryRowContext(ctx, `SELECT installation_id::text,timeline_id::text,change_sequence FROM jobs.server_state WHERE singleton`).Scan(&state.InstallationID, &state.TimelineID, &state.ChangeSequence); err != nil {
		t.Fatal(err)
	}
	marker = &UpdateBackupMarker{
		UpdateID: request.UpdateID, BackupID: "019b4eb0-5317-79a6-a0de-fd97719910fe",
		InstallationID: state.InstallationID, TimelineID: state.TimelineID, ChangeSequence: state.ChangeSequence,
		SourceSchema: request.SourceSchema, TargetRelease: request.TargetRelease,
		TargetImageDigest:  "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		ExportedSnapshotID: "00000003-0000001B-4",
		ManifestSHA256:     "9090909090909090909090909090909090909090909090909090909090909090",
	}
	transaction, err = admin.AdvanceUpdate(ctx, request.UpdateID, UpdateWritersStopped, UpdateBackupVerified, marker)
	if err != nil || transaction.Phase != UpdateBackupVerified {
		t.Fatalf("bind v9 backup transaction=%#v err=%v", transaction, err)
	}
	transaction, err = admin.AdvanceUpdate(ctx, request.UpdateID, UpdateBackupVerified, UpdateMigrationStarted, nil)
	if err != nil || transaction.Phase != UpdateMigrationStarted {
		t.Fatalf("start v9 migration transaction=%#v err=%v", transaction, err)
	}
	authorization = UpdateMigrationAuthorization{
		UpdateID: request.UpdateID, BackupID: marker.BackupID, TargetRelease: request.TargetRelease,
		TargetImage: request.TargetImage, TargetSchema: request.TargetSchema,
		ExportedSnapshotID: marker.ExportedSnapshotID, ManifestSHA256: marker.ManifestSHA256,
	}
	if state, err := migrateUpdateManifest(ctx, Config{DSNFile: ownerFile}, authorization, v9Manifest); err != nil || state.Classification != Compatible || state.Version != 9 {
		t.Fatalf("v9 migration state=%#v err=%v", state, err)
	}
	for _, phases := range [][2]UpdatePhase{{UpdateMigrationStarted, UpdateMigrated}, {UpdateMigrated, UpdateCandidateReady}, {UpdateCandidateReady, UpdateDoctorPassed}, {UpdateDoctorPassed, UpdateConfigPublished}, {UpdateConfigPublished, UpdateCommitted}} {
		transaction, err = admin.AdvanceUpdate(ctx, request.UpdateID, phases[0], phases[1], nil)
		if err != nil || transaction.Phase != phases[1] {
			t.Fatalf("v9 phase %s -> %s transaction=%#v err=%v", phases[0], phases[1], transaction, err)
		}
	}
	if snapshot, inspectErr := inspect(ctx, ownerDB); inspectErr != nil {
		t.Fatalf("inspect v9 schema with current manifest: %v", inspectErr)
	} else if state := Classify(snapshot, current); state.Classification != UpgradeRequired || state.Version != 9 {
		t.Fatalf("current manifest did not require the v9 to v10 update: %#v", state)
	}
	request = UpdateRequest{
		UpdateID:                "019b4eb0-798c-7a52-8d29-8560fcbb2088",
		SourceRelease:           "v0.9.0",
		TargetRelease:           "v0.10.0",
		SourceImage:             "ghcr.io/rock3r/punaro@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		TargetImage:             "ghcr.io/rock3r/punaro@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		SourceSchema:            9,
		TargetSchema:            10,
		SchemaMin:               9,
		SchemaMax:               10,
		RollbackFloor:           9,
		PostgresMajor:           postgresMajor,
		ReleaseSHA256:           "9191919191919191919191919191919191919191919191919191919191919191",
		ComposeSHA256:           "9292929292929292929292929292929292929292929292929292929292929292",
		MigrationManifestSHA256: migrationManifestSHA256(v10Manifest),
	}
	transaction, err = admin.BeginUpdate(ctx, request)
	if err != nil || transaction.Phase != UpdateFenced {
		t.Fatalf("begin v10 update transaction=%#v err=%v", transaction, err)
	}
	transaction, err = admin.AdvanceUpdate(ctx, request.UpdateID, UpdateFenced, UpdateWritersStopped, nil)
	if err != nil || transaction.Phase != UpdateWritersStopped {
		t.Fatalf("stop v10 writers transaction=%#v err=%v", transaction, err)
	}
	if err := ownerDB.QueryRowContext(ctx, `SELECT installation_id::text,timeline_id::text,change_sequence FROM jobs.server_state WHERE singleton`).Scan(&state.InstallationID, &state.TimelineID, &state.ChangeSequence); err != nil {
		t.Fatal(err)
	}
	marker = &UpdateBackupMarker{
		UpdateID: request.UpdateID, BackupID: "019b4eb0-5317-79a6-a0de-fd97719910ff",
		InstallationID: state.InstallationID, TimelineID: state.TimelineID, ChangeSequence: state.ChangeSequence,
		SourceSchema: request.SourceSchema, TargetRelease: request.TargetRelease,
		TargetImageDigest:  "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		ExportedSnapshotID: "00000003-0000001B-5",
		ManifestSHA256:     "9393939393939393939393939393939393939393939393939393939393939393",
	}
	transaction, err = admin.AdvanceUpdate(ctx, request.UpdateID, UpdateWritersStopped, UpdateBackupVerified, marker)
	if err != nil || transaction.Phase != UpdateBackupVerified {
		t.Fatalf("bind v10 backup transaction=%#v err=%v", transaction, err)
	}
	transaction, err = admin.AdvanceUpdate(ctx, request.UpdateID, UpdateBackupVerified, UpdateMigrationStarted, nil)
	if err != nil || transaction.Phase != UpdateMigrationStarted {
		t.Fatalf("start v10 migration transaction=%#v err=%v", transaction, err)
	}
	authorization = UpdateMigrationAuthorization{
		UpdateID: request.UpdateID, BackupID: marker.BackupID, TargetRelease: request.TargetRelease,
		TargetImage: request.TargetImage, TargetSchema: request.TargetSchema,
		ExportedSnapshotID: marker.ExportedSnapshotID, ManifestSHA256: marker.ManifestSHA256,
	}
	if state, err := migrateUpdateManifest(ctx, Config{DSNFile: ownerFile}, authorization, v10Manifest); err != nil || state.Classification != Compatible || state.Version != 10 {
		t.Fatalf("v10 migration state=%#v err=%v", state, err)
	}
	if err := admin.CheckMailCutoverSchemaReadiness(ctx); err == nil {
		t.Fatal("mail cutover accepted v10 while the current v13 schema was pending")
	}
	for _, phases := range [][2]UpdatePhase{{UpdateMigrationStarted, UpdateMigrated}, {UpdateMigrated, UpdateCandidateReady}, {UpdateCandidateReady, UpdateDoctorPassed}, {UpdateDoctorPassed, UpdateConfigPublished}, {UpdateConfigPublished, UpdateCommitted}} {
		transaction, err = admin.AdvanceUpdate(ctx, request.UpdateID, phases[0], phases[1], nil)
		if err != nil || transaction.Phase != phases[1] {
			t.Fatalf("v10 phase %s -> %s transaction=%#v err=%v", phases[0], phases[1], transaction, err)
		}
	}
	v10App, err := OpenApplication(ctx, Config{DSNFile: appFile})
	if err != nil {
		t.Fatalf("open current application binary against compatible v10 schema: %v", err)
	}
	if err := v10App.TrustedAttachmentRuntimeReady(ctx); err == nil {
		_ = v10App.Close()
		t.Fatal("trusted attachment runtime accepted compatible schema v10")
	}
	if err := v10App.AdvertiseEndpoints("v10-compatible-machine", []string{"agent/v10-compatible"}, time.Now().UTC(), time.Minute); err != nil {
		_ = v10App.Close()
		t.Fatalf("v13 binary could not advertise endpoints against compatible v10 schema: %v", err)
	}
	if err := v10App.AdvertiseEndpoints("v10-compatible-machine", nil, time.Now().UTC().Add(time.Second), time.Minute); err != nil {
		_ = v10App.Close()
		t.Fatalf("v13 binary could not withdraw endpoints against compatible v10 schema: %v", err)
	}
	if err := v10App.Close(); err != nil {
		t.Fatalf("close compatible v10 application: %v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `DELETE FROM relay.mail_endpoints WHERE machine_id='v10-compatible-machine'`); err != nil {
		t.Fatalf("remove compatible v10 endpoint fixture: %v", err)
	}
	const (
		bridgeCorruptProjectID  = "019b4eb0-798c-7a52-8d29-8560fcbb2090"
		bridgeCorruptArtifactID = "019b4eb0-798c-7a52-8d29-8560fcbb2091"
		bridgeCorruptRequestID  = "019b4eb0-798c-7a52-8d29-8560fcbb2092"
		bridgeCorruptSHA256     = "9797979797979797979797979797979797979797979797979797979797979797"
	)
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO relay.projects (id,display_name,created_by) VALUES ($1,'v10 corrupt attachment bridge',$2)`, bridgeCorruptProjectID, bridgeOwnerID); err != nil {
		t.Fatalf("stage v10 corrupt attachment project: %v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `
INSERT INTO attachment.uploads (
    artifact_id,project_id,principal_id,timeline_id,idempotency_key,request_sha256,
    size_bytes,sha256,display_name,media_type,state,expires_at,ready_at
)
SELECT $1,$2,$3,timeline_id,$4,$5,4096,$5,'legacy-corrupt.bin','application/octet-stream',
       'corrupt',statement_timestamp()+interval '7 days',statement_timestamp()
FROM jobs.server_state WHERE singleton`, bridgeCorruptArtifactID, bridgeCorruptProjectID, bridgeOwnerID, bridgeCorruptRequestID, bridgeCorruptSHA256); err != nil {
		t.Fatalf("stage v10 corrupt attachment: %v", err)
	}
	request = UpdateRequest{
		UpdateID:                "019b4eb0-798c-7a52-8d29-8560fcbb2089",
		SourceRelease:           "v0.10.0",
		TargetRelease:           "v0.17.0",
		SourceImage:             "ghcr.io/rock3r/punaro@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		TargetImage:             "ghcr.io/rock3r/punaro@sha256:abababababababababababababababababababababababababababababababab",
		SourceSchema:            10,
		TargetSchema:            current.MaxSupported,
		SchemaMin:               10,
		SchemaMax:               current.MaxSupported,
		RollbackFloor:           10,
		PostgresMajor:           postgresMajor,
		ReleaseSHA256:           "9494949494949494949494949494949494949494949494949494949494949494",
		ComposeSHA256:           "9595959595959595959595959595959595959595959595959595959595959595",
		MigrationManifestSHA256: MigrationManifestSHA256(),
	}
	transaction, err = admin.BeginUpdate(ctx, request)
	if err != nil || transaction.Phase != UpdateFenced {
		t.Fatalf("begin current update transaction=%#v err=%v", transaction, err)
	}
	transaction, err = admin.AdvanceUpdate(ctx, request.UpdateID, UpdateFenced, UpdateWritersStopped, nil)
	if err != nil || transaction.Phase != UpdateWritersStopped {
		t.Fatalf("stop current writers transaction=%#v err=%v", transaction, err)
	}
	if err := ownerDB.QueryRowContext(ctx, `SELECT installation_id::text,timeline_id::text,change_sequence FROM jobs.server_state WHERE singleton`).Scan(&state.InstallationID, &state.TimelineID, &state.ChangeSequence); err != nil {
		t.Fatal(err)
	}
	marker = &UpdateBackupMarker{
		UpdateID: request.UpdateID, BackupID: "019b4eb0-5317-79a6-a0de-fd9771991100",
		InstallationID: state.InstallationID, TimelineID: state.TimelineID, ChangeSequence: state.ChangeSequence,
		SourceSchema: request.SourceSchema, TargetRelease: request.TargetRelease,
		TargetImageDigest:  "sha256:abababababababababababababababababababababababababababababababab",
		ExportedSnapshotID: "00000003-0000001B-6",
		ManifestSHA256:     "9696969696969696969696969696969696969696969696969696969696969696",
	}
	transaction, err = admin.AdvanceUpdate(ctx, request.UpdateID, UpdateWritersStopped, UpdateBackupVerified, marker)
	if err != nil || transaction.Phase != UpdateBackupVerified {
		t.Fatalf("bind current backup transaction=%#v err=%v", transaction, err)
	}
	transaction, err = admin.AdvanceUpdate(ctx, request.UpdateID, UpdateBackupVerified, UpdateMigrationStarted, nil)
	if err != nil || transaction.Phase != UpdateMigrationStarted {
		t.Fatalf("start current migration transaction=%#v err=%v", transaction, err)
	}
	authorization = UpdateMigrationAuthorization{
		UpdateID: request.UpdateID, BackupID: marker.BackupID, TargetRelease: request.TargetRelease,
		TargetImage: request.TargetImage, TargetSchema: request.TargetSchema,
		ExportedSnapshotID: marker.ExportedSnapshotID, ManifestSHA256: marker.ManifestSHA256,
	}
	if state, err := MigrateUpdate(ctx, Config{DSNFile: ownerFile}, authorization); err != nil || state.Classification != Compatible || state.Version != CurrentManifest().MaxSupported {
		t.Fatalf("current migration state=%#v err=%v", state, err)
	}
	currentApp, err := OpenApplication(ctx, Config{DSNFile: appFile})
	if err != nil {
		t.Fatalf("open exact current application: %v", err)
	}
	if err := currentApp.TrustedAttachmentRuntimeReady(ctx); err != nil {
		_ = currentApp.Close()
		t.Fatalf("trusted attachment runtime rejected exact current schema: %v", err)
	}
	if err := currentApp.CanonicalBrainRuntimeReady(ctx); err != nil {
		_ = currentApp.Close()
		t.Fatalf("canonical brain runtime rejected exact current schema: %v", err)
	}
	if err := currentApp.Close(); err != nil {
		t.Fatalf("close exact current application: %v", err)
	}
	var (
		corruptProjectID, corruptOwnerID, corruptPath, corruptSHA256, corruptState string
		corruptSize, corruptGeneration                                             int64
		corruptTombstonedAt, corruptGCAfter                                        time.Time
	)
	if err := ownerDB.QueryRowContext(ctx, `
SELECT project_id::text,owner_principal_id::text,storage_path,size_bytes,sha256::text,
       state,tombstoned_at,gc_after,gc_generation
FROM attachment.deletions WHERE artifact_id=$1`, bridgeCorruptArtifactID).Scan(
		&corruptProjectID, &corruptOwnerID, &corruptPath, &corruptSize, &corruptSHA256,
		&corruptState, &corruptTombstonedAt, &corruptGCAfter, &corruptGeneration,
	); err != nil {
		t.Fatalf("read v10 corrupt attachment tombstone: %v", err)
	}
	if corruptProjectID != bridgeCorruptProjectID || corruptOwnerID != bridgeOwnerID ||
		corruptPath != "ready/"+bridgeCorruptArtifactID+".blob" || corruptSize != 4096 ||
		corruptSHA256 != bridgeCorruptSHA256 || corruptState != "tombstoned" || corruptGeneration != 0 ||
		corruptGCAfter.Sub(corruptTombstonedAt) != 24*time.Hour {
		t.Fatalf("v10 corrupt attachment tombstone project=%s owner=%s path=%s size=%d sha256=%s state=%s tombstoned_at=%s gc_after=%s generation=%d",
			corruptProjectID, corruptOwnerID, corruptPath, corruptSize, corruptSHA256, corruptState,
			corruptTombstonedAt, corruptGCAfter, corruptGeneration)
	}
	if err := admin.CheckMailCutoverSchemaReadiness(ctx); err != nil {
		t.Fatalf("mail cutover rejected exact current schema: %v", err)
	}
	for _, phases := range [][2]UpdatePhase{{UpdateMigrationStarted, UpdateMigrated}, {UpdateMigrated, UpdateCandidateReady}, {UpdateCandidateReady, UpdateDoctorPassed}, {UpdateDoctorPassed, UpdateConfigPublished}, {UpdateConfigPublished, UpdateCommitted}} {
		transaction, err = admin.AdvanceUpdate(ctx, request.UpdateID, phases[0], phases[1], nil)
		if err != nil || transaction.Phase != phases[1] {
			t.Fatalf("current phase %s -> %s transaction=%#v err=%v", phases[0], phases[1], transaction, err)
		}
	}
	if _, err := ownerDB.ExecContext(ctx, `DELETE FROM attachment.deletions WHERE artifact_id=$1`, bridgeCorruptArtifactID); err != nil {
		t.Fatalf("remove v10 corrupt attachment tombstone: %v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `DELETE FROM attachment.uploads WHERE artifact_id=$1`, bridgeCorruptArtifactID); err != nil {
		t.Fatalf("remove v10 corrupt attachment: %v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `DELETE FROM relay.projects WHERE id=$1`, bridgeCorruptProjectID); err != nil {
		t.Fatalf("remove v10 corrupt attachment project: %v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `DELETE FROM jobs.update_transactions`); err != nil {
		t.Fatalf("remove v5 bridge transaction fixture: %v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `DELETE FROM auth.installation_owner WHERE principal_id=$1`, bridgeOwnerID); err != nil {
		t.Fatalf("remove v5 bridge ownership fixture: %v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `DELETE FROM auth.principals WHERE id=$1`, bridgeOwnerID); err != nil {
		t.Fatalf("remove v5 bridge principal fixture: %v", err)
	}
}

func testTransactionalUpdateFenceIntegration(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB) {
	t.Helper()
	admin := &Administration{db: ownerDB}
	var postgresVersion int
	if err := ownerDB.QueryRowContext(ctx, `SELECT current_setting('server_version_num')::integer / 10000`).Scan(&postgresVersion); err != nil {
		t.Fatal(err)
	}
	request := UpdateRequest{
		UpdateID:                "019b4eb0-21f8-7d93-84df-10e6cf05ce53",
		SourceRelease:           "v0.6.0",
		TargetRelease:           "v0.7.0",
		SourceImage:             "ghcr.io/rock3r/punaro@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TargetImage:             "ghcr.io/rock3r/punaro@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		SourceSchema:            CurrentManifest().MaxSupported,
		TargetSchema:            CurrentManifest().MaxSupported,
		SchemaMin:               CurrentManifest().MaxSupported,
		SchemaMax:               CurrentManifest().MaxSupported,
		RollbackFloor:           CurrentManifest().MaxSupported,
		PostgresMajor:           postgresVersion,
		ReleaseSHA256:           "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		ComposeSHA256:           "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		MigrationManifestSHA256: MigrationManifestSHA256(),
	}

	// A writer that crossed the shared transaction gate must drain before the
	// exclusive durable fence can be published.
	writer, err := app.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.ExecContext(ctx, `SELECT jobs.assert_application_mutation()`); err != nil {
		_ = writer.Rollback()
		t.Fatal(err)
	}
	result := make(chan struct {
		transaction UpdateTransaction
		err         error
	}, 1)
	go func() {
		transaction, beginErr := admin.BeginUpdate(ctx, request)
		result <- struct {
			transaction UpdateTransaction
			err         error
		}{transaction, beginErr}
	}()
	select {
	case early := <-result:
		_ = writer.Rollback()
		t.Fatalf("fence did not drain in-flight writer: %#v err=%v", early.transaction, early.err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
	var transaction UpdateTransaction
	select {
	case completed := <-result:
		transaction, err = completed.transaction, completed.err
	case <-time.After(5 * time.Second):
		t.Fatal("fence acquisition did not resume after writer commit")
	}
	if err != nil || transaction.Phase != UpdateFenced || transaction.UpdateID != request.UpdateID {
		t.Fatalf("begin transaction=%#v err=%v", transaction, err)
	}
	if retried, err := admin.BeginUpdate(ctx, request); err != nil || retried != transaction {
		t.Fatalf("exact begin retry=%#v err=%v", retried, err)
	}
	conflict := request
	conflict.UpdateID = "019b4eb0-798c-7a52-8d29-8560fcbb2083"
	if _, err := admin.BeginUpdate(ctx, conflict); !errors.Is(err, ErrUpdateConflict) {
		t.Fatalf("concurrent update error=%v", err)
	}
	if _, err := app.AdvanceChange(ctx); !errors.Is(err, ErrMaintenance) {
		t.Fatalf("fenced application mutation error=%v", err)
	}
	if _, err := app.CreatePrincipal(ctx, PrincipalKindService, "fenced"); !errors.Is(err, ErrMaintenance) {
		t.Fatalf("fenced transaction mutation error=%v", err)
	}
	if err := app.AdvertiseEndpoints("fenced-relay-machine", []string{"agent/fenced"}, time.Now().UTC(), time.Minute); !errors.Is(err, relay.ErrMaintenance) {
		t.Fatalf("fenced relay mutation error=%v", err)
	}
	nonceNow := time.Now().UTC()
	if err := app.ConsumeRequestNonce("fenced-relay-machine", "fenced-nonce", nonceNow, nonceNow.Add(time.Minute)); !errors.Is(err, relay.ErrMaintenance) {
		t.Fatalf("fenced relay nonce error=%v", err)
	}

	transaction, err = admin.AdvanceUpdate(ctx, request.UpdateID, UpdateFenced, UpdateWritersStopped, nil)
	if err != nil || transaction.Phase != UpdateWritersStopped {
		t.Fatalf("writers stopped=%#v err=%v", transaction, err)
	}
	state, err := app.InstallationState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	marker := &UpdateBackupMarker{
		UpdateID:           request.UpdateID,
		BackupID:           "019b4eb0-a147-7d6c-8dc5-3824e816cc57",
		InstallationID:     state.InstallationID,
		TimelineID:         state.TimelineID,
		ChangeSequence:     state.ChangeSequence,
		SourceSchema:       request.SourceSchema,
		TargetRelease:      request.TargetRelease,
		TargetImageDigest:  "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ExportedSnapshotID: "00000003-0000001B-1",
		ManifestSHA256:     "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}
	transaction, err = admin.AdvanceUpdate(ctx, request.UpdateID, UpdateWritersStopped, UpdateBackupVerified, marker)
	if err != nil || transaction.Phase != UpdateBackupVerified || transaction.BackupID != marker.BackupID {
		t.Fatalf("backup marker=%#v err=%v", transaction, err)
	}
	if _, err := admin.AdvanceUpdate(ctx, request.UpdateID, UpdateBackupVerified, UpdateCommitted, nil); !errors.Is(err, ErrInvalidUpdateTransition) {
		t.Fatalf("skipped migration error=%v", err)
	}
	for _, transition := range [][2]UpdatePhase{{UpdateBackupVerified, UpdateMigrationStarted}, {UpdateMigrationStarted, UpdateMigrated}, {UpdateMigrated, UpdateCandidateReady}, {UpdateCandidateReady, UpdateDoctorPassed}, {UpdateDoctorPassed, UpdateConfigPublished}, {UpdateConfigPublished, UpdateCommitted}} {
		transaction, err = admin.AdvanceUpdate(ctx, request.UpdateID, transition[0], transition[1], nil)
		if err != nil || transaction.Phase != transition[1] {
			t.Fatalf("transition %s -> %s transaction=%#v err=%v", transition[0], transition[1], transaction, err)
		}
	}
	if _, err := admin.ActiveUpdate(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("committed update remained active: %v", err)
	}
	latest, err := admin.LatestUpdate(ctx)
	if err != nil || latest.UpdateID != request.UpdateID || latest.Phase != UpdateCommitted {
		t.Fatalf("latest update=%#v err=%v", latest, err)
	}
	if _, err := app.AdvanceChange(ctx); err != nil {
		t.Fatalf("mutation remained fenced after commit: %v", err)
	}

	// A pre-update dump contains the durable row at writers_stopped, before the
	// external verified-backup marker can be recorded. This is the exact shape
	// present after restoring that dump into a pristine stack.
	recoveryRequest := request
	recoveryRequest.UpdateID = "019b4eb0-798c-7a52-8d29-8560fcbb2083"
	transaction, err = admin.BeginUpdate(ctx, recoveryRequest)
	if err != nil {
		t.Fatalf("begin recovery fixture: %v", err)
	}
	transaction, err = admin.AdvanceUpdate(ctx, recoveryRequest.UpdateID, UpdateFenced, UpdateWritersStopped, nil)
	if err != nil || transaction.Phase != UpdateWritersStopped {
		t.Fatalf("recovery fixture writers stopped=%#v err=%v", transaction, err)
	}
	beforeRestore, err := app.InstallationState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	recoveryMarker := UpdateBackupMarker{
		UpdateID: recoveryRequest.UpdateID, BackupID: "019b4eb0-c447-7c76-b73f-f442bab67061",
		InstallationID: beforeRestore.InstallationID, TimelineID: beforeRestore.TimelineID,
		ChangeSequence: beforeRestore.ChangeSequence, SourceSchema: recoveryRequest.SourceSchema,
		TargetRelease:      recoveryRequest.TargetRelease,
		TargetImageDigest:  "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ExportedSnapshotID: "00000003-0000001B-2",
		ManifestSHA256:     "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
	}
	mismatch := recoveryMarker
	mismatch.TargetRelease = "v0.7.1"
	if _, _, err := admin.RestoreUpdateRecovery(ctx, mismatch); err == nil {
		t.Fatal("mismatched restored-backup evidence was accepted")
	}
	unchanged, err := app.InstallationState(ctx)
	if err != nil || unchanged != beforeRestore {
		t.Fatalf("failed recovery authorization mutated timeline: state=%#v err=%v", unchanged, err)
	}
	restored, transaction, err := admin.RestoreUpdateRecovery(ctx, recoveryMarker)
	if err != nil || transaction.Phase != UpdateRecoveryRequired || restored.InstallationID != beforeRestore.InstallationID || restored.TimelineID == beforeRestore.TimelineID || restored.ChangeSequence != beforeRestore.ChangeSequence || transaction.BackupID != recoveryMarker.BackupID || transaction.BackupTimelineID != beforeRestore.TimelineID {
		t.Fatalf("restored update state=%#v transaction=%#v err=%v", restored, transaction, err)
	}
	retriedState, retriedTransaction, err := admin.RestoreUpdateRecovery(ctx, recoveryMarker)
	if err != nil || retriedState != restored || retriedTransaction != transaction {
		t.Fatalf("restored update retry state=%#v transaction=%#v err=%v", retriedState, retriedTransaction, err)
	}
	if _, err := app.AdvanceChange(ctx); !errors.Is(err, ErrMaintenance) {
		t.Fatalf("restored recovery did not retain maintenance fence: %v", err)
	}
	for _, transition := range [][2]UpdatePhase{{UpdateRecoveryRequired, UpdateRecoveryReady}, {UpdateRecoveryReady, UpdateRecoveryDoctor}, {UpdateRecoveryDoctor, UpdateRecoveryConfig}, {UpdateRecoveryConfig, UpdateRecovered}} {
		transaction, err = admin.AdvanceUpdate(ctx, recoveryRequest.UpdateID, transition[0], transition[1], nil)
		if err != nil || transaction.Phase != transition[1] {
			t.Fatalf("restored recovery transition %s -> %s transaction=%#v err=%v", transition[0], transition[1], transaction, err)
		}
	}
	if _, err := app.AdvanceChange(ctx); err != nil {
		t.Fatalf("recovered update retained maintenance fence: %v", err)
	}
}

func m6CatalogDiagnostic(ctx context.Context, ownerDSN string) string {
	db, err := sql.Open("pgx", ownerDSN)
	if err != nil {
		return "open-failed"
	}
	defer func() { _ = db.Close() }()
	queries := []string{
		`SELECT format('v13-reserve:%s:%s:%s:%s:%s:%s:%s:%s:%s',proc.oid::regprocedure::text,md5(btrim(proc.prosrc)),language.lanname,proc.provolatile,proc.prosecdef,pg_get_userbyid(proc.proowner),pg_get_function_result(proc.oid),proc.proretset,COALESCE(array_to_string(proc.proconfig,','),'')) FROM pg_proc AS proc JOIN pg_language AS language ON language.oid=proc.prolang WHERE proc.oid=ANY(ARRAY[to_regprocedure('attachment.reserve_upload(uuid,uuid,uuid,bytea,bigint,text,text,text,interval)'),to_regprocedure('attachment.reserve_upload(uuid,uuid,bigint,uuid,uuid,bytea,bigint,text,text,text,interval)')]) ORDER BY proc.oid::regprocedure::text`,
		`SELECT format('v13-reserve-acl:%s:%s:%s:%s',proc.oid::regprocedure::text,COALESCE(grantee.rolname,'PUBLIC'),acl.privilege_type,acl.is_grantable) FROM pg_proc AS proc CROSS JOIN LATERAL aclexplode(COALESCE(proc.proacl,acldefault('f',proc.proowner))) AS acl LEFT JOIN pg_roles AS grantee ON grantee.oid=acl.grantee WHERE proc.oid=ANY(ARRAY[to_regprocedure('attachment.reserve_upload(uuid,uuid,uuid,bytea,bigint,text,text,text,interval)'),to_regprocedure('attachment.reserve_upload(uuid,uuid,bigint,uuid,uuid,bytea,bigint,text,text,text,interval)')]) ORDER BY proc.oid::regprocedure::text,grantee.rolname`,
		`SELECT format('v13-publish:%s:%s:%s:%s:%s:%s:%s:%s:%s',proc.oid::regprocedure::text,md5(btrim(proc.prosrc)),language.lanname,proc.provolatile,proc.prosecdef,pg_get_userbyid(proc.proowner),pg_get_function_result(proc.oid),proc.proretset,COALESCE(array_to_string(proc.proconfig,','),'')) FROM pg_proc AS proc JOIN pg_language AS language ON language.oid=proc.prolang WHERE proc.oid=ANY(ARRAY[to_regprocedure('attachment.publish_upload(uuid,uuid,bigint,uuid,text,bigint,text)'),to_regprocedure('attachment.publish_upload(uuid,uuid,bigint,uuid,bigint,uuid,text,bigint,text)')]) ORDER BY proc.oid::regprocedure::text`,
		`SELECT format('v13-publish-acl:%s:%s:%s:%s',proc.oid::regprocedure::text,COALESCE(grantee.rolname,'PUBLIC'),acl.privilege_type,acl.is_grantable) FROM pg_proc AS proc CROSS JOIN LATERAL aclexplode(COALESCE(proc.proacl,acldefault('f',proc.proowner))) AS acl LEFT JOIN pg_roles AS grantee ON grantee.oid=acl.grantee WHERE proc.oid=ANY(ARRAY[to_regprocedure('attachment.publish_upload(uuid,uuid,bigint,uuid,text,bigint,text)'),to_regprocedure('attachment.publish_upload(uuid,uuid,bigint,uuid,bigint,uuid,text,bigint,text)')]) ORDER BY proc.oid::regprocedure::text,grantee.rolname`,
		`SELECT format('v13-gc-candidates:%s:%s:%s:%s:%s:%s:%s:%s:%s',proc.oid::regprocedure::text,md5(btrim(proc.prosrc)),language.lanname,proc.provolatile,proc.prosecdef,pg_get_userbyid(proc.proowner),pg_get_function_result(proc.oid),proc.proretset,COALESCE(array_to_string(proc.proconfig,','),'')) FROM pg_proc AS proc JOIN pg_language AS language ON language.oid=proc.prolang WHERE proc.oid=to_regprocedure('attachment.gc_candidates(uuid,integer)')`,
		`WITH relation AS (SELECT to_regclass('attachment.deletions') AS oid), routines AS (SELECT unnest(ARRAY[to_regprocedure('attachment.tombstone_artifact(uuid,uuid,bigint,uuid,uuid,bytea)'),to_regprocedure('attachment.claim_artifact_gc(uuid,interval)'),to_regprocedure('attachment.finalize_artifact_gc(uuid,bigint,uuid)'),to_regprocedure('attachment.orphan_gc_allowed(uuid)')]) AS oid) SELECT format('v12-counts:columns=%s:constraints=%s:indexes=%s:table-acls=%s:routines=%s:routine-acls=%s', (SELECT count(*) FROM pg_attribute,relation WHERE attrelid=relation.oid AND attnum>0 AND NOT attisdropped), (SELECT count(*) FROM pg_constraint,relation WHERE conrelid=relation.oid AND contype<>'n'), (SELECT count(*) FROM pg_index,relation WHERE indrelid=relation.oid), (SELECT count(*) FROM pg_class AS object JOIN relation ON object.oid=relation.oid CROSS JOIN LATERAL aclexplode(COALESCE(object.relacl,acldefault('r',object.relowner))) AS acl), (SELECT count(*) FROM pg_proc,routines WHERE pg_proc.oid=routines.oid), (SELECT count(*) FROM pg_proc JOIN routines ON pg_proc.oid=routines.oid CROSS JOIN LATERAL aclexplode(COALESCE(pg_proc.proacl,acldefault('f',pg_proc.proowner))) AS acl))`,
		`SELECT format('v12-column:%s:%s:%s:%s:%s',attname,atttypid::regtype::text,atttypmod,attnotnull,COALESCE(pg_get_expr(adbin,adrelid),'')) FROM pg_attribute LEFT JOIN pg_attrdef ON adrelid=attrelid AND adnum=attnum WHERE attrelid=to_regclass('attachment.deletions') AND attnum>0 AND NOT attisdropped ORDER BY attnum`,
		`SELECT format('v12-constraint:%s:%s:%s:%s:%s:%s',conname,contype,conkey::text,convalidated,condeferrable,COALESCE(pg_get_expr(conbin,conrelid),'')) FROM pg_constraint WHERE conrelid=to_regclass('attachment.deletions') AND contype<>'n' ORDER BY conname`,
		`SELECT format('v12-index:%s:%s:%s:%s:%s:%s:%s',indexrelid::regclass::text,indkey::text,indisunique,indisprimary,indisvalid,indisready,COALESCE(pg_get_expr(indpred,indrelid),'')) FROM pg_index WHERE indrelid=to_regclass('attachment.deletions') ORDER BY indexrelid::regclass::text`,
		`SELECT format('v12-routine:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s',proc.oid::regprocedure::text,md5(btrim(proc.prosrc)),language.lanname,proc.provolatile,proc.prosecdef,proc.proisstrict,proc.proleakproof,proc.proparallel,pg_get_userbyid(proc.proowner),pg_get_function_result(proc.oid),proc.proretset,COALESCE(array_to_string(proc.proconfig,','),'')) FROM pg_proc AS proc JOIN pg_language AS language ON language.oid=proc.prolang WHERE proc.oid=ANY(ARRAY[to_regprocedure('attachment.tombstone_artifact(uuid,uuid,bigint,uuid,uuid,bytea)'),to_regprocedure('attachment.claim_artifact_gc(uuid,interval)'),to_regprocedure('attachment.finalize_artifact_gc(uuid,bigint,uuid)'),to_regprocedure('attachment.orphan_gc_allowed(uuid)')]) ORDER BY proc.oid::regprocedure::text`,
		`SELECT format('v12-routine-acl:%s:%s:%s:%s',proc.oid::regprocedure::text,COALESCE(grantee.rolname,'PUBLIC'),acl.privilege_type,acl.is_grantable) FROM pg_proc AS proc CROSS JOIN LATERAL aclexplode(COALESCE(proc.proacl,acldefault('f',proc.proowner))) AS acl LEFT JOIN pg_roles AS grantee ON grantee.oid=acl.grantee WHERE proc.oid=ANY(ARRAY[to_regprocedure('attachment.tombstone_artifact(uuid,uuid,bigint,uuid,uuid,bytea)'),to_regprocedure('attachment.claim_artifact_gc(uuid,interval)'),to_regprocedure('attachment.finalize_artifact_gc(uuid,bigint,uuid)'),to_regprocedure('attachment.orphan_gc_allowed(uuid)')]) ORDER BY proc.oid::regprocedure::text,grantee.rolname`,
		`SELECT format('v12-table:%s:%s:%s:%s:%s:%s:%s',relation.relkind,relation.relpersistence,relation.relrowsecurity,relation.relforcerowsecurity,pg_get_userbyid(relation.relowner),COALESCE(grantee.rolname,'PUBLIC'),acl.privilege_type) FROM pg_class AS relation CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) AS acl LEFT JOIN pg_roles AS grantee ON grantee.oid=acl.grantee WHERE relation.oid=to_regclass('attachment.deletions') ORDER BY grantee.rolname,acl.privilege_type`,
		`WITH relations AS (SELECT unnest(ARRAY[to_regclass('attachment.endpoint_principals'),to_regclass('attachment.conversation_projects'),to_regclass('attachment.message_artifacts'),to_regclass('attachment.recipient_grants'),to_regclass('attachment.recipient_grant_endpoints')]) AS oid), routines AS (SELECT unnest(ARRAY[to_regprocedure('attachment.device_authority_current(uuid,uuid,bigint)'),to_regprocedure('attachment.bind_endpoint_principals(text,uuid,uuid,bigint,jsonb,timestamp with time zone)'),to_regprocedure('attachment.bind_conversation_project(uuid,uuid,bigint,uuid,text,uuid)'),to_regprocedure('attachment.bind_message_artifacts(uuid,uuid,bigint,uuid,jsonb)'),to_regprocedure('attachment.project_has_recipient_records(uuid,uuid)'),to_regprocedure('attachment.authorize_download(uuid,uuid,bigint,uuid)')]) AS oid) SELECT format('v11-counts:tables=%s:columns=%s:constraints=%s:fks=%s:indexes=%s:table-acls=%s:routines=%s:routine-acls=%s', (SELECT count(*) FROM pg_class,relations WHERE pg_class.oid=relations.oid), (SELECT count(*) FROM pg_attribute,relations WHERE attrelid=relations.oid AND attnum>0 AND NOT attisdropped), (SELECT count(*) FROM pg_constraint,relations WHERE conrelid=relations.oid AND contype<>'n'), (SELECT count(*) FROM pg_constraint,relations WHERE conrelid=relations.oid AND contype='f'), (SELECT count(*) FROM pg_index,relations WHERE indrelid=relations.oid), (SELECT count(*) FROM pg_class AS relation JOIN relations ON relation.oid=relations.oid CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) AS acl), (SELECT count(*) FROM pg_proc,routines WHERE pg_proc.oid=routines.oid), (SELECT count(*) FROM pg_proc JOIN routines ON pg_proc.oid=routines.oid CROSS JOIN LATERAL aclexplode(COALESCE(pg_proc.proacl,acldefault('f',pg_proc.proowner))) AS acl))`,
		`SELECT format('v11-column:%s:%s:%s:%s:%s', attrelid::regclass::text, attname, atttypid::regtype::text, atttypmod, attnotnull) FROM pg_attribute WHERE attrelid = ANY(ARRAY[to_regclass('attachment.endpoint_principals'),to_regclass('attachment.conversation_projects'),to_regclass('attachment.message_artifacts'),to_regclass('attachment.recipient_grants'),to_regclass('attachment.recipient_grant_endpoints')]) AND attnum>0 AND NOT attisdropped ORDER BY attrelid::regclass::text,attnum`,
		`SELECT format('v11-constraint:%s:%s:%s:%s:%s:%s:%s:%s:%s', conrelid::regclass::text,conname,contype,conkey::text,NULLIF(confrelid,0)::regclass::text,confkey::text,convalidated,condeferrable,COALESCE(pg_get_expr(conbin,conrelid),'')) FROM pg_constraint WHERE conrelid = ANY(ARRAY[to_regclass('attachment.endpoint_principals'),to_regclass('attachment.conversation_projects'),to_regclass('attachment.message_artifacts'),to_regclass('attachment.recipient_grants'),to_regclass('attachment.recipient_grant_endpoints')]) AND contype<>'n' ORDER BY conrelid::regclass::text,conname`,
		`SELECT format('v11-index:%s:%s:%s:%s:%s:%s:%s:%s',indexrelid::regclass::text,indrelid::regclass::text,indkey::text,indisunique,indisprimary,indisvalid,indisready,COALESCE(pg_get_expr(indpred,indrelid),'')) FROM pg_index WHERE indrelid = ANY(ARRAY[to_regclass('attachment.endpoint_principals'),to_regclass('attachment.conversation_projects'),to_regclass('attachment.message_artifacts'),to_regclass('attachment.recipient_grants'),to_regclass('attachment.recipient_grant_endpoints')]) ORDER BY indexrelid::regclass::text`,
		`SELECT format('v11-routine:%s:%s:%s:%s:%s:%s:%s:%s:%s',proc.oid::regprocedure::text,md5(btrim(proc.prosrc)),language.lanname,proc.provolatile,proc.prosecdef,pg_get_userbyid(proc.proowner),pg_get_function_result(proc.oid),proc.proretset,COALESCE(array_to_string(proc.proconfig,','),'')) FROM pg_proc AS proc JOIN pg_language AS language ON language.oid=proc.prolang WHERE proc.oid = ANY(ARRAY[to_regprocedure('attachment.device_authority_current(uuid,uuid,bigint)'),to_regprocedure('attachment.bind_endpoint_principals(text,uuid,uuid,bigint,jsonb,timestamp with time zone)'),to_regprocedure('attachment.bind_conversation_project(uuid,uuid,bigint,uuid,text,uuid)'),to_regprocedure('attachment.bind_message_artifacts(uuid,uuid,bigint,uuid,jsonb)'),to_regprocedure('attachment.project_has_recipient_records(uuid,uuid)'),to_regprocedure('attachment.authorize_download(uuid,uuid,bigint,uuid)')]) ORDER BY proc.oid::regprocedure::text`,
		`SELECT format('v11-routine-acl:%s:%s:%s:%s',proc.oid::regprocedure::text,COALESCE(grantee.rolname,'PUBLIC'),acl.privilege_type,acl.is_grantable) FROM pg_proc AS proc CROSS JOIN LATERAL aclexplode(COALESCE(proc.proacl,acldefault('f',proc.proowner))) AS acl LEFT JOIN pg_roles AS grantee ON grantee.oid=acl.grantee WHERE proc.oid = ANY(ARRAY[to_regprocedure('attachment.device_authority_current(uuid,uuid,bigint)'),to_regprocedure('attachment.bind_endpoint_principals(text,uuid,uuid,bigint,jsonb,timestamp with time zone)'),to_regprocedure('attachment.bind_conversation_project(uuid,uuid,bigint,uuid,text,uuid)'),to_regprocedure('attachment.bind_message_artifacts(uuid,uuid,bigint,uuid,jsonb)'),to_regprocedure('attachment.project_has_recipient_records(uuid,uuid)'),to_regprocedure('attachment.authorize_download(uuid,uuid,bigint,uuid)')]) ORDER BY proc.oid::regprocedure::text,grantee.rolname`,
		`SELECT format('v11-table-acl:%s:%s:%s:%s:%s',relation.oid::regclass::text,pg_get_userbyid(relation.relowner),COALESCE(grantee.rolname,'PUBLIC'),acl.privilege_type,acl.is_grantable) FROM pg_class AS relation CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) AS acl LEFT JOIN pg_roles AS grantee ON grantee.oid=acl.grantee WHERE relation.oid = ANY(ARRAY[to_regclass('attachment.endpoint_principals'),to_regclass('attachment.conversation_projects'),to_regclass('attachment.message_artifacts'),to_regclass('attachment.recipient_grants'),to_regclass('attachment.recipient_grant_endpoints')]) ORDER BY relation.oid::regclass::text,grantee.rolname,acl.privilege_type`,
		`SELECT format('constraint:%s:%s:%s', conrelid::regclass::text, conkey::text, pg_get_expr(conbin, conrelid)) FROM pg_constraint WHERE conrelid = ANY(ARRAY[to_regclass('attachment.ready_blob_manifest'),to_regclass('jobs.backup_gc_fences'),to_regclass('jobs.restore_events')]) AND contype = 'c' ORDER BY conrelid::regclass::text, conkey::text`,
		`SELECT format('key:%s:%s:%s', conrelid::regclass::text, contype, conkey::text) FROM pg_constraint WHERE conrelid = ANY(ARRAY[to_regclass('attachment.ready_blob_manifest'),to_regclass('jobs.backup_gc_fences'),to_regclass('jobs.restore_events')]) AND contype IN ('p','u') ORDER BY conrelid::regclass::text, contype, conkey::text`,
		`SELECT format('column:%s:%s:%s:%s:%s:%s', attrelid::regclass::text, attname, atttypid::regtype::text, atttypmod, attnotnull, COALESCE(pg_get_expr(adbin, adrelid),'')) FROM pg_attribute LEFT JOIN pg_attrdef ON adrelid=attrelid AND adnum=attnum WHERE attrelid = ANY(ARRAY[to_regclass('attachment.ready_blob_manifest'),to_regclass('jobs.backup_gc_fences'),to_regclass('jobs.restore_events')]) AND attnum > 0 AND NOT attisdropped ORDER BY attrelid::regclass::text, attnum`,
		`SELECT format('routine:%s:%s:%s:%s:%s:%s:%s:%s', proc.oid::regprocedure::text, md5(btrim(proc.prosrc)), language.lanname, proc.provolatile, proc.prosecdef, pg_get_userbyid(proc.proowner), pg_get_function_result(proc.oid), COALESCE(array_to_string(proc.proconfig,','),'')) FROM pg_proc AS proc JOIN pg_language AS language ON language.oid=proc.prolang WHERE proc.oid = ANY(ARRAY[to_regprocedure('jobs.acquire_backup_gc_fence(interval)'),to_regprocedure('jobs.bind_backup_snapshot(uuid,text)'),to_regprocedure('jobs.renew_backup_gc_fence(uuid,text,interval)'),to_regprocedure('jobs.cancel_unbound_backup_gc_fence(uuid)'),to_regprocedure('jobs.release_backup_gc_fence(uuid,text,boolean)'),to_regprocedure('jobs.physical_blob_gc_permitted()'),to_regprocedure('jobs.rotate_restored_timeline(uuid,uuid,uuid,bigint)')]) ORDER BY proc.oid::regprocedure::text`,
		`SELECT format('routine-acl:%s:%s:%s:%s', proc.oid::regprocedure::text, COALESCE(grantee.rolname,'PUBLIC'), acl.privilege_type, acl.is_grantable) FROM pg_proc AS proc CROSS JOIN LATERAL aclexplode(COALESCE(proc.proacl,acldefault('f',proc.proowner))) AS acl LEFT JOIN pg_roles AS grantee ON grantee.oid=acl.grantee WHERE proc.oid = ANY(ARRAY[to_regprocedure('jobs.acquire_backup_gc_fence(interval)'),to_regprocedure('jobs.bind_backup_snapshot(uuid,text)'),to_regprocedure('jobs.renew_backup_gc_fence(uuid,text,interval)'),to_regprocedure('jobs.cancel_unbound_backup_gc_fence(uuid)'),to_regprocedure('jobs.release_backup_gc_fence(uuid,text,boolean)'),to_regprocedure('jobs.physical_blob_gc_permitted()'),to_regprocedure('jobs.rotate_restored_timeline(uuid,uuid,uuid,bigint)')]) ORDER BY proc.oid::regprocedure::text, grantee.rolname`,
		`SELECT format('table-acl:%s:%s:%s:%s:%s', relation.oid::regclass::text, pg_get_userbyid(relation.relowner), COALESCE(grantee.rolname,'PUBLIC'), acl.privilege_type, acl.is_grantable) FROM pg_class AS relation CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) AS acl LEFT JOIN pg_roles AS grantee ON grantee.oid=acl.grantee WHERE relation.oid = ANY(ARRAY[to_regclass('attachment.ready_blob_manifest'),to_regclass('jobs.backup_gc_fences'),to_regclass('jobs.restore_events')]) ORDER BY relation.oid::regclass::text, grantee.rolname, acl.privilege_type`,
		`SELECT format('index:%s:%s:%s:%s:%s', indexrelid::regclass::text, indrelid::regclass::text, indkey::text, indisunique, pg_get_expr(indpred,indrelid)) FROM pg_index WHERE indexrelid=to_regclass('jobs.backup_gc_fences_active')`,
		`WITH relations AS (SELECT unnest(ARRAY[to_regclass('attachment.uploads'),to_regclass('attachment.ready_artifacts'),to_regclass('attachment.global_quota'),to_regclass('attachment.project_quotas'),to_regclass('attachment.principal_quotas')]) AS oid), routines AS (SELECT unnest(ARRAY[to_regprocedure('attachment.reserve_upload(uuid,uuid,uuid,bytea,bigint,text,text,text,interval)'),to_regprocedure('attachment.claim_upload(uuid,uuid,interval)'),to_regprocedure('attachment.publish_upload(uuid,uuid,bigint,uuid,text,bigint,text)'),to_regprocedure('attachment.begin_reap_upload(uuid)'),to_regprocedure('attachment.release_expired_upload(uuid,uuid)'),to_regprocedure('attachment.mark_corrupt(uuid)'),to_regprocedure('attachment.reconcile_candidates(text,timestamp with time zone,uuid,integer)'),to_regprocedure('attachment.project_has_records(uuid,uuid)')]) AS oid) SELECT format('v10-counts:tables=%s:columns=%s:constraints=%s:fks=%s:indexes=%s:table-acls=%s:routines=%s:routine-acls=%s', (SELECT count(*) FROM pg_class,relations WHERE pg_class.oid=relations.oid), (SELECT count(*) FROM pg_attribute,relations WHERE attrelid=relations.oid AND attnum>0 AND NOT attisdropped), (SELECT count(*) FROM pg_constraint,relations WHERE conrelid=relations.oid), (SELECT count(*) FROM pg_constraint,relations WHERE conrelid=relations.oid AND contype='f'), (SELECT count(*) FROM pg_index,relations WHERE indrelid=relations.oid), (SELECT count(*) FROM pg_class AS relation JOIN relations ON relation.oid=relations.oid CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) AS acl), (SELECT count(*) FROM pg_proc,routines WHERE pg_proc.oid=routines.oid), (SELECT count(*) FROM pg_proc JOIN routines ON pg_proc.oid=routines.oid CROSS JOIN LATERAL aclexplode(COALESCE(pg_proc.proacl,acldefault('f',pg_proc.proowner))) AS acl))`,
		`SELECT format('v10-routine:%s:%s:%s:%s:%s:%s', proc.oid::regprocedure::text, md5(btrim(proc.prosrc)), language.lanname, proc.provolatile, proc.prosecdef, COALESCE(array_to_string(proc.proconfig,','),'')) FROM pg_proc AS proc JOIN pg_language AS language ON language.oid=proc.prolang WHERE proc.oid = ANY(ARRAY[to_regprocedure('attachment.reserve_upload(uuid,uuid,uuid,bytea,bigint,text,text,text,interval)'),to_regprocedure('attachment.claim_upload(uuid,uuid,interval)'),to_regprocedure('attachment.publish_upload(uuid,uuid,bigint,uuid,text,bigint,text)'),to_regprocedure('attachment.begin_reap_upload(uuid)'),to_regprocedure('attachment.release_expired_upload(uuid,uuid)'),to_regprocedure('attachment.mark_corrupt(uuid)'),to_regprocedure('attachment.reconcile_candidates(text,timestamp with time zone,uuid,integer)'),to_regprocedure('attachment.project_has_records(uuid,uuid)')]) ORDER BY proc.oid::regprocedure::text`,
		`SELECT format('v10-critical:%s:%s:%s', conrelid::regclass::text, conname, pg_get_expr(conbin,conrelid)) FROM pg_constraint WHERE conrelid=to_regclass('attachment.uploads') AND conname IN ('uploads_size_bytes_check','uploads_state_check') ORDER BY conname`,
		`SELECT format('v10-index:%s:%s:%s:%s:%s', indexrelid::regclass::text, indrelid::regclass::text, indkey::text, indisvalid, indisready) FROM pg_index WHERE indexrelid IN (to_regclass('attachment.uploads_project_state'),to_regclass('attachment.uploads_reconcile_order')) ORDER BY indexrelid::regclass::text`,
	}
	var diagnostic strings.Builder
	for _, query := range queries {
		rows, queryErr := db.QueryContext(ctx, query)
		if queryErr != nil {
			return "query-failed"
		}
		for rows.Next() {
			var line string
			if rows.Scan(&line) == nil && diagnostic.Len()+len(line) < 16<<10 {
				diagnostic.WriteString(line)
				diagnostic.WriteByte(';')
			}
		}
		_ = rows.Close()
	}
	return diagnostic.String()
}

func testBackupRestoreIntegration(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB, ownerFile, appFile string) {
	t.Helper()
	identity, err := app.Identity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	releaseRestoreLock, err := AcquireRestoreLock(ctx, Config{DSNFile: appFile}, identity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireRestoreLock(ctx, Config{DSNFile: appFile}, identity); err == nil {
		releaseRestoreLock()
		t.Fatal("concurrent target-database restore lock unexpectedly succeeded")
	}
	releaseRestoreLock()
	releaseRestoreLock, err = AcquireRestoreLock(ctx, Config{DSNFile: appFile}, identity)
	if err != nil {
		t.Fatalf("released target-database restore lock was not reusable: %v", err)
	}
	releaseRestoreLock()
	if _, err := app.db.ExecContext(ctx, `SELECT jobs.acquire_backup_gc_fence(interval '5 minutes')`); err == nil {
		t.Fatal("application role can acquire privileged backup GC fences")
	}
	if _, err := app.db.ExecContext(ctx, `INSERT INTO attachment.ready_blob_manifest (storage_path, size_bytes, sha256) VALUES ('ready/test', 4, repeat('a', 64))`); err == nil {
		t.Fatal("application role can directly publish READY blob backup metadata")
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO attachment.ready_blob_manifest (storage_path, size_bytes, sha256) VALUES ('ready/test', 4, repeat('a', 64))`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = ownerDB.ExecContext(context.Background(), `DELETE FROM attachment.ready_blob_manifest WHERE storage_path = 'ready/test'`)
	}()
	dumpCalled := false
	source, err := NewBackupSource(app, ownerFile, func(_ context.Context, dsnFile, snapshotID, destination string) error {
		dumpCalled = true
		if dsnFile != ownerFile || snapshotID == "" || !filepath.IsAbs(destination) {
			t.Fatalf("dump inputs dsn=%q snapshot=%q destination=%q", dsnFile, snapshotID, destination)
		}
		return os.WriteFile(destination, []byte("dump"), 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := source.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.ReadyBlobs) != 1 || snapshot.ReadyBlobs[0].StoragePath != "ready/test" || snapshot.ReadyBlobs[0].Size != 4 || snapshot.ReadyBlobs[0].SHA256 != strings.Repeat("a", 64) {
		t.Fatalf("unexpected READY snapshot: %#v", snapshot.ReadyBlobs)
	}
	var gcPermitted bool
	if err := app.db.QueryRowContext(ctx, `SELECT jobs.physical_blob_gc_permitted()`).Scan(&gcPermitted); err != nil || gcPermitted {
		t.Fatalf("physical GC was not fenced: permitted=%t err=%v", gcPermitted, err)
	}
	dumpPath := filepath.Join(t.TempDir(), "database.dump")
	if err := snapshot.Dump(ctx, dumpPath); err != nil || !dumpCalled {
		t.Fatalf("snapshot dump called=%t err=%v", dumpCalled, err)
	}
	if err := snapshot.Finish(ctx, true); err != nil {
		t.Fatal(err)
	}
	if err := app.db.QueryRowContext(ctx, `SELECT jobs.physical_blob_gc_permitted()`).Scan(&gcPermitted); err != nil || !gcPermitted {
		t.Fatalf("physical GC fence did not release: permitted=%t err=%v", gcPermitted, err)
	}
	var expiredToken string
	if err := ownerDB.QueryRowContext(ctx, `SELECT jobs.acquire_backup_gc_fence(interval '5 minutes')::text`).Scan(&expiredToken); err != nil {
		t.Fatal(err)
	}
	const expiredSnapshot = "00000003-0000001B-999"
	var bound bool
	if err := ownerDB.QueryRowContext(ctx, `SELECT jobs.bind_backup_snapshot($1::uuid,$2)`, expiredToken, expiredSnapshot).Scan(&bound); err != nil || !bound {
		t.Fatalf("bind expired-fence fixture=%t err=%v", bound, err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE jobs.backup_gc_fences SET acquired_at = statement_timestamp() - interval '10 minutes', expires_at = statement_timestamp() - interval '1 second' WHERE fence_id = $1::uuid`, expiredToken); err != nil {
		t.Fatal(err)
	}
	var expiredRelease sql.NullBool
	if err := ownerDB.QueryRowContext(ctx, `SELECT jobs.release_backup_gc_fence($1::uuid,$2,true)`, expiredToken, expiredSnapshot).Scan(&expiredRelease); err != nil || expiredRelease.Valid {
		t.Fatalf("expired fence verified release=%#v err=%v", expiredRelease, err)
	}
	if confirmed, err := reconcileBackupGCFence(ctx, ownerDB, expiredToken, expiredSnapshot, false); err == nil || confirmed {
		t.Fatalf("active expired fence reconciled as released: confirmed=%t err=%v", confirmed, err)
	}
	var released bool
	if err := ownerDB.QueryRowContext(ctx, `SELECT jobs.release_backup_gc_fence($1::uuid,$2,false)`, expiredToken, expiredSnapshot).Scan(&released); err != nil || !released {
		t.Fatalf("expired fence unverified release=%t err=%v", released, err)
	}
	if confirmed, err := reconcileBackupGCFence(ctx, ownerDB, expiredToken, expiredSnapshot, false); err != nil || !confirmed {
		t.Fatalf("released unverified fence was not reconciled: confirmed=%t err=%v", confirmed, err)
	}
	if confirmed, err := reconcileBackupGCFence(ctx, ownerDB, expiredToken, expiredSnapshot, true); err == nil || confirmed {
		t.Fatalf("released unverified fence reconciled as verified: confirmed=%t err=%v", confirmed, err)
	}
	const missingFenceID = "018f47f4-7b18-7cc2-98d6-31d4fb5ab743"
	if confirmed, err := reconcileBackupGCFence(ctx, ownerDB, missingFenceID, expiredSnapshot, true); err == nil || confirmed {
		t.Fatalf("missing fence reconciled as verified: confirmed=%t err=%v", confirmed, err)
	}
	if confirmed, err := reconcileBackupGCFence(ctx, ownerDB, missingFenceID, expiredSnapshot, false); err != nil || !confirmed {
		t.Fatalf("missing abort fence was not reconciled: confirmed=%t err=%v", confirmed, err)
	}
	var verified bool
	if err := ownerDB.QueryRowContext(ctx, `SELECT verified FROM jobs.backup_gc_fences WHERE snapshot_id = $1`, snapshot.ID).Scan(&verified); err != nil || !verified {
		t.Fatalf("backup fence verification state=%t err=%v", verified, err)
	}
	var verifiedToken string
	if err := ownerDB.QueryRowContext(ctx, `SELECT fence_id::text FROM jobs.backup_gc_fences WHERE snapshot_id = $1`, snapshot.ID).Scan(&verifiedToken); err != nil {
		t.Fatal(err)
	}
	if confirmed, err := reconcileBackupGCFence(ctx, ownerDB, verifiedToken, snapshot.ID, true); err != nil || !confirmed {
		t.Fatalf("released verified fence was not reconciled: confirmed=%t err=%v", confirmed, err)
	}
	retrySource, err := NewBackupSource(app, ownerFile, func(context.Context, string, string, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	retryOpenFenceSession := retrySource.openFenceSession
	releaseAttempts := 0
	retrySource.openFenceSession = func(openCtx context.Context, dsnFile string) (backupFenceSession, error) {
		session, openErr := retryOpenFenceSession(openCtx, dsnFile)
		if openErr != nil {
			return nil, openErr
		}
		return &fakeBackupFenceSession{
			release: func(releaseCtx context.Context, token, snapshotID string, releaseVerified bool) (bool, error) {
				releaseAttempts++
				if releaseAttempts == 1 {
					return false, nil
				}
				return session.Release(releaseCtx, token, snapshotID, releaseVerified)
			},
			reconcile: session.Reconcile,
			close:     session.Close,
		}, nil
	}
	retrySnapshot, err := retrySource.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = retrySnapshot.Finish(context.Background(), false) }()
	if err := retrySnapshot.Finish(ctx, true); err == nil {
		t.Fatal("injected verified fence release failure unexpectedly succeeded")
	}
	if err := app.db.QueryRowContext(ctx, `SELECT jobs.physical_blob_gc_permitted()`).Scan(&gcPermitted); err != nil || gcPermitted {
		t.Fatalf("failed verified release did not retain GC fence: permitted=%t err=%v", gcPermitted, err)
	}
	if err := retrySnapshot.Finish(ctx, false); err != nil {
		t.Fatalf("unverified fence release retry failed: %v", err)
	}
	if releaseAttempts != 2 {
		t.Fatalf("fence release attempts=%d, want 2", releaseAttempts)
	}
	if err := app.db.QueryRowContext(ctx, `SELECT jobs.physical_blob_gc_permitted()`).Scan(&gcPermitted); err != nil || !gcPermitted {
		t.Fatalf("retried GC fence did not release immediately: permitted=%t err=%v", gcPermitted, err)
	}
	if err := ownerDB.QueryRowContext(ctx, `SELECT verified FROM jobs.backup_gc_fences WHERE snapshot_id = $1`, retrySnapshot.ID).Scan(&verified); err != nil || verified {
		t.Fatalf("retried backup fence verification state=%t err=%v", verified, err)
	}
	ambiguousSource, err := NewBackupSource(app, ownerFile, func(context.Context, string, string, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	ambiguousOpenFenceSession := ambiguousSource.openFenceSession
	ambiguousSource.openFenceSession = func(openCtx context.Context, dsnFile string) (backupFenceSession, error) {
		session, openErr := ambiguousOpenFenceSession(openCtx, dsnFile)
		if openErr != nil {
			return nil, openErr
		}
		return &fakeBackupFenceSession{
			release: func(releaseCtx context.Context, token, snapshotID string, releaseVerified bool) (bool, error) {
				released, releaseErr := session.Release(releaseCtx, token, snapshotID, releaseVerified)
				if releaseErr != nil || !released {
					return released, releaseErr
				}
				return false, errors.New("simulated lost release response")
			},
			reconcile: session.Reconcile,
			close:     session.Close,
		}, nil
	}
	ambiguousSnapshot, err := ambiguousSource.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ambiguousSnapshot.Finish(context.Background(), false) }()
	if err := ambiguousSnapshot.Finish(ctx, true); err != nil {
		t.Fatalf("committed fence release was not reconciled: %v", err)
	}
	if err := ownerDB.QueryRowContext(ctx, `SELECT verified FROM jobs.backup_gc_fences WHERE snapshot_id = $1`, ambiguousSnapshot.ID).Scan(&verified); err != nil || !verified {
		t.Fatalf("reconciled backup fence verification state=%t err=%v", verified, err)
	}
	before, err := app.InstallationState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := OpenAdministration(ctx, Config{DSNFile: ownerFile})
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := admin.RotateRestoredTimeline(ctx, "018f47f4-7b18-7cc2-98d6-31d4fb5ab742", before)
	if closeErr := admin.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil || rotated.InstallationID != before.InstallationID || rotated.TimelineID == before.TimelineID || rotated.ChangeSequence != before.ChangeSequence {
		t.Fatalf("timeline rotation before=%#v after=%#v err=%v", before, rotated, err)
	}
	admin, err = OpenAdministration(ctx, Config{DSNFile: ownerFile})
	if err != nil {
		t.Fatal(err)
	}
	retried, err := admin.RotateRestoredTimeline(ctx, "018f47f4-7b18-7cc2-98d6-31d4fb5ab742", before)
	if closeErr := admin.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil || retried != rotated {
		t.Fatalf("timeline rotation retry=%#v want=%#v err=%v", retried, rotated, err)
	}
	if err := ValidateCursor(rotated, before); !errors.Is(err, ErrCursorTimelineChanged) {
		t.Fatalf("pre-restore cursor error=%v, want timeline change", err)
	}
	if err := ValidateCursor(rotated, InstallationState{InstallationID: rotated.InstallationID, TimelineID: rotated.TimelineID, ChangeSequence: rotated.ChangeSequence + 1}); !errors.Is(err, ErrCursorFromFuture) {
		t.Fatalf("future cursor error=%v, want future rejection", err)
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
