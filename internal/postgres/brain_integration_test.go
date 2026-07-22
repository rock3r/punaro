package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rock3r/punaro/internal/secretguard"
)

func testCanonicalBrainSchemaDriftIntegration(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB) {
	t.Helper()
	for _, drift := range []struct {
		name    string
		apply   string
		restore string
	}{
		{
			name:    "memory table ownership",
			apply:   `ALTER TABLE brain.memory_tombstones OWNER TO punaro_app`,
			restore: `ALTER TABLE brain.memory_tombstones OWNER TO punaro_owner; REVOKE ALL ON brain.memory_tombstones FROM punaro_app`,
		},
		{
			name:    "memory change delete privilege",
			apply:   `GRANT DELETE ON brain.memory_changes TO punaro_app`,
			restore: `REVOKE DELETE ON brain.memory_changes FROM punaro_app`,
		},
		{
			name:    "memory scope maintain privilege",
			apply:   `GRANT MAINTAIN ON brain.scopes TO punaro_app`,
			restore: `REVOKE MAINTAIN ON brain.scopes FROM punaro_app`,
		},
		{
			name:    "memory scope missing insert privilege",
			apply:   `REVOKE INSERT ON brain.scopes FROM punaro_app`,
			restore: `GRANT INSERT ON brain.scopes TO punaro_app`,
		},
		{
			name:    "memory revision column update privilege",
			apply:   `GRANT UPDATE (document) ON brain.memory_revisions TO punaro_app`,
			restore: `REVOKE UPDATE (document) ON brain.memory_revisions FROM punaro_app`,
		},
		{
			name:    "memory change column references privilege",
			apply:   `GRANT REFERENCES (scope_id) ON brain.memory_changes TO punaro_app`,
			restore: `REVOKE REFERENCES (scope_id) ON brain.memory_changes FROM punaro_app`,
		},
		{
			name:    "memory tombstone read privilege",
			apply:   `GRANT SELECT ON brain.memory_tombstones TO punaro_app`,
			restore: `REVOKE SELECT ON brain.memory_tombstones FROM punaro_app`,
		},
		{
			name:    "memory tombstone public read privilege",
			apply:   `GRANT SELECT ON brain.memory_tombstones TO PUBLIC`,
			restore: `REVOKE SELECT ON brain.memory_tombstones FROM PUBLIC`,
		},
		{
			name:    "memory tombstone insert privilege",
			apply:   `GRANT INSERT ON brain.memory_tombstones TO punaro_app`,
			restore: `REVOKE INSERT ON brain.memory_tombstones FROM punaro_app`,
		},
		{
			name:    "memory scope select grant option",
			apply:   `GRANT SELECT ON brain.scopes TO punaro_app WITH GRANT OPTION`,
			restore: `REVOKE GRANT OPTION FOR SELECT ON brain.scopes FROM punaro_app`,
		},
		{
			name:    "memory mutation fence",
			apply:   `ALTER TABLE brain.memory_items DISABLE TRIGGER application_mutation_fence`,
			restore: `ALTER TABLE brain.memory_items ENABLE TRIGGER application_mutation_fence`,
		},
		{
			name:    "memory scope state index",
			apply:   `DROP INDEX brain.memory_items_scope_state`,
			restore: `CREATE INDEX memory_items_scope_state ON brain.memory_items (scope_id,state,id)`,
		},
		{
			name:    "memory purge public execute",
			apply:   `GRANT EXECUTE ON FUNCTION brain.purge_memory(uuid,uuid,uuid,bigint) TO PUBLIC`,
			restore: `REVOKE EXECUTE ON FUNCTION brain.purge_memory(uuid,uuid,uuid,bigint) FROM PUBLIC`,
		},
		{
			name:    "memory state constraint",
			apply:   `ALTER TABLE brain.memory_items DROP CONSTRAINT memory_items_state_check; ALTER TABLE brain.memory_items ADD CONSTRAINT memory_items_state_check CHECK (state IS NOT NULL)`,
			restore: `ALTER TABLE brain.memory_items DROP CONSTRAINT memory_items_state_check; ALTER TABLE brain.memory_items ADD CONSTRAINT memory_items_state_check CHECK (state IN ('active','archived'))`,
		},
		{
			name:    "memory document constraint",
			apply:   `ALTER TABLE brain.memory_revisions DROP CONSTRAINT memory_revisions_document_check; ALTER TABLE brain.memory_revisions ADD CONSTRAINT memory_revisions_document_check CHECK (jsonb_typeof(document) IS NOT NULL)`,
			restore: `ALTER TABLE brain.memory_revisions DROP CONSTRAINT memory_revisions_document_check; ALTER TABLE brain.memory_revisions ADD CONSTRAINT memory_revisions_document_check CHECK (jsonb_typeof(document)='object' AND octet_length(document::text)<=262144)`,
		},
		{
			name:    "memory hash constraint",
			apply:   `ALTER TABLE brain.memory_revisions DROP CONSTRAINT memory_revisions_content_sha256_check; ALTER TABLE brain.memory_revisions ADD CONSTRAINT memory_revisions_content_sha256_check CHECK (octet_length(content_sha256)>=1)`,
			restore: `ALTER TABLE brain.memory_revisions DROP CONSTRAINT memory_revisions_content_sha256_check; ALTER TABLE brain.memory_revisions ADD CONSTRAINT memory_revisions_content_sha256_check CHECK (octet_length(content_sha256)=32)`,
		},
		{
			name:    "memory operation constraint",
			apply:   `ALTER TABLE brain.memory_revisions DROP CONSTRAINT memory_revisions_operation_check; ALTER TABLE brain.memory_revisions ADD CONSTRAINT memory_revisions_operation_check CHECK (operation IN ('create','update','archive','restore','unexpected'))`,
			restore: `ALTER TABLE brain.memory_revisions DROP CONSTRAINT memory_revisions_operation_check; ALTER TABLE brain.memory_revisions ADD CONSTRAINT memory_revisions_operation_check CHECK (operation IN ('create','update','archive','restore'))`,
		},
		{
			name:    "memory scope foreign key",
			apply:   `ALTER TABLE brain.memory_items DROP CONSTRAINT memory_items_scope_id_fkey; ALTER TABLE brain.memory_items ADD CONSTRAINT memory_items_scope_id_fkey FOREIGN KEY (scope_id) REFERENCES relay.projects(id)`,
			restore: `ALTER TABLE brain.memory_items DROP CONSTRAINT memory_items_scope_id_fkey; ALTER TABLE brain.memory_items ADD CONSTRAINT memory_items_scope_id_fkey FOREIGN KEY (scope_id) REFERENCES brain.scopes(id)`,
		},
	} {
		t.Run("readiness rejects "+drift.name+" drift", func(t *testing.T) {
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
	if _, err := ownerDB.ExecContext(ctx, `ALTER TABLE brain.memory_items DROP CONSTRAINT memory_items_logical_key_check; ALTER TABLE brain.memory_items ADD CONSTRAINT memory_items_logical_key_check CHECK (logical_key IS NULL OR (char_length(logical_key) >= 1 AND char_length(logical_key) <= 128 AND octet_length(logical_key) <= 512 AND logical_key !~ '[[:cntrl:]]'))`); err != nil {
		t.Fatal(err)
	}
	restoredConstraintErr := app.Ready(ctx)
	if _, err := ownerDB.ExecContext(ctx, `ALTER TABLE brain.memory_items DROP CONSTRAINT memory_items_logical_key_check; ALTER TABLE brain.memory_items ADD CONSTRAINT memory_items_logical_key_check CHECK (logical_key IS NULL OR (char_length(logical_key) BETWEEN 1 AND 128 AND octet_length(logical_key) <= 512 AND logical_key !~ '[[:cntrl:]]'))`); err != nil {
		t.Fatal(err)
	}
	if restoredConstraintErr != nil {
		t.Fatalf("readiness rejected dump/restore-normalized logical-key constraint: %v", restoredConstraintErr)
	}
	if err := app.Ready(ctx); err != nil {
		t.Fatalf("readiness did not recover after logical-key constraint restoration: %v", err)
	}
	var purgeDefinition string
	if err := ownerDB.QueryRowContext(ctx, `SELECT pg_get_functiondef('brain.purge_memory(uuid,uuid,uuid,bigint)'::regprocedure)`).Scan(&purgeDefinition); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `CREATE OR REPLACE FUNCTION brain.purge_memory(
requested_principal uuid, requested_project uuid, requested_item uuid, expected_revision bigint
) RETURNS TABLE (scope_id uuid,revision bigint,timeline_id uuid,change_sequence bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog
AS $function$ BEGIN RETURN; END $function$`); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err == nil {
		t.Fatal("readiness accepted replacement memory purge routine")
	}
	if _, err := ownerDB.ExecContext(ctx, purgeDefinition); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err != nil {
		t.Fatalf("readiness did not recover after memory purge routine restoration: %v", err)
	}
}

func testSecretGuardSchemaDriftIntegration(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB) {
	t.Helper()
	for _, drift := range []struct {
		name, apply, restore string
	}{
		{"guard state owner", `ALTER TABLE brain.secret_guard_state OWNER TO punaro_app`, `ALTER TABLE brain.secret_guard_state OWNER TO punaro_owner; REVOKE ALL ON brain.secret_guard_state FROM punaro_app; GRANT SELECT ON brain.secret_guard_state TO punaro_app`},
		{"rule digest", `UPDATE brain.secret_guard_state SET rule_digest=decode(repeat('00',32),'hex') WHERE singleton`, `UPDATE brain.secret_guard_state SET rule_digest=decode('39fb102e3a58faf1e5b7d0045caed1c2110da2f622102c088aeef16f775dfa22','hex') WHERE singleton`},
		{"extra delete", `GRANT DELETE ON brain.secret_exceptions TO punaro_app`, `REVOKE DELETE ON brain.secret_exceptions FROM punaro_app`},
		{"extra column update", `GRANT UPDATE (rule_id) ON brain.secret_exceptions TO punaro_app`, `REVOKE UPDATE (rule_id) ON brain.secret_exceptions FROM punaro_app`},
		{"public select", `GRANT SELECT ON brain.secret_exceptions TO PUBLIC`, `REVOKE SELECT ON brain.secret_exceptions FROM PUBLIC`},
		{"grant option", `GRANT SELECT ON brain.secret_guard_state TO punaro_app WITH GRANT OPTION`, `REVOKE GRANT OPTION FOR SELECT ON brain.secret_guard_state FROM punaro_app`},
		{"disabled fence", `ALTER TABLE brain.secret_exceptions DISABLE TRIGGER application_mutation_fence`, `ALTER TABLE brain.secret_exceptions ENABLE TRIGGER application_mutation_fence`},
		{"row security", `ALTER TABLE brain.secret_exceptions ENABLE ROW LEVEL SECURITY`, `ALTER TABLE brain.secret_exceptions DISABLE ROW LEVEL SECURITY`},
		{"project FK update action", `ALTER TABLE brain.secret_exceptions DROP CONSTRAINT secret_exceptions_project_id_fkey; ALTER TABLE brain.secret_exceptions ADD CONSTRAINT secret_exceptions_project_id_fkey FOREIGN KEY (project_id) REFERENCES relay.projects(id) ON UPDATE CASCADE`, `ALTER TABLE brain.secret_exceptions DROP CONSTRAINT secret_exceptions_project_id_fkey; ALTER TABLE brain.secret_exceptions ADD CONSTRAINT secret_exceptions_project_id_fkey FOREIGN KEY (project_id) REFERENCES relay.projects(id)`},
	} {
		t.Run(drift.name, func(t *testing.T) {
			if _, err := ownerDB.ExecContext(ctx, drift.apply); err != nil {
				t.Fatal(err)
			}
			if err := app.Ready(ctx); err == nil {
				t.Fatal("readiness accepted secret-guard drift")
			}
			if _, err := ownerDB.ExecContext(ctx, drift.restore); err != nil {
				t.Fatalf("restore secret-guard drift: %v", err)
			}
			if err := app.Ready(ctx); err != nil {
				t.Fatalf("readiness did not recover: %v", err)
			}
		})
	}
}

func testMemoryQuarantineSchemaDriftIntegration(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB) {
	t.Helper()
	for _, drift := range []struct {
		name, apply, restore string
	}{
		{"extra delete", `GRANT DELETE ON brain.memory_quarantines TO punaro_app`, `REVOKE DELETE ON brain.memory_quarantines FROM punaro_app`},
		{"disabled fence", `ALTER TABLE brain.memory_secret_scans DISABLE TRIGGER application_mutation_fence`, `ALTER TABLE brain.memory_secret_scans ENABLE TRIGGER application_mutation_fence`},
		{"missing history index", `DROP INDEX brain.memory_quarantines_item_history`, `CREATE INDEX memory_quarantines_item_history ON brain.memory_quarantines (item_id, quarantined_at, id)`},
		{"unexpected column", `ALTER TABLE brain.secret_project_state ADD COLUMN unsafe text`, `ALTER TABLE brain.secret_project_state DROP COLUMN unsafe`},
		{"row security", `ALTER TABLE brain.memory_quarantines ENABLE ROW LEVEL SECURITY`, `ALTER TABLE brain.memory_quarantines DISABLE ROW LEVEL SECURITY`},
		{"scan primary key", `ALTER TABLE brain.memory_secret_scans DROP CONSTRAINT memory_secret_scans_pkey; ALTER TABLE brain.memory_secret_scans ADD CONSTRAINT memory_secret_scans_pkey UNIQUE (item_id,revision)`, `ALTER TABLE brain.memory_secret_scans DROP CONSTRAINT memory_secret_scans_pkey; ALTER TABLE brain.memory_secret_scans ADD CONSTRAINT memory_secret_scans_pkey PRIMARY KEY (item_id)`},
		{"released principal FK action", `ALTER TABLE brain.memory_quarantines DROP CONSTRAINT memory_quarantines_released_by_fkey; ALTER TABLE brain.memory_quarantines ADD CONSTRAINT memory_quarantines_released_by_fkey FOREIGN KEY (released_by) REFERENCES auth.principals(id) ON UPDATE CASCADE`, `ALTER TABLE brain.memory_quarantines DROP CONSTRAINT memory_quarantines_released_by_fkey; ALTER TABLE brain.memory_quarantines ADD CONSTRAINT memory_quarantines_released_by_fkey FOREIGN KEY (released_by) REFERENCES auth.principals(id)`},
		{"permissive scan generation", `ALTER TABLE brain.memory_secret_scans DROP CONSTRAINT memory_secret_scans_generation_check; ALTER TABLE brain.memory_secret_scans ADD CONSTRAINT memory_secret_scans_generation_check CHECK (exception_generation >= 0 OR true)`, `ALTER TABLE brain.memory_secret_scans DROP CONSTRAINT memory_secret_scans_generation_check; ALTER TABLE brain.memory_secret_scans ADD CONSTRAINT memory_secret_scans_generation_check CHECK (exception_generation >= 0)`},
	} {
		t.Run(drift.name, func(t *testing.T) {
			if _, err := ownerDB.ExecContext(ctx, drift.apply); err != nil {
				t.Fatal(err)
			}
			if err := app.Ready(ctx); err == nil {
				t.Fatal("readiness accepted memory-quarantine drift")
			}
			if _, err := ownerDB.ExecContext(ctx, drift.restore); err != nil {
				t.Fatalf("restore memory-quarantine drift: %v", err)
			}
			if err := app.Ready(ctx); err != nil {
				t.Fatalf("readiness did not recover: %v", err)
			}
		})
	}
}

func testCanonicalBrainIntegration(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB) {
	t.Helper()
	actor, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "memory actor")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "memory reader")
	if err != nil {
		t.Fatal(err)
	}
	outsider, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "memory outsider")
	if err != nil {
		t.Fatal(err)
	}
	var projectID, otherProjectID, retiredProjectID string
	if err := ownerDB.QueryRowContext(ctx, `INSERT INTO relay.projects (display_name,created_by) VALUES ('brain project',$1) RETURNING id::text`, actor.ID).Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if err := ownerDB.QueryRowContext(ctx, `INSERT INTO relay.projects (display_name,created_by) VALUES ('other brain project',$1) RETURNING id::text`, actor.ID).Scan(&otherProjectID); err != nil {
		t.Fatal(err)
	}
	if err := ownerDB.QueryRowContext(ctx, `INSERT INTO relay.projects (display_name,created_by,merged_into,merged_at) VALUES ('retired brain project',$1,$2,statement_timestamp()) RETURNING id::text`, actor.ID, projectID).Scan(&retiredProjectID); err != nil {
		t.Fatal(err)
	}
	for _, grant := range []struct {
		principal  string
		project    string
		capability Capability
	}{
		{actor.ID, projectID, CapabilityMemoryRead},
		{actor.ID, projectID, CapabilityMemoryWrite},
		{actor.ID, projectID, CapabilityMemoryPurge},
		{actor.ID, projectID, CapabilityMemoryAdminister},
		{reader.ID, projectID, CapabilityMemoryRead},
		{reader.ID, projectID, CapabilityMemoryWrite},
		{actor.ID, otherProjectID, CapabilityMemoryRead},
		{actor.ID, otherProjectID, CapabilityMemoryWrite},
		{actor.ID, otherProjectID, CapabilityMemoryAdminister},
	} {
		if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants (principal_id,scope,project_id,capability) VALUES ($1,'project',$2,$3)`, grant.principal, grant.project, grant.capability); err != nil {
			t.Fatal(err)
		}
	}
	allProjectsReader, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "all-project memory reader")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants (principal_id,scope,capability) VALUES ($1,'all_projects','memory.read')`, allProjectsReader.ID); err != nil {
		t.Fatal(err)
	}
	start, err := app.InstallationState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	secretDocument := json.RawMessage(`{"token":"resolved-value-123"}`)
	secretCreate := MemoryCreateRequest{
		PrincipalID: actor.ID, ProjectID: projectID,
		IdempotencyKey: "15151515-1515-4515-8515-151515151501",
		Kind:           "preference", Trust: "curated", Document: secretDocument,
	}
	beforeSecretRejection := readSecretGuardEffects(ctx, t, ownerDB)
	_, err = app.CreateMemory(ctx, secretCreate)
	var rejection MemorySecretRejection
	if !errors.As(err, &rejection) || rejection.Finding.RuleID != secretguard.RuleSensitiveField || rejection.Finding.FieldPath != "/token" || strings.Contains(err.Error(), "resolved-value-123") {
		t.Fatalf("secret create rejection=%#v err=%v", rejection, err)
	}
	sensitiveFinding := rejection.Finding
	if after := readSecretGuardEffects(ctx, t, ownerDB); after != beforeSecretRejection {
		t.Fatalf("rejected secret create effects before=%#v after=%#v", beforeSecretRejection, after)
	}
	otherProjectException, err := app.ApproveMemorySecretException(ctx, MemorySecretExceptionRequest{
		PrincipalID: actor.ID, ProjectID: otherProjectID, IdempotencyKey: "15151515-1515-4515-8515-151515151513",
		RuleID: sensitiveFinding.RuleID, FieldPath: sensitiveFinding.FieldPath, RuleVersion: sensitiveFinding.RuleVersion, Fingerprint: sensitiveFinding.Fingerprint,
	})
	if err != nil || !otherProjectException.Active {
		t.Fatalf("approve other-project exception: %v", err)
	}
	var exceptionOnlyProjectID string
	if err := ownerDB.QueryRowContext(ctx, `INSERT INTO relay.projects (display_name,created_by) VALUES ('exception-only brain project',$1) RETURNING id::text`, actor.ID).Scan(&exceptionOnlyProjectID); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants (principal_id,scope,project_id,capability) VALUES ($1,'project',$2,$3)`, actor.ID, exceptionOnlyProjectID, CapabilityMemoryAdminister); err != nil {
		t.Fatal(err)
	}
	retainedException, err := app.ApproveMemorySecretException(ctx, MemorySecretExceptionRequest{
		PrincipalID: actor.ID, ProjectID: exceptionOnlyProjectID, IdempotencyKey: "15151515-1515-4515-8515-151515151517",
		RuleID: sensitiveFinding.RuleID, FieldPath: sensitiveFinding.FieldPath, RuleVersion: sensitiveFinding.RuleVersion, Fingerprint: sensitiveFinding.Fingerprint,
	})
	if err != nil || !retainedException.Active {
		t.Fatalf("approve exception-only project exception=%#v err=%v", retainedException, err)
	}
	var exceptionOnlyHasScope bool
	if err := ownerDB.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM brain.scopes WHERE project_id=$1)`, exceptionOnlyProjectID).Scan(&exceptionOnlyHasScope); err != nil || exceptionOnlyHasScope {
		t.Fatalf("exception-only project scope=%v err=%v", exceptionOnlyHasScope, err)
	}
	assertExceptionMergeFence := func(state string) {
		t.Helper()
		mergeTx, beginErr := beginMutation(ctx, app.db)
		if beginErr != nil {
			t.Fatal(beginErr)
		}
		defer func() { _ = mergeTx.Rollback() }()
		if _, _, _, _, _, _, mergeErr := projectMergeCounts(ctx, mergeTx, actor.ID, exceptionOnlyProjectID, projectID); !errors.Is(mergeErr, ErrProjectMergeBrainState) {
			t.Fatalf("%s exception-only merge fence error=%v", state, mergeErr)
		}
	}
	assertExceptionMergeFence("active")
	retainedException, err = app.RevokeMemorySecretException(ctx, MemorySecretExceptionRevokeRequest{
		PrincipalID: actor.ID, ProjectID: exceptionOnlyProjectID, IdempotencyKey: "15151515-1515-4515-8515-151515151518", ExceptionID: retainedException.ExceptionID,
	})
	if err != nil || retainedException.Active {
		t.Fatalf("revoke exception-only project exception=%#v err=%v", retainedException, err)
	}
	assertExceptionMergeFence("revoked")
	secretCreate.IdempotencyKey = "15151515-1515-4515-8515-151515151514"
	beforeSecretRejection = readSecretGuardEffects(ctx, t, ownerDB)
	if _, err := app.CreateMemory(ctx, secretCreate); !errors.As(err, &rejection) {
		t.Fatalf("other-project exception allowed secret: %v", err)
	}
	if after := readSecretGuardEffects(ctx, t, ownerDB); after != beforeSecretRejection {
		t.Fatalf("other-project rejected effects before=%#v after=%#v", beforeSecretRejection, after)
	}
	wrongPath := sensitiveFinding
	wrongPath.FieldPath = "/other"
	if _, err := app.ApproveMemorySecretException(ctx, MemorySecretExceptionRequest{
		PrincipalID: actor.ID, ProjectID: projectID, IdempotencyKey: "15151515-1515-4515-8515-151515151502",
		RuleID: wrongPath.RuleID, FieldPath: wrongPath.FieldPath, RuleVersion: wrongPath.RuleVersion, Fingerprint: wrongPath.Fingerprint,
	}); err != nil {
		t.Fatalf("approve wrong-path exception: %v", err)
	}
	secretCreate.IdempotencyKey = "15151515-1515-4515-8515-151515151503"
	beforeSecretRejection = readSecretGuardEffects(ctx, t, ownerDB)
	if _, err := app.CreateMemory(ctx, secretCreate); !errors.As(err, &rejection) {
		t.Fatalf("wrong-path exception allowed secret: %v", err)
	}
	if after := readSecretGuardEffects(ctx, t, ownerDB); after != beforeSecretRejection {
		t.Fatalf("wrong-path rejected effects before=%#v after=%#v", beforeSecretRejection, after)
	}
	if _, err := app.ApproveMemorySecretException(ctx, MemorySecretExceptionRequest{
		PrincipalID: outsider.ID, ProjectID: projectID, IdempotencyKey: "15151515-1515-4515-8515-151515151507",
		RuleID: sensitiveFinding.RuleID, FieldPath: sensitiveFinding.FieldPath, RuleVersion: sensitiveFinding.RuleVersion, Fingerprint: sensitiveFinding.Fingerprint,
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unauthorized exception approval error=%v", err)
	}
	raceFindings, err := secretguard.ScanDocument([]byte(`{"password":"concurrent-value"}`))
	if err != nil || len(raceFindings) != 1 {
		t.Fatalf("concurrent exception finding=%#v err=%v", raceFindings, err)
	}
	type exceptionResult struct {
		result MemorySecretExceptionResult
		err    error
	}
	exceptionResults := make(chan exceptionResult, 2)
	for _, key := range []string{"15151515-1515-4515-8515-151515151509", "15151515-1515-4515-8515-151515151510"} {
		go func() {
			result, approveErr := app.ApproveMemorySecretException(ctx, MemorySecretExceptionRequest{
				PrincipalID: actor.ID, ProjectID: projectID, IdempotencyKey: key,
				RuleID: raceFindings[0].RuleID, FieldPath: raceFindings[0].FieldPath, RuleVersion: raceFindings[0].RuleVersion, Fingerprint: raceFindings[0].Fingerprint,
			})
			exceptionResults <- exceptionResult{result, approveErr}
		}()
	}
	firstException, secondException := <-exceptionResults, <-exceptionResults
	if firstException.err != nil || secondException.err != nil || firstException.result != secondException.result || !firstException.result.Active {
		t.Fatalf("concurrent exception approvals=%#v/%#v", firstException, secondException)
	}
	multiDocument := json.RawMessage(`{"value":"-----BEGIN PRIVATE KEY-----\nmaterial\nghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"}`)
	multiFindings, err := secretguard.ScanDocument(multiDocument)
	if err != nil || len(multiFindings) != 2 {
		t.Fatalf("multi-rule finding=%#v err=%v", multiFindings, err)
	}
	if _, err := app.ApproveMemorySecretException(ctx, MemorySecretExceptionRequest{
		PrincipalID: actor.ID, ProjectID: projectID, IdempotencyKey: "15151515-1515-4515-8515-151515151511",
		RuleID: multiFindings[0].RuleID, FieldPath: multiFindings[0].FieldPath, RuleVersion: multiFindings[0].RuleVersion, Fingerprint: multiFindings[0].Fingerprint,
	}); err != nil {
		t.Fatalf("approve first multi-rule finding: %v", err)
	}
	multiCreate := secretCreate
	multiCreate.IdempotencyKey = "15151515-1515-4515-8515-151515151512"
	multiCreate.Document = multiDocument
	beforeSecretRejection = readSecretGuardEffects(ctx, t, ownerDB)
	if _, err := app.CreateMemory(ctx, multiCreate); !errors.As(err, &rejection) || rejection.Finding.RuleID != secretguard.RuleBearerToken {
		t.Fatalf("excepted first rule hid second finding: rejection=%#v err=%v", rejection, err)
	}
	if after := readSecretGuardEffects(ctx, t, ownerDB); after != beforeSecretRejection {
		t.Fatalf("multi-rule rejected effects before=%#v after=%#v", beforeSecretRejection, after)
	}
	exception, err := app.ApproveMemorySecretException(ctx, MemorySecretExceptionRequest{
		PrincipalID: actor.ID, ProjectID: projectID, IdempotencyKey: "15151515-1515-4515-8515-151515151504",
		RuleID: sensitiveFinding.RuleID, FieldPath: sensitiveFinding.FieldPath, RuleVersion: sensitiveFinding.RuleVersion, Fingerprint: sensitiveFinding.Fingerprint,
	})
	if err != nil || !exception.Active {
		t.Fatalf("approve exact exception=%#v err=%v", exception, err)
	}
	otherProjectCreate := secretCreate
	otherProjectCreate.ProjectID = otherProjectID
	otherProjectCreate.IdempotencyKey = "15151515-1515-4515-8515-151515151505"
	if _, err := app.CreateMemory(ctx, otherProjectCreate); err != nil {
		t.Fatalf("exact exception did not allow create: %v", err)
	}
	guardTx, err := app.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := guardMemoryDocument(ctx, guardTx, projectID, secretDocument); err != nil {
		_ = guardTx.Rollback()
		t.Fatalf("lock exact exception for writer transaction: %v", err)
	}
	revokeDone := make(chan exceptionResult, 1)
	go func() {
		result, revokeErr := app.RevokeMemorySecretException(ctx, MemorySecretExceptionRevokeRequest{
			PrincipalID: actor.ID, ProjectID: projectID, IdempotencyKey: "15151515-1515-4515-8515-151515151506", ExceptionID: exception.ExceptionID,
		})
		revokeDone <- exceptionResult{result: result, err: revokeErr}
	}()
	waitDeadline := time.Now().Add(2 * time.Second)
	for {
		var waiting bool
		if err := ownerDB.QueryRowContext(ctx, `SELECT EXISTS (
SELECT 1 FROM pg_stat_activity
WHERE usename='punaro_app' AND wait_event_type='Lock'
  AND query LIKE 'SELECT revoked_at IS NULL FROM brain.secret_exceptions%FOR UPDATE')`).Scan(&waiting); err != nil {
			_ = guardTx.Rollback()
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case result := <-revokeDone:
			_ = guardTx.Rollback()
			t.Fatalf("revocation escaped the in-flight writer exception lock: %#v", result)
		default:
		}
		if time.Now().After(waitDeadline) {
			_ = guardTx.Rollback()
			t.Fatal("revocation did not wait for the in-flight writer exception lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := guardTx.Commit(); err != nil {
		t.Fatal(err)
	}
	var revoked MemorySecretExceptionResult
	select {
	case result := <-revokeDone:
		revoked, err = result.result, result.err
	case <-time.After(5 * time.Second):
		t.Fatal("revocation did not finish after the writer transaction committed")
	}
	if err != nil || revoked.Active || revoked.ExceptionID != exception.ExceptionID {
		t.Fatalf("revoke exception=%#v err=%v", revoked, err)
	}
	secretCreate.IdempotencyKey = "15151515-1515-4515-8515-151515151515"
	beforeSecretRejection = readSecretGuardEffects(ctx, t, ownerDB)
	if _, err := app.CreateMemory(ctx, secretCreate); !errors.As(err, &rejection) {
		t.Fatalf("revoked exception allowed later publication: %v", err)
	}
	if after := readSecretGuardEffects(ctx, t, ownerDB); after != beforeSecretRejection {
		t.Fatalf("post-revoke rejection effects before=%#v after=%#v", beforeSecretRejection, after)
	}
	create := MemoryCreateRequest{
		PrincipalID: actor.ID, ProjectID: projectID,
		IdempotencyKey: "14141414-1414-4414-8414-141414141401",
		LogicalKey:     "agent.preference", Kind: "preference", Trust: "curated",
		Document: json.RawMessage(`{"title":"Use focused tests","enabled":true,"numeric":1e0}`),
	}
	type createResult struct {
		result MemoryMutationResult
		err    error
	}
	started := make(chan struct{})
	results := make(chan createResult, 2)
	for range 2 {
		go func() {
			<-started
			result, createErr := app.CreateMemory(ctx, create)
			results <- createResult{result: result, err: createErr}
		}()
	}
	close(started)
	first, second := <-results, <-results
	if first.err != nil || second.err != nil || first.result != second.result {
		t.Fatalf("concurrent memory create=%#v/%#v", first, second)
	}
	created := first.result
	if created.Revision != 1 || created.State != MemoryActive || created.ETag == "" {
		t.Fatalf("created memory=%#v", created)
	}
	secretUpdate := MemoryUpdateRequest{
		PrincipalID: actor.ID, ProjectID: projectID, ItemID: created.ItemID,
		IdempotencyKey: "15151515-1515-4515-8515-151515151508", ExpectedETag: created.ETag,
		LogicalKey: create.LogicalKey, Kind: create.Kind, Trust: create.Trust, Document: secretDocument,
	}
	beforeSecretRejection = readSecretGuardEffects(ctx, t, ownerDB)
	if _, err := app.UpdateMemory(ctx, secretUpdate); !errors.As(err, &rejection) {
		t.Fatalf("secret update rejection=%v", err)
	}
	if after := readSecretGuardEffects(ctx, t, ownerDB); after != beforeSecretRejection {
		t.Fatalf("rejected secret update effects before=%#v after=%#v", beforeSecretRejection, after)
	}
	if retry, err := app.CreateMemory(ctx, create); err != nil || retry != created {
		t.Fatalf("exact create retry=%#v err=%v", retry, err)
	}
	changedCreate := create
	changedCreate.Document = json.RawMessage(`{"title":"changed retry"}`)
	if _, err := app.CreateMemory(ctx, changedCreate); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed create retry error=%v", err)
	}
	logicalConflict := create
	logicalConflict.IdempotencyKey = "14141414-1414-4414-8414-141414141402"
	if _, err := app.CreateMemory(ctx, logicalConflict); !errors.Is(err, ErrMemoryLogicalKeyConflict) {
		t.Fatalf("logical-key conflict error=%v", err)
	}
	otherScope := create
	otherScope.ProjectID = otherProjectID
	otherScope.IdempotencyKey = "14141414-1414-4414-8414-141414141403"
	if _, err := app.CreateMemory(ctx, otherScope); err != nil {
		t.Fatalf("same logical key in another project failed: %v", err)
	}

	item, err := app.GetMemory(ctx, reader.ID, projectID, created.ItemID)
	documentHash := sha256.Sum256(item.Document)
	if err != nil || item.ETag != created.ETag || item.Revision != 1 || item.ContentSHA256 != hex.EncodeToString(documentHash[:]) {
		t.Fatalf("memory get=%#v err=%v", item, err)
	}
	var decodedDocument map[string]any
	if json.Unmarshal(item.Document, &decodedDocument) != nil || decodedDocument["title"] != "Use focused tests" || decodedDocument["numeric"] != float64(1) {
		t.Fatalf("memory document changed semantics: %s", item.Document)
	}
	if _, err := app.GetMemory(ctx, outsider.ID, projectID, created.ItemID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unauthorized get error=%v", err)
	}
	if _, err := app.GetMemory(ctx, reader.ID, otherProjectID, created.ItemID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-project get error=%v", err)
	}
	testMemorySecretQuarantine(ctx, t, app, ownerDB, actor.ID, reader.ID, outsider.ID)
	for name, deniedCreate := range map[string]MemoryCreateRequest{
		"unauthorized": {
			PrincipalID: outsider.ID, ProjectID: projectID, IdempotencyKey: "14141414-1414-4414-8414-141414141421",
			Kind: "preference", Trust: "curated", Document: json.RawMessage(`{"title":"denied"}`),
		},
		"missing project": {
			PrincipalID: actor.ID, ProjectID: "14141414-1414-4414-8414-141414141499", IdempotencyKey: "14141414-1414-4414-8414-141414141422",
			Kind: "preference", Trust: "curated", Document: json.RawMessage(`{"title":"missing"}`),
		},
		"retired project": {
			PrincipalID: actor.ID, ProjectID: retiredProjectID, IdempotencyKey: "14141414-1414-4414-8414-141414141423",
			Kind: "preference", Trust: "curated", Document: json.RawMessage(`{"title":"retired"}`),
		},
	} {
		if _, err := app.CreateMemory(ctx, deniedCreate); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s create disclosed project state: %v", name, err)
		}
	}

	update := MemoryUpdateRequest{
		PrincipalID: actor.ID, ProjectID: projectID, ItemID: created.ItemID,
		IdempotencyKey: "14141414-1414-4414-8414-141414141404", ExpectedETag: created.ETag,
		LogicalKey: "agent.preference", Kind: "preference", Trust: "reviewed",
		Document: json.RawMessage(`{"title":"Second canonical revision"}`),
	}
	updated, err := app.UpdateMemory(ctx, update)
	if err != nil || updated.Revision != 2 || updated.ETag == created.ETag {
		t.Fatalf("memory update=%#v err=%v", updated, err)
	}
	if retry, err := app.UpdateMemory(ctx, update); err != nil || retry != updated {
		t.Fatalf("exact update retry=%#v err=%v", retry, err)
	}
	changedUpdate := update
	changedUpdate.Document = json.RawMessage(`{"title":"changed update retry"}`)
	if _, err := app.UpdateMemory(ctx, changedUpdate); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed update retry error=%v", err)
	}
	stale := update
	stale.IdempotencyKey = "14141414-1414-4414-8414-141414141405"
	stale.Document = json.RawMessage(`{"title":"must not persist"}`)
	beforeStale := readBrainEffects(ctx, t, ownerDB, created.ItemID, stale.IdempotencyKey, projectID)
	if _, err := app.UpdateMemory(ctx, stale); !errors.Is(err, ErrStaleMemoryETag) {
		t.Fatalf("stale update error=%v", err)
	}
	assertBrainEffects(ctx, t, ownerDB, created.ItemID, stale.IdempotencyKey, projectID, beforeStale)
	var revisionCount int
	if err := ownerDB.QueryRowContext(ctx, `SELECT count(*) FROM brain.memory_revisions WHERE item_id=$1`, created.ItemID).Scan(&revisionCount); err != nil || revisionCount != 2 {
		t.Fatalf("stale update revision count=%d err=%v", revisionCount, err)
	}

	archiveRequest := MemoryArchiveRequest{
		PrincipalID: actor.ID, ProjectID: projectID, ItemID: created.ItemID,
		IdempotencyKey: "14141414-1414-4414-8414-141414141406", ExpectedETag: updated.ETag, Archived: true,
	}
	archived, err := app.ArchiveMemory(ctx, archiveRequest)
	if err != nil || archived.Revision != 3 || archived.State != MemoryArchived {
		t.Fatalf("archive=%#v err=%v", archived, err)
	}
	if retry, err := app.ArchiveMemory(ctx, archiveRequest); err != nil || retry != archived {
		t.Fatalf("exact archive retry=%#v err=%v", retry, err)
	}
	changedArchive := archiveRequest
	changedArchive.Archived = false
	if _, err := app.ArchiveMemory(ctx, changedArchive); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed archive retry error=%v", err)
	}
	staleArchive := archiveRequest
	staleArchive.IdempotencyKey = "14141414-1414-4414-8414-141414141412"
	staleArchive.Archived = false
	beforeStale = readBrainEffects(ctx, t, ownerDB, created.ItemID, staleArchive.IdempotencyKey, projectID)
	if _, err := app.ArchiveMemory(ctx, staleArchive); !errors.Is(err, ErrStaleMemoryETag) {
		t.Fatalf("stale archive error=%v", err)
	}
	assertBrainEffects(ctx, t, ownerDB, created.ItemID, staleArchive.IdempotencyKey, projectID, beforeStale)
	if _, err := app.DeleteMemory(ctx, MemoryDeleteRequest{
		PrincipalID: reader.ID, ProjectID: projectID, ItemID: created.ItemID,
		IdempotencyKey: "14141414-1414-4414-8414-141414141407", ExpectedETag: archived.ETag,
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("writer without purge delete error=%v", err)
	}
	restored, err := app.ArchiveMemory(ctx, MemoryArchiveRequest{
		PrincipalID: actor.ID, ProjectID: projectID, ItemID: created.ItemID,
		IdempotencyKey: "14141414-1414-4414-8414-141414141408", ExpectedETag: archived.ETag, Archived: false,
	})
	if err != nil || restored.Revision != 4 || restored.State != MemoryActive {
		t.Fatalf("restore=%#v err=%v", restored, err)
	}
	abandonedTimeline := "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	abandonedSequence := restored.ChangeSequence + 1000
	abandonedTx, err := beginMutation(ctx, app.db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := abandonedTx.ExecContext(ctx, `INSERT INTO brain.memory_changes
(timeline_id,change_sequence,scope_id,item_id,operation,revision)
SELECT $1,$2,scope_id,id,'restore',current_revision FROM brain.memory_items WHERE id=$3`, abandonedTimeline, abandonedSequence, created.ItemID); err != nil {
		_ = abandonedTx.Rollback()
		t.Fatal(err)
	}
	if err := abandonedTx.Commit(); err != nil {
		t.Fatal(err)
	}
	timelineItem, err := app.GetMemory(ctx, reader.ID, projectID, created.ItemID)
	if err != nil || timelineItem.ChangeSequence != restored.ChangeSequence {
		t.Fatalf("current-timeline memory get=%#v want sequence=%d err=%v", timelineItem, restored.ChangeSequence, err)
	}
	cleanupAbandonedTx, err := beginMutation(ctx, ownerDB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cleanupAbandonedTx.ExecContext(ctx, `DELETE FROM brain.memory_changes WHERE timeline_id=$1 AND change_sequence=$2`, abandonedTimeline, abandonedSequence); err != nil {
		_ = cleanupAbandonedTx.Rollback()
		t.Fatal(err)
	}
	if err := cleanupAbandonedTx.Commit(); err != nil {
		t.Fatal(err)
	}
	var restoreAuditAction string
	if err := ownerDB.QueryRowContext(ctx, `SELECT action FROM audit.events WHERE target_id=$1 ORDER BY event_id DESC LIMIT 1`, created.ItemID).Scan(&restoreAuditAction); err != nil || restoreAuditAction != string(AuditMemoryRestore) {
		t.Fatalf("restore audit action=%q err=%v", restoreAuditAction, err)
	}
	noOpRestore := MemoryArchiveRequest{
		PrincipalID: actor.ID, ProjectID: projectID, ItemID: created.ItemID,
		IdempotencyKey: "14141414-1414-4414-8414-141414141413", ExpectedETag: restored.ETag, Archived: false,
	}
	unrelatedBeforeNoOp := otherScope
	unrelatedBeforeNoOp.IdempotencyKey = "14141414-1414-4414-8414-141414141416"
	unrelatedBeforeNoOp.LogicalKey = "unrelated.noop.sequence"
	unrelatedBeforeNoOp.Document = json.RawMessage(`{"title":"unrelated global sequence"}`)
	if _, err := app.CreateMemory(ctx, unrelatedBeforeNoOp); err != nil {
		t.Fatalf("unrelated activity before no-op: %v", err)
	}
	beforeNoOp := readBrainEffects(ctx, t, ownerDB, created.ItemID, noOpRestore.IdempotencyKey, projectID)
	if result, err := app.ArchiveMemory(ctx, noOpRestore); err != nil || result.Revision != restored.Revision || result.ETag != restored.ETag || result.ChangeSequence != restored.ChangeSequence {
		t.Fatalf("same-state restore=%#v err=%v", result, err)
	}
	afterNoOp := readBrainEffects(ctx, t, ownerDB, created.ItemID, noOpRestore.IdempotencyKey, projectID)
	expectedNoOp := beforeNoOp
	expectedNoOp.idempotency++
	if afterNoOp != expectedNoOp {
		t.Fatalf("same-state restore effects before=%#v after=%#v", beforeNoOp, afterNoOp)
	}
	func() {
		beforeRotation, err := app.InstallationState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		rotatedTimeline := "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
		if _, err := ownerDB.ExecContext(ctx, `UPDATE jobs.server_state SET timeline_id=$1 WHERE singleton`, rotatedTimeline); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, restoreErr := ownerDB.ExecContext(ctx, `UPDATE jobs.server_state SET timeline_id=$1 WHERE singleton`, beforeRotation.TimelineID); restoreErr != nil {
				t.Fatalf("restore brain test timeline: %v", restoreErr)
			}
		}()
		originNoOp := noOpRestore
		originNoOp.IdempotencyKey = "14141414-1414-4414-8414-141414141417"
		origin, err := app.ArchiveMemory(ctx, originNoOp)
		if err != nil || origin.Revision != restored.Revision || origin.ETag != restored.ETag || origin.ChangeSequence != 0 {
			t.Fatalf("timeline-origin no-op=%#v err=%v", origin, err)
		}
		if replay, err := app.ArchiveMemory(ctx, originNoOp); err != nil || replay != origin {
			t.Fatalf("timeline-origin no-op replay=%#v want=%#v err=%v", replay, origin, err)
		}
	}()
	if _, err := app.UpdateMemory(ctx, MemoryUpdateRequest{
		PrincipalID: actor.ID, ProjectID: projectID, ItemID: created.ItemID,
		IdempotencyKey: "14141414-1414-4414-8414-141414141409", ExpectedETag: archived.ETag,
		Kind: "preference", Trust: "curated", Document: json.RawMessage(`{"title":"stale after restore"}`),
	}); !errors.Is(err, ErrStaleMemoryETag) {
		t.Fatalf("pre-restore ETag update error=%v", err)
	}
	staleDelete := MemoryDeleteRequest{
		PrincipalID: actor.ID, ProjectID: projectID, ItemID: created.ItemID,
		IdempotencyKey: "14141414-1414-4414-8414-141414141414", ExpectedETag: archived.ETag,
	}
	beforeStale = readBrainEffects(ctx, t, ownerDB, created.ItemID, staleDelete.IdempotencyKey, projectID)
	if _, err := app.DeleteMemory(ctx, staleDelete); !errors.Is(err, ErrStaleMemoryETag) {
		t.Fatalf("stale delete error=%v", err)
	}
	assertBrainEffects(ctx, t, ownerDB, created.ItemID, staleDelete.IdempotencyKey, projectID, beforeStale)
	stateForACL, err := app.InstallationState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	directTombstoneTx, err := beginMutation(ctx, app.db)
	if err != nil {
		t.Fatal(err)
	}
	_, directTombstoneErr := directTombstoneTx.ExecContext(ctx, `INSERT INTO brain.memory_tombstones
(item_id,scope_id,deleted_by,timeline_id,change_sequence)
SELECT id,scope_id,$2,$3,$4 FROM brain.memory_items WHERE id=$1`, created.ItemID, actor.ID, stateForACL.TimelineID, restored.ChangeSequence)
	_ = directTombstoneTx.Rollback()
	if directTombstoneErr == nil {
		t.Fatal("application role inserted a memory tombstone directly")
	}
	var appTombstoneCount int
	if err := app.db.QueryRowContext(ctx, `SELECT count(*) FROM brain.memory_tombstones`).Scan(&appTombstoneCount); err == nil {
		t.Fatalf("application role read memory tombstones directly: count=%d", appTombstoneCount)
	}

	page, err := app.FetchMemoryChanges(ctx, MemoryChangeRequest{PrincipalID: reader.ID, ProjectID: projectID, Cursor: start, Limit: 2})
	if err != nil || len(page.Changes) != 2 || !page.More || page.Changes[0].Type != MemoryChangeCreate || page.Changes[1].Type != MemoryChangeUpdate {
		t.Fatalf("first memory change page=%#v err=%v", page, err)
	}
	if _, err := app.FetchMemoryChanges(ctx, MemoryChangeRequest{PrincipalID: outsider.ID, ProjectID: projectID, Cursor: start, Limit: 2}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unauthorized feed error=%v", err)
	}
	badOutsiderCursor := start
	badOutsiderCursor.TimelineID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	if _, err := app.FetchMemoryChanges(ctx, MemoryChangeRequest{PrincipalID: outsider.ID, ProjectID: projectID, Cursor: badOutsiderCursor, Limit: 2}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unauthorized malformed cursor leaked state: %v", err)
	}
	allProjectPage, err := app.FetchMemoryChanges(ctx, MemoryChangeRequest{PrincipalID: allProjectsReader.ID, ProjectID: projectID, Cursor: start, Limit: 2})
	if err != nil || len(allProjectPage.Changes) != 2 {
		t.Fatalf("all-project feed=%#v err=%v", allProjectPage, err)
	}
	allChanges := append([]MemoryChange(nil), page.Changes...)
	cursor := page.Cursor
	for page.More {
		page, err = app.FetchMemoryChanges(ctx, MemoryChangeRequest{PrincipalID: reader.ID, ProjectID: projectID, Cursor: cursor, Limit: 2})
		if err != nil {
			t.Fatal(err)
		}
		allChanges = append(allChanges, page.Changes...)
		cursor = page.Cursor
	}
	if len(allChanges) != 4 || allChanges[0].Type != MemoryChangeCreate || allChanges[1].Type != MemoryChangeUpdate || allChanges[2].Type != MemoryChangeArchive || allChanges[3].Type != MemoryChangeRestore {
		t.Fatalf("complete memory changes=%#v", allChanges)
	}
	gapSeen := false
	for index := 1; index < len(allChanges); index++ {
		if allChanges[index].ChangeSequence <= allChanges[index-1].ChangeSequence {
			t.Fatalf("non-monotonic memory changes=%#v", allChanges)
		}
		gapSeen = gapSeen || allChanges[index].ChangeSequence > allChanges[index-1].ChangeSequence+1
	}
	if !gapSeen {
		t.Fatal("project feed did not preserve the expected unrelated-project global sequence gap")
	}
	current, err := app.InstallationState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	future := current
	future.ChangeSequence++
	if _, err := app.FetchMemoryChanges(ctx, MemoryChangeRequest{PrincipalID: reader.ID, ProjectID: projectID, Cursor: future, Limit: 2}); !errors.Is(err, ErrCursorFromFuture) {
		t.Fatalf("future feed cursor error=%v", err)
	}
	wrongTimeline := current
	wrongTimeline.TimelineID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	if _, err := app.FetchMemoryChanges(ctx, MemoryChangeRequest{PrincipalID: reader.ID, ProjectID: projectID, Cursor: wrongTimeline, Limit: 2}); !errors.Is(err, ErrCursorTimelineChanged) {
		t.Fatalf("wrong timeline feed error=%v", err)
	}
	wrongInstallation := current
	wrongInstallation.InstallationID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	if _, err := app.FetchMemoryChanges(ctx, MemoryChangeRequest{PrincipalID: reader.ID, ProjectID: projectID, Cursor: wrongInstallation, Limit: 2}); !errors.Is(err, ErrCursorTimelineChanged) {
		t.Fatalf("wrong installation feed error=%v", err)
	}
	for _, limit := range []int{0, maxMemoryChangePage + 1} {
		if _, err := app.FetchMemoryChanges(ctx, MemoryChangeRequest{PrincipalID: reader.ID, ProjectID: projectID, Cursor: current, Limit: limit}); err == nil {
			t.Fatalf("invalid feed limit %d accepted", limit)
		}
	}
	mergeTx, err := beginMutation(ctx, app.db)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, _, _, err := projectMergeCounts(ctx, mergeTx, actor.ID, projectID, otherProjectID); !errors.Is(err, ErrProjectMergeBrainState) {
		_ = mergeTx.Rollback()
		t.Fatalf("live memory merge fence error=%v", err)
	}
	_ = mergeTx.Rollback()

	deleted, err := app.DeleteMemory(ctx, MemoryDeleteRequest{
		PrincipalID: actor.ID, ProjectID: projectID, ItemID: created.ItemID,
		IdempotencyKey: "14141414-1414-4414-8414-141414141410", ExpectedETag: restored.ETag,
	})
	if err != nil || deleted.ETag != "" || deleted.State != "" || deleted.Revision != restored.Revision {
		t.Fatalf("delete=%#v err=%v", deleted, err)
	}
	changedDelete := MemoryDeleteRequest{
		PrincipalID: actor.ID, ProjectID: projectID, ItemID: created.ItemID,
		IdempotencyKey: "14141414-1414-4414-8414-141414141410", ExpectedETag: archived.ETag,
	}
	if _, err := app.DeleteMemory(ctx, changedDelete); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed delete retry error=%v", err)
	}
	if _, err := app.GetMemory(ctx, reader.ID, projectID, created.ItemID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted get error=%v", err)
	}
	if err := ownerDB.QueryRowContext(ctx, `SELECT count(*) FROM brain.memory_revisions WHERE item_id=$1`, created.ItemID).Scan(&revisionCount); err != nil || revisionCount != 0 {
		t.Fatalf("purged revision count=%d err=%v", revisionCount, err)
	}
	var tombstoneCount int
	if err := ownerDB.QueryRowContext(ctx, `SELECT count(*) FROM brain.memory_tombstones WHERE item_id=$1`, created.ItemID).Scan(&tombstoneCount); err != nil || tombstoneCount != 1 {
		t.Fatalf("memory tombstone count=%d err=%v", tombstoneCount, err)
	}
	mergeTx, err = beginMutation(ctx, app.db)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, _, _, err := projectMergeCounts(ctx, mergeTx, actor.ID, projectID, otherProjectID); !errors.Is(err, ErrProjectMergeBrainState) {
		_ = mergeTx.Rollback()
		t.Fatalf("retained history merge fence error=%v", err)
	}
	_ = mergeTx.Rollback()
	var leaked bool
	if err := ownerDB.QueryRowContext(ctx, `SELECT
EXISTS (SELECT 1 FROM brain.memory_changes WHERE item_id=$1 AND (operation LIKE '%Second canonical revision%' OR scope_id::text LIKE '%Second canonical revision%'))
OR EXISTS (SELECT 1 FROM audit.events WHERE target_id=$1 AND (action LIKE '%Second canonical revision%' OR target_kind LIKE '%Second canonical revision%'))
OR EXISTS (SELECT 1 FROM relay.idempotency_records WHERE resource_id=$1 AND (result::text LIKE '%Second canonical revision%' OR result::text LIKE '%agent.preference%'))`, created.ItemID).Scan(&leaked); err != nil || leaked {
		t.Fatalf("hard-delete metadata leaked content=%v err=%v", leaked, err)
	}
	directCreate := create
	directCreate.IdempotencyKey = "14141414-1414-4414-8414-141414141415"
	directCreate.LogicalKey = "direct.purge"
	directCreate.Document = json.RawMessage(`{"title":"direct routine evidence"}`)
	directItem, err := app.CreateMemory(ctx, directCreate)
	if err != nil {
		t.Fatal(err)
	}
	directBefore, err := app.InstallationState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	directTx, err := beginMutation(ctx, app.db)
	if err != nil {
		t.Fatal(err)
	}
	var directScope, directTimeline string
	var directRevision, directSequence int64
	if err := directTx.QueryRowContext(ctx, `SELECT scope_id::text,revision,timeline_id::text,change_sequence
FROM brain.purge_memory($1::uuid,$2::uuid,$3::uuid,$4)`, actor.ID, projectID, directItem.ItemID, directItem.Revision).Scan(&directScope, &directRevision, &directTimeline, &directSequence); err != nil {
		_ = directTx.Rollback()
		t.Fatalf("direct purge routine failed: %v", err)
	}
	if err := directTx.Commit(); err != nil {
		t.Fatal(err)
	}
	if directRevision != directItem.Revision || directTimeline != directBefore.TimelineID || directSequence != directBefore.ChangeSequence+1 || !validOpaqueID(directScope) {
		t.Fatalf("direct purge evidence scope=%q revision=%d timeline=%q sequence=%d before=%#v", directScope, directRevision, directTimeline, directSequence, directBefore)
	}
	var directEvidence int
	if err := ownerDB.QueryRowContext(ctx, `SELECT
  (SELECT count(*) FROM brain.memory_tombstones WHERE item_id=$1)
 +(SELECT count(*) FROM brain.memory_changes WHERE item_id=$1 AND operation='delete')
 +(SELECT count(*) FROM audit.events WHERE target_id=$1 AND action='memory.delete')`, directItem.ItemID).Scan(&directEvidence); err != nil || directEvidence != 3 {
		t.Fatalf("direct purge evidence count=%d err=%v", directEvidence, err)
	}
	var purgeGrantID string
	if err := ownerDB.QueryRowContext(ctx, `UPDATE auth.capability_grants SET revoked_at=statement_timestamp()
WHERE principal_id=$1 AND project_id=$2 AND capability='memory.purge' AND revoked_at IS NULL RETURNING id::text`, actor.ID, projectID).Scan(&purgeGrantID); err != nil {
		t.Fatal(err)
	}
	if retry, err := app.DeleteMemory(ctx, MemoryDeleteRequest{
		PrincipalID: actor.ID, ProjectID: projectID, ItemID: created.ItemID,
		IdempotencyKey: "14141414-1414-4414-8414-141414141410", ExpectedETag: restored.ETag,
	}); err != nil || retry != deleted {
		t.Fatalf("delete retry after revocation=%#v err=%v", retry, err)
	}
	reuse := create
	reuse.IdempotencyKey = "14141414-1414-4414-8414-141414141411"
	if _, err := app.CreateMemory(ctx, reuse); err != nil {
		t.Fatalf("hard delete did not release logical key: %v", err)
	}
	if _, err := app.db.ExecContext(ctx, `UPDATE brain.memory_revisions SET document='{}'::jsonb WHERE item_id=$1`, created.ItemID); err == nil {
		t.Fatal("application role mutated an immutable memory revision")
	}
}

func testMemorySecretQuarantine(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB, actorID, readerID, outsiderID string) {
	t.Helper()
	var projectID string
	if err := ownerDB.QueryRowContext(ctx, `INSERT INTO relay.projects (display_name,created_by) VALUES ('quarantine brain project',$1) RETURNING id::text`, actorID).Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	for _, grant := range []struct {
		principal  string
		capability Capability
	}{
		{actorID, CapabilityMemoryRead},
		{actorID, CapabilityMemoryWrite},
		{actorID, CapabilityMemoryAdminister},
		{readerID, CapabilityMemoryRead},
	} {
		if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants (principal_id,scope,project_id,capability) VALUES ($1,'project',$2,$3)`, grant.principal, projectID, grant.capability); err != nil {
			t.Fatal(err)
		}
	}
	created, err := app.CreateMemory(ctx, MemoryCreateRequest{
		PrincipalID: actorID, ProjectID: projectID, IdempotencyKey: "16161616-1616-4616-8616-161616161601",
		LogicalKey: "legacy.secret", Kind: "preference", Trust: "curated", Document: json.RawMessage(`{"title":"legacy safe value"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := app.CreateMemory(ctx, MemoryCreateRequest{
		PrincipalID: actorID, ProjectID: projectID, IdempotencyKey: "16161616-1616-4616-8616-161616161610",
		LogicalKey: "legacy.second", Kind: "preference", Trust: "curated", Document: json.RawMessage(`{"title":"second legacy safe value"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	legacyDocument := `{"token":"resolved-legacy-value-123"}`
	if _, err := ownerDB.ExecContext(ctx, `UPDATE brain.memory_revisions
SET document=$2::jsonb,content_sha256=digest(($2::jsonb)::text,'sha256')
WHERE item_id=$1 AND revision=1`, created.ItemID, legacyDocument); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `DELETE FROM brain.memory_secret_scans WHERE item_id=$1`, created.ItemID); err != nil {
		t.Fatal(err)
	}
	secondLegacyDocument := `{"password":"second-legacy-value-456"}`
	if _, err := ownerDB.ExecContext(ctx, `UPDATE brain.memory_revisions
SET document=$2::jsonb,content_sha256=digest(($2::jsonb)::text,'sha256')
WHERE item_id=$1 AND revision=1`, second.ItemID, secondLegacyDocument); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `DELETE FROM brain.memory_secret_scans WHERE item_id=$1`, second.ItemID); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE brain.memory_revisions SET content_sha256=decode(repeat('00',32),'hex') WHERE item_id=$1 AND revision=1`, second.ItemID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.RescanMemorySecrets(ctx, MemorySecretRescanRequest{
		PrincipalID: actorID, ProjectID: projectID, IdempotencyKey: "16161616-1616-4616-8616-161616161615", Limit: 2,
	}); err == nil || strings.Contains(err.Error(), "second-legacy") {
		t.Fatalf("corrupt-candidate rescan error=%v", err)
	}
	var failedBatchEffects int
	if err := ownerDB.QueryRowContext(ctx, `SELECT
  (SELECT count(*) FROM brain.memory_quarantines AS quarantine JOIN brain.memory_items AS item ON item.id=quarantine.item_id JOIN brain.scopes AS scope ON scope.id=item.scope_id WHERE scope.project_id=$1)
+ (SELECT count(*) FROM brain.memory_secret_scans AS scan JOIN brain.memory_items AS item ON item.id=scan.item_id JOIN brain.scopes AS scope ON scope.id=item.scope_id WHERE scope.project_id=$1)
+ (SELECT count(*) FROM relay.idempotency_records WHERE key='16161616-1616-4616-8616-161616161615')`, projectID).Scan(&failedBatchEffects); err != nil || failedBatchEffects != 0 {
		t.Fatalf("failed rescan batch effects=%d err=%v", failedBatchEffects, err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE brain.memory_revisions SET content_sha256=digest(document::text,'sha256') WHERE item_id=$1 AND revision=1`, second.ItemID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.RescanMemorySecrets(ctx, MemorySecretRescanRequest{
		PrincipalID: readerID, ProjectID: projectID, IdempotencyKey: "16161616-1616-4616-8616-161616161611", Limit: 1,
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unauthorized secret rescan error=%v", err)
	}
	request := MemorySecretRescanRequest{
		PrincipalID: actorID, ProjectID: projectID, IdempotencyKey: "16161616-1616-4616-8616-161616161602", Limit: 1,
	}
	result, err := app.RescanMemorySecrets(ctx, request)
	if err != nil || result.Scanned != 1 || result.Quarantined != 1 || result.Released != 0 || !result.Remaining {
		t.Fatalf("secret rescan=%#v err=%v", result, err)
	}
	if retry, err := app.RescanMemorySecrets(ctx, request); err != nil || retry != result {
		t.Fatalf("secret rescan retry=%#v err=%v", retry, err)
	}
	changedRequest := request
	changedRequest.Limit = 2
	if _, err := app.RescanMemorySecrets(ctx, changedRequest); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed secret rescan retry error=%v", err)
	}
	secondBatch, err := app.RescanMemorySecrets(ctx, MemorySecretRescanRequest{
		PrincipalID: actorID, ProjectID: projectID, IdempotencyKey: "16161616-1616-4616-8616-161616161612", Limit: 1,
	})
	if err != nil || secondBatch.Scanned != 1 || secondBatch.Quarantined != 1 || secondBatch.Released != 0 || secondBatch.Remaining {
		t.Fatalf("second secret rescan batch=%#v err=%v", secondBatch, err)
	}
	if encoded, _ := json.Marshal(result); strings.Contains(string(encoded), "resolved-legacy") {
		t.Fatalf("secret rescan result leaked content: %s", encoded)
	}
	if _, err := app.GetMemory(ctx, readerID, projectID, created.ItemID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("quarantined ordinary get error=%v", err)
	}
	if _, err := app.ReviewMemorySecretQuarantine(ctx, outsiderID, projectID, created.ItemID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unauthorized quarantine review error=%v", err)
	}
	review, err := app.ReviewMemorySecretQuarantine(ctx, actorID, projectID, created.ItemID)
	var reviewedDocument map[string]any
	if err != nil || json.Unmarshal(review.Item.Document, &reviewedDocument) != nil || !review.Active || review.Item.ItemID != created.ItemID || reviewedDocument["token"] != "resolved-legacy-value-123" || review.Finding.RuleID != secretguard.RuleSensitiveField || review.Finding.FieldPath != "/token" {
		t.Fatalf("quarantine review=%#v err=%v", review, err)
	}
	secondReview, err := app.ReviewMemorySecretQuarantine(ctx, actorID, projectID, second.ItemID)
	if err != nil {
		t.Fatalf("second quarantine review: %v", err)
	}
	if _, err := app.UpdateMemory(ctx, MemoryUpdateRequest{
		PrincipalID: actorID, ProjectID: projectID, ItemID: second.ItemID,
		IdempotencyKey: "16161616-1616-4616-8616-161616161613", ExpectedETag: secondReview.Item.ETag,
		LogicalKey: "legacy.second", Kind: "preference", Trust: "curated", Document: json.RawMessage(`{"title":"second clean replacement"}`),
	}); err != nil {
		t.Fatalf("clean second quarantined item: %v", err)
	}
	noOp, err := app.RescanMemorySecrets(ctx, MemorySecretRescanRequest{
		PrincipalID: actorID, ProjectID: projectID, IdempotencyKey: "16161616-1616-4616-8616-161616161614", Limit: 2,
	})
	if err != nil || noOp.Scanned != 0 || noOp.Quarantined != 0 || noOp.Released != 0 || noOp.Remaining {
		t.Fatalf("completed no-op rescan=%#v err=%v", noOp, err)
	}
	archived, err := app.ArchiveMemory(ctx, MemoryArchiveRequest{
		PrincipalID: actorID, ProjectID: projectID, ItemID: created.ItemID,
		IdempotencyKey: "16161616-1616-4616-8616-161616161603", ExpectedETag: review.Item.ETag, Archived: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.GetMemory(ctx, readerID, projectID, created.ItemID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("archive escaped quarantine: %v", err)
	}
	restored, err := app.ArchiveMemory(ctx, MemoryArchiveRequest{
		PrincipalID: actorID, ProjectID: projectID, ItemID: created.ItemID,
		IdempotencyKey: "16161616-1616-4616-8616-161616161604", ExpectedETag: archived.ETag, Archived: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	exception, err := app.ApproveMemorySecretException(ctx, MemorySecretExceptionRequest{
		PrincipalID: actorID, ProjectID: projectID, IdempotencyKey: "16161616-1616-4616-8616-161616161605",
		RuleID: review.Finding.RuleID, FieldPath: review.Finding.FieldPath, RuleVersion: review.Finding.RuleVersion, Fingerprint: review.Finding.Fingerprint,
	})
	if err != nil {
		t.Fatal(err)
	}
	released, err := app.RescanMemorySecrets(ctx, MemorySecretRescanRequest{
		PrincipalID: actorID, ProjectID: projectID, IdempotencyKey: "16161616-1616-4616-8616-161616161606", Limit: 2,
	})
	if err != nil || released.Scanned != 2 || released.Quarantined != 0 || released.Released != 1 || released.Remaining {
		t.Fatalf("excepted rescan=%#v err=%v", released, err)
	}
	if item, err := app.GetMemory(ctx, readerID, projectID, created.ItemID); err != nil || json.Unmarshal(item.Document, &reviewedDocument) != nil || reviewedDocument["token"] != "resolved-legacy-value-123" || item.Revision != restored.Revision {
		t.Fatalf("released ordinary get=%#v err=%v", item, err)
	}
	if _, err := app.RevokeMemorySecretException(ctx, MemorySecretExceptionRevokeRequest{
		PrincipalID: actorID, ProjectID: projectID, IdempotencyKey: "16161616-1616-4616-8616-161616161607", ExceptionID: exception.ExceptionID,
	}); err != nil {
		t.Fatal(err)
	}
	requarantined, err := app.RescanMemorySecrets(ctx, MemorySecretRescanRequest{
		PrincipalID: actorID, ProjectID: projectID, IdempotencyKey: "16161616-1616-4616-8616-161616161608", Limit: 2,
	})
	if err != nil || requarantined.Scanned != 2 || requarantined.Quarantined != 1 || requarantined.Released != 0 || requarantined.Remaining {
		t.Fatalf("post-revoke rescan=%#v err=%v", requarantined, err)
	}
	cleaned, err := app.UpdateMemory(ctx, MemoryUpdateRequest{
		PrincipalID: actorID, ProjectID: projectID, ItemID: created.ItemID,
		IdempotencyKey: "16161616-1616-4616-8616-161616161609", ExpectedETag: restored.ETag,
		LogicalKey: "legacy.secret", Kind: "preference", Trust: "curated", Document: json.RawMessage(`{"title":"clean replacement"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if item, err := app.GetMemory(ctx, readerID, projectID, created.ItemID); err != nil || json.Unmarshal(item.Document, &reviewedDocument) != nil || item.Revision != cleaned.Revision || reviewedDocument["title"] != "clean replacement" {
		t.Fatalf("clean update release=%#v err=%v", item, err)
	}
	var metadataLeaked bool
	if err := ownerDB.QueryRowContext(ctx, `SELECT
EXISTS (SELECT 1 FROM audit.events WHERE project_id=$1 AND to_jsonb(audit.events)::text LIKE ANY (ARRAY['%resolved-legacy%','%second-legacy%']))
OR EXISTS (SELECT 1 FROM relay.idempotency_records WHERE to_jsonb(relay.idempotency_records)::text LIKE ANY (ARRAY['%resolved-legacy%','%second-legacy%']))
OR EXISTS (SELECT 1 FROM brain.memory_changes AS change JOIN brain.scopes AS scope ON scope.id=change.scope_id WHERE scope.project_id=$1 AND to_jsonb(change)::text LIKE ANY (ARRAY['%resolved-legacy%','%second-legacy%']))
OR EXISTS (SELECT 1 FROM brain.memory_quarantines AS quarantine JOIN brain.memory_items AS item ON item.id=quarantine.item_id JOIN brain.scopes AS scope ON scope.id=item.scope_id WHERE scope.project_id=$1 AND to_jsonb(quarantine)::text LIKE ANY (ARRAY['%resolved-legacy%','%second-legacy%']))`, projectID).Scan(&metadataLeaked); err != nil || metadataLeaked {
		t.Fatalf("quarantine metadata leaked content=%v err=%v", metadataLeaked, err)
	}
}

type brainEffects struct {
	revisions         int
	changes           int
	audits            int
	idempotency       int
	changeSequence    int64
	contentGeneration int64
}

func readBrainEffects(ctx context.Context, t *testing.T, ownerDB *sql.DB, itemID, idempotencyKey, projectID string) brainEffects {
	t.Helper()
	var effects brainEffects
	if err := ownerDB.QueryRowContext(ctx, `SELECT
  (SELECT count(*) FROM brain.memory_revisions WHERE item_id=$1),
  (SELECT count(*) FROM brain.memory_changes WHERE item_id=$1),
  (SELECT count(*) FROM audit.events WHERE target_id=$1 AND action LIKE 'memory.%'),
	  (SELECT count(*) FROM relay.idempotency_records WHERE key=$2),
	  (SELECT change_sequence FROM jobs.server_state WHERE singleton),
	  (SELECT content_generation FROM relay.projects WHERE id=$3)`, itemID, idempotencyKey, projectID).Scan(&effects.revisions, &effects.changes, &effects.audits, &effects.idempotency, &effects.changeSequence, &effects.contentGeneration); err != nil {
		t.Fatal(err)
	}
	return effects
}

func assertBrainEffects(ctx context.Context, t *testing.T, ownerDB *sql.DB, itemID, idempotencyKey, projectID string, want brainEffects) {
	t.Helper()
	if got := readBrainEffects(ctx, t, ownerDB, itemID, idempotencyKey, projectID); got != want {
		t.Fatalf("memory failure changed state: got=%#v want=%#v", got, want)
	}
}

type secretGuardEffects struct {
	items, revisions, changes, audits, idempotency, jobs, scopes int
	scans, quarantines, projectStates                            int
	changeSequence, contentGeneration                            int64
}

func readSecretGuardEffects(ctx context.Context, t *testing.T, ownerDB *sql.DB) secretGuardEffects {
	t.Helper()
	var effects secretGuardEffects
	if err := ownerDB.QueryRowContext(ctx, `SELECT
  (SELECT count(*) FROM brain.memory_items),
  (SELECT count(*) FROM brain.memory_revisions),
  (SELECT count(*) FROM brain.memory_changes),
  (SELECT count(*) FROM audit.events),
  (SELECT count(*) FROM relay.idempotency_records),
  (SELECT count(*) FROM jobs.outbox),
  (SELECT count(*) FROM brain.scopes),
  (SELECT count(*) FROM brain.memory_secret_scans),
  (SELECT count(*) FROM brain.memory_quarantines),
  (SELECT count(*) FROM brain.secret_project_state),
  (SELECT change_sequence FROM jobs.server_state WHERE singleton),
  (SELECT sum(content_generation) FROM relay.projects)`).Scan(
		&effects.items, &effects.revisions, &effects.changes, &effects.audits,
		&effects.idempotency, &effects.jobs, &effects.scopes,
		&effects.scans, &effects.quarantines, &effects.projectStates,
		&effects.changeSequence, &effects.contentGeneration,
	); err != nil {
		t.Fatal(err)
	}
	return effects
}
