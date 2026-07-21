package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
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
		{reader.ID, projectID, CapabilityMemoryRead},
		{reader.ID, projectID, CapabilityMemoryWrite},
		{actor.ID, otherProjectID, CapabilityMemoryRead},
		{actor.ID, otherProjectID, CapabilityMemoryWrite},
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
