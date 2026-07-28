package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
)

func testMemoryConsolidationCheckpointIntegration(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB) {
	t.Helper()
	actor, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "consolidation checkpoint actor")
	if err != nil {
		t.Fatal(err)
	}
	var projectID, scopeID string
	if err := ownerDB.QueryRowContext(ctx, `INSERT INTO relay.projects(display_name,created_by) VALUES ('consolidation checkpoint project',$1) RETURNING id::text`, actor.ID).Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if err := ownerDB.QueryRowContext(ctx, `INSERT INTO brain.scopes(project_id,created_by) VALUES ($1,$2) RETURNING id::text`, projectID, actor.ID).Scan(&scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants(principal_id,scope,project_id,capability) VALUES ($1,'project',$2,$3),($1,'project',$2,$4)`, actor.ID, projectID, CapabilityMemoryWrite, CapabilityMemoryPurge); err != nil {
		t.Fatal(err)
	}
	first, claimed, err := app.ClaimMemoryConsolidationCheckpoint(ctx, scopeID, "11111111-1111-4111-8111-111111111111", memoryEmbeddingMinLease)
	if err != nil || !claimed || first.TimelineID == "" || first.Sequence != 0 {
		t.Fatalf("first consolidation claim=%#v claimed=%t err=%v", first, claimed, err)
	}
	input, err := app.ReadMemoryConsolidationInput(ctx, first)
	if err != nil || input.Lease != first || input.TimelineID != first.TimelineID || input.NextSequence != first.Sequence || len(input.Sources) != 0 {
		t.Fatalf("initial consolidation input=%#v err=%v", input, err)
	}
	created := make([]MemoryMutationResult, 0, 2)
	for index := 0; index < 2; index++ {
		result, createErr := app.CreateMemory(ctx, MemoryCreateRequest{PrincipalID: actor.ID, ProjectID: projectID, IdempotencyKey: []string{"11111111-1111-4111-8111-111111111112", "11111111-1111-4111-8111-111111111113"}[index], LogicalKey: []string{"consolidation.first", "consolidation.second"}[index], Kind: "fact", Trust: "curated", Document: json.RawMessage(`{"source":true}`)})
		if createErr != nil {
			t.Fatal(createErr)
		}
		created = append(created, result)
	}
	input, err = app.ReadMemoryConsolidationInput(ctx, first)
	if err != nil || len(input.Sources) != len(created) || input.NextSequence != created[len(created)-1].ChangeSequence || input.Sources[0].ItemID != created[0].ItemID || input.Sources[1].Revision != created[1].Revision {
		t.Fatalf("post-claim consolidation input=%#v created=%#v err=%v", input, created, err)
	}
	if _, claimed, err := app.ClaimMemoryConsolidationCheckpoint(ctx, scopeID, "22222222-2222-4222-8222-222222222222", memoryEmbeddingMinLease); err != nil || claimed {
		t.Fatalf("duplicate consolidation claim claimed=%t err=%v", claimed, err)
	}
	if err := app.AdvanceMemoryConsolidationCheckpoint(ctx, first, "33333333-3333-4333-8333-333333333333", 1); !errors.Is(err, ErrStaleMemoryConsolidationLease) {
		t.Fatalf("future or foreign cursor advance error=%v", err)
	}
	if err := app.AdvanceMemoryConsolidationCheckpoint(ctx, first, first.TimelineID, 1<<60); !errors.Is(err, ErrStaleMemoryConsolidationLease) {
		t.Fatalf("future sequence advance error=%v", err)
	}
	if err := app.AdvanceMemoryConsolidationCheckpoint(ctx, first, first.TimelineID, 2); err != nil {
		t.Fatalf("advance consolidation checkpoint: %v", err)
	}
	if _, err := app.ReadMemoryConsolidationInput(ctx, first); !errors.Is(err, ErrStaleMemoryConsolidationLease) {
		t.Fatalf("released consolidation input error=%v", err)
	}
	second, claimed, err := app.ClaimMemoryConsolidationCheckpoint(ctx, scopeID, "22222222-2222-4222-8222-222222222222", memoryEmbeddingMinLease)
	if err != nil || !claimed || second.TimelineID != first.TimelineID || second.Sequence != 2 || second.Generation <= first.Generation {
		t.Fatalf("durable consolidation reclaim=%#v first=%#v claimed=%t err=%v", second, first, claimed, err)
	}
	quarantined, err := app.CreateMemory(ctx, MemoryCreateRequest{PrincipalID: actor.ID, ProjectID: projectID, IdempotencyKey: "11111111-1111-4111-8111-111111111114", LogicalKey: "consolidation.quarantined", Kind: "fact", Trust: "curated", Document: json.RawMessage(`{"source":"quarantined"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO brain.memory_quarantines(item_id,detected_revision,rule_version,rule_id,field_path,value_fingerprint,quarantined_by)
VALUES ($1,$2,1,'sensitive-field','/source',decode(repeat('11',32),'hex'),$3)`, quarantined.ItemID, quarantined.Revision, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE brain.memory_quarantines SET released_by=$2,released_at=statement_timestamp() WHERE item_id=$1 AND released_at IS NULL`, quarantined.ItemID, actor.ID); err != nil {
		t.Fatal(err)
	}
	clean, err := app.UpdateMemory(ctx, MemoryUpdateRequest{PrincipalID: actor.ID, ProjectID: projectID, ItemID: quarantined.ItemID, IdempotencyKey: "11111111-1111-4111-8111-111111111115", ExpectedETag: quarantined.ETag, LogicalKey: "consolidation.quarantined", Kind: "fact", Trust: "curated", Document: json.RawMessage(`{"source":"clean"}`)})
	if err != nil {
		t.Fatal(err)
	}
	input, err = app.ReadMemoryConsolidationInput(ctx, second)
	if err != nil || len(input.Sources) != 1 || input.NextSequence != clean.ChangeSequence || input.Sources[0].ItemID != clean.ItemID || input.Sources[0].Revision != clean.Revision {
		t.Fatalf("released-quarantine consolidation input=%#v quarantined=%#v clean=%#v err=%v", input, quarantined, clean, err)
	}
	if err := app.AdvanceMemoryConsolidationCheckpoint(ctx, second, second.TimelineID, input.NextSequence); err != nil {
		t.Fatalf("advance released-quarantine consolidation checkpoint: %v", err)
	}
	third, claimed, err := app.ClaimMemoryConsolidationCheckpoint(ctx, scopeID, "33333333-3333-4333-8333-333333333333", memoryEmbeddingMinLease)
	if err != nil || !claimed || third.Sequence != clean.ChangeSequence || third.Generation <= second.Generation {
		t.Fatalf("released-quarantine consolidation reclaim=%#v clean=%#v second=%#v claimed=%t err=%v", third, clean, second, claimed, err)
	}
	input, err = app.ReadMemoryConsolidationInput(ctx, third)
	if err != nil || len(input.Sources) != 0 || input.NextSequence != third.Sequence {
		t.Fatalf("released quarantine replayed historical source=%#v err=%v", input, err)
	}
	purged, err := app.CreateMemory(ctx, MemoryCreateRequest{PrincipalID: actor.ID, ProjectID: projectID, IdempotencyKey: "11111111-1111-4111-8111-111111111116", LogicalKey: "consolidation.purged", Kind: "fact", Trust: "curated", Document: json.RawMessage(`{"source":"purged"}`)})
	if err != nil {
		t.Fatal(err)
	}
	purged, err = app.DeleteMemory(ctx, MemoryDeleteRequest{PrincipalID: actor.ID, ProjectID: projectID, ItemID: purged.ItemID, IdempotencyKey: "11111111-1111-4111-8111-111111111117", ExpectedETag: purged.ETag})
	if err != nil {
		t.Fatal(err)
	}
	input, err = app.ReadMemoryConsolidationInput(ctx, third)
	if err != nil || len(input.Sources) != 0 || input.NextSequence != purged.ChangeSequence {
		t.Fatalf("purged revisions remained materializable=%#v purged=%#v err=%v", input, purged, err)
	}
	if err := app.AdvanceMemoryConsolidationCheckpoint(ctx, third, third.TimelineID, input.NextSequence); err != nil {
		t.Fatalf("advance purged consolidation cursor: %v", err)
	}
	if err := app.AdvanceMemoryConsolidationCheckpoint(ctx, first, first.TimelineID, 3); !errors.Is(err, ErrStaleMemoryConsolidationLease) {
		t.Fatalf("stale consolidation advance error=%v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE brain.memory_consolidation_checkpoints SET lease_until=statement_timestamp()-interval '1 second' WHERE scope_id=$1`, scopeID); err != nil {
		t.Fatal(err)
	}
	fourth, claimed, err := app.ClaimMemoryConsolidationCheckpoint(ctx, scopeID, "44444444-4444-4444-8444-444444444444", memoryEmbeddingMinLease)
	if err != nil || !claimed || fourth.Generation <= third.Generation || fourth.Sequence != input.NextSequence {
		t.Fatalf("expired consolidation reclaim=%#v input=%#v claimed=%t err=%v", fourth, input, claimed, err)
	}
	archived, err := app.CreateMemory(ctx, MemoryCreateRequest{PrincipalID: actor.ID, ProjectID: projectID, IdempotencyKey: "11111111-1111-4111-8111-111111111118", LogicalKey: "consolidation.archived", Kind: "fact", Trust: "curated", Document: json.RawMessage(`{"source":"archived"}`)})
	if err != nil {
		t.Fatal(err)
	}
	archived, err = app.ArchiveMemory(ctx, MemoryArchiveRequest{PrincipalID: actor.ID, ProjectID: projectID, ItemID: archived.ItemID, IdempotencyKey: "11111111-1111-4111-8111-111111111119", ExpectedETag: archived.ETag, Archived: true})
	if err != nil {
		t.Fatal(err)
	}
	input, err = app.ReadMemoryConsolidationInput(ctx, fourth)
	if err != nil || len(input.Sources) != 0 || input.NextSequence != archived.ChangeSequence {
		t.Fatalf("archived revisions remained materializable=%#v archived=%#v err=%v", input, archived, err)
	}
	if err := app.AdvanceMemoryConsolidationCheckpoint(ctx, second, second.TimelineID, 3); !errors.Is(err, ErrStaleMemoryConsolidationLease) {
		t.Fatalf("expired consolidation lease advance error=%v", err)
	}
	testMemoryConsolidationRestoreLineageIntegration(ctx, t, app, ownerDB, actor.ID, projectID)
}

func testMemoryConsolidationRestoreLineageIntegration(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB, actorID, projectID string) {
	t.Helper()
	var scopeID string
	if err := ownerDB.QueryRowContext(ctx, `INSERT INTO brain.scopes(project_id,created_by) VALUES ($1,$2) RETURNING id::text`, projectID, actorID).Scan(&scopeID); err != nil {
		t.Fatal(err)
	}
	rootSource, err := app.CreateMemory(ctx, MemoryCreateRequest{PrincipalID: actorID, ProjectID: projectID, IdempotencyKey: "11111111-1111-4111-8111-111111111120", LogicalKey: "consolidation.restore.root", Kind: "fact", Trust: "curated", Document: json.RawMessage(`{"source":"root"}`)})
	if err != nil {
		t.Fatal(err)
	}
	rootLease, claimed, err := app.ClaimMemoryConsolidationCheckpoint(ctx, scopeID, "55555555-5555-4555-8555-555555555555", memoryEmbeddingMinLease)
	if err != nil || !claimed {
		t.Fatalf("root consolidation claim lease=%#v claimed=%t err=%v", rootLease, claimed, err)
	}
	input, err := app.ReadMemoryConsolidationInput(ctx, rootLease)
	if err != nil || len(input.Sources) != 1 || input.Sources[0].ItemID != rootSource.ItemID || input.NextSequence != rootSource.ChangeSequence {
		t.Fatalf("root consolidation input=%#v source=%#v err=%v", input, rootSource, err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE brain.memory_consolidation_checkpoints SET lease_until=statement_timestamp()-interval '1 second' WHERE scope_id=$1`, scopeID); err != nil {
		t.Fatal(err)
	}
	_, firstRestoredTimeline, firstRestoreSequence := rotateConsolidationTestTimeline(ctx, t, ownerDB)
	rootReplay, claimed, err := app.ClaimMemoryConsolidationCheckpoint(ctx, scopeID, "66666666-6666-4666-8666-666666666666", memoryEmbeddingMinLease)
	if err != nil || !claimed || rootReplay.TimelineID != rootLease.TimelineID || rootReplay.Sequence != 0 || rootReplay.Generation <= rootLease.Generation {
		t.Fatalf("root crash reclaim lease=%#v prior=%#v claimed=%t err=%v", rootReplay, rootLease, claimed, err)
	}
	input, err = app.ReadMemoryConsolidationInput(ctx, rootReplay)
	if err != nil || len(input.Sources) != 1 || input.Sources[0].ItemID != rootSource.ItemID || input.NextSequence != firstRestoreSequence {
		t.Fatalf("single-hop replay input=%#v source=%#v restore_sequence=%d err=%v", input, rootSource, firstRestoreSequence, err)
	}
	if err := app.AdvanceMemoryConsolidationCheckpoint(ctx, rootReplay, rootReplay.TimelineID, input.NextSequence); err != nil {
		t.Fatalf("drain root restore edge: %v", err)
	}
	firstLease, claimed, err := app.ClaimMemoryConsolidationCheckpoint(ctx, scopeID, "77777777-7777-4777-8777-777777777777", memoryEmbeddingMinLease)
	if err != nil || !claimed || firstLease.TimelineID != firstRestoredTimeline || firstLease.Sequence != 0 {
		t.Fatalf("single-hop rebase lease=%#v restored_timeline=%q claimed=%t err=%v", firstLease, firstRestoredTimeline, claimed, err)
	}
	middleSource, err := app.CreateMemory(ctx, MemoryCreateRequest{PrincipalID: actorID, ProjectID: projectID, IdempotencyKey: "11111111-1111-4111-8111-111111111121", LogicalKey: "consolidation.restore.middle", Kind: "fact", Trust: "curated", Document: json.RawMessage(`{"source":"middle"}`)})
	if err != nil {
		t.Fatal(err)
	}
	input, err = app.ReadMemoryConsolidationInput(ctx, firstLease)
	if err != nil || len(input.Sources) != 1 || input.Sources[0].ItemID != middleSource.ItemID || input.NextSequence != middleSource.ChangeSequence {
		t.Fatalf("first restored consolidation input=%#v source=%#v err=%v", input, middleSource, err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE brain.memory_consolidation_checkpoints SET lease_until=statement_timestamp()-interval '1 second' WHERE scope_id=$1`, scopeID); err != nil {
		t.Fatal(err)
	}
	_, secondRestoredTimeline, secondRestoreSequence := rotateConsolidationTestTimeline(ctx, t, ownerDB)
	firstReplay, claimed, err := app.ClaimMemoryConsolidationCheckpoint(ctx, scopeID, "88888888-8888-4888-8888-888888888888", memoryEmbeddingMinLease)
	if err != nil || !claimed || firstReplay.TimelineID != firstRestoredTimeline || firstReplay.Sequence != 0 || firstReplay.Generation <= firstLease.Generation {
		t.Fatalf("first restore crash reclaim lease=%#v prior=%#v claimed=%t err=%v", firstReplay, firstLease, claimed, err)
	}
	input, err = app.ReadMemoryConsolidationInput(ctx, firstReplay)
	if err != nil || len(input.Sources) != 1 || input.Sources[0].ItemID != middleSource.ItemID || input.NextSequence != secondRestoreSequence {
		t.Fatalf("multi-hop replay input=%#v source=%#v restore_sequence=%d err=%v", input, middleSource, secondRestoreSequence, err)
	}
	if err := app.AdvanceMemoryConsolidationCheckpoint(ctx, firstReplay, firstReplay.TimelineID, input.NextSequence); err != nil {
		t.Fatalf("drain second restore edge: %v", err)
	}
	secondLease, claimed, err := app.ClaimMemoryConsolidationCheckpoint(ctx, scopeID, "99999999-9999-4999-8999-999999999999", memoryEmbeddingMinLease)
	if err != nil || !claimed || secondLease.TimelineID != secondRestoredTimeline || secondLease.Sequence != 0 {
		t.Fatalf("multi-hop rebase lease=%#v restored_timeline=%q claimed=%t err=%v", secondLease, secondRestoredTimeline, claimed, err)
	}
	input, err = app.ReadMemoryConsolidationInput(ctx, secondLease)
	if err != nil || len(input.Sources) != 0 || input.NextSequence != 0 {
		t.Fatalf("second restored timeline retained replayed sources input=%#v err=%v", input, err)
	}
}

func rotateConsolidationTestTimeline(ctx context.Context, t *testing.T, ownerDB *sql.DB) (string, string, int64) {
	t.Helper()
	var previousTimeline, restoredTimeline string
	var restoreSequence int64
	if err := ownerDB.QueryRowContext(ctx, `WITH prior AS (
    SELECT installation_id,timeline_id,change_sequence FROM jobs.server_state WHERE singleton FOR UPDATE
), rotated AS (
    UPDATE jobs.server_state SET timeline_id=gen_random_uuid(),timeline_started_at=statement_timestamp()
    WHERE singleton RETURNING timeline_id
), event AS (
    INSERT INTO jobs.restore_events(restore_id,backup_id,installation_id,previous_timeline_id,restored_timeline_id,restored_change_sequence)
    SELECT gen_random_uuid(),gen_random_uuid(),prior.installation_id,prior.timeline_id,rotated.timeline_id,prior.change_sequence FROM prior,rotated
)
SELECT prior.timeline_id::text,rotated.timeline_id::text,prior.change_sequence FROM prior,rotated`).Scan(&previousTimeline, &restoredTimeline, &restoreSequence); err != nil {
		t.Fatalf("seed restore lineage edge: %v", err)
	}
	return previousTimeline, restoredTimeline, restoreSequence
}

func testMemoryConsolidationSchemaDriftIntegration(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB) {
	t.Helper()
	for _, drift := range []struct{ apply, restore string }{
		{`GRANT SELECT ON brain.memory_consolidation_checkpoints TO punaro_app`, `REVOKE SELECT ON brain.memory_consolidation_checkpoints FROM punaro_app`},
		{`GRANT EXECUTE ON FUNCTION brain.claim_memory_consolidation_checkpoint(uuid,uuid,bigint) TO PUBLIC`, `REVOKE EXECUTE ON FUNCTION brain.claim_memory_consolidation_checkpoint(uuid,uuid,bigint) FROM PUBLIC`},
	} {
		if _, err := ownerDB.ExecContext(ctx, drift.apply); err != nil {
			t.Fatal(err)
		}
		if err := app.Ready(ctx); err == nil {
			t.Fatal("readiness accepted consolidation schema drift")
		}
		if _, err := ownerDB.ExecContext(ctx, drift.restore); err != nil {
			t.Fatal(err)
		}
		if err := app.Ready(ctx); err != nil {
			t.Fatalf("readiness did not recover after consolidation drift: %v", err)
		}
	}
}
