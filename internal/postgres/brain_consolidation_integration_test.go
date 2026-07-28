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
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants(principal_id,scope,project_id,capability) VALUES ($1,'project',$2,$3)`, actor.ID, projectID, CapabilityMemoryWrite); err != nil {
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
	if err := app.AdvanceMemoryConsolidationCheckpoint(ctx, first, first.TimelineID, 3); !errors.Is(err, ErrStaleMemoryConsolidationLease) {
		t.Fatalf("stale consolidation advance error=%v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE brain.memory_consolidation_checkpoints SET lease_until=statement_timestamp()-interval '1 second' WHERE scope_id=$1`, scopeID); err != nil {
		t.Fatal(err)
	}
	fourth, claimed, err := app.ClaimMemoryConsolidationCheckpoint(ctx, scopeID, "44444444-4444-4444-8444-444444444444", memoryEmbeddingMinLease)
	if err != nil || !claimed || fourth.Generation <= third.Generation || fourth.Sequence != third.Sequence {
		t.Fatalf("expired consolidation reclaim=%#v third=%#v claimed=%t err=%v", fourth, third, claimed, err)
	}
	if err := app.AdvanceMemoryConsolidationCheckpoint(ctx, second, second.TimelineID, 3); !errors.Is(err, ErrStaleMemoryConsolidationLease) {
		t.Fatalf("expired consolidation lease advance error=%v", err)
	}
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
