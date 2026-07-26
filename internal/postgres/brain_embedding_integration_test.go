package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
)

func testMemoryEmbeddingSchemaDriftIntegration(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB) {
	t.Helper()
	for _, drift := range []struct {
		name, apply, restore string
	}{
		{"application write", `GRANT INSERT ON brain.embedding_jobs TO punaro_app`, `REVOKE INSERT ON brain.embedding_jobs FROM punaro_app`},
		{"application read", `REVOKE SELECT ON brain.embedding_generations FROM punaro_app`, `GRANT SELECT ON brain.embedding_generations TO punaro_app`},
		{"queue trigger", `ALTER TABLE brain.memory_revisions DISABLE TRIGGER memory_revision_embedding_queue`, `ALTER TABLE brain.memory_revisions ENABLE TRIGGER memory_revision_embedding_queue`},
		{"claim index", `DROP INDEX brain.embedding_jobs_claim_order`, `CREATE INDEX embedding_jobs_claim_order ON brain.embedding_jobs (generation_id, created_at, item_id) WHERE state='queued'`},
	} {
		t.Run(drift.name, func(t *testing.T) {
			if _, err := ownerDB.ExecContext(ctx, drift.apply); err != nil {
				t.Fatal(err)
			}
			if err := app.Ready(ctx); err == nil {
				t.Fatalf("readiness accepted embedding %s drift", drift.name)
			}
			if _, err := ownerDB.ExecContext(ctx, drift.restore); err != nil {
				t.Fatal(err)
			}
			if err := app.Ready(ctx); err != nil {
				t.Fatalf("readiness did not recover after embedding %s restoration: %v", drift.name, err)
			}
		})
	}
}

func testMemoryEmbeddingQueueIntegration(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB) {
	t.Helper()
	actor, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "embedding queue actor")
	if err != nil {
		t.Fatal(err)
	}
	var projectID string
	if err := ownerDB.QueryRowContext(ctx, `INSERT INTO relay.projects(display_name,created_by) VALUES ('embedding queue project',$1) RETURNING id::text`, actor.ID).Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants(principal_id,scope,project_id,capability) VALUES ($1,'project',$2,$3)`, actor.ID, projectID, CapabilityMemoryWrite); err != nil {
		t.Fatal(err)
	}
	create := func(key, title string) MemoryMutationResult {
		t.Helper()
		result, createErr := app.CreateMemory(ctx, MemoryCreateRequest{PrincipalID: actor.ID, ProjectID: projectID, IdempotencyKey: key, LogicalKey: "embedding-" + key, Kind: "decision", Trust: "curated", Document: json.RawMessage(`{"title":` + strconvQuote(title) + `}`)})
		if createErr != nil {
			t.Fatal(createErr)
		}
		return result
	}
	withoutGeneration := create("19191919-1919-4191-8191-191919191911", "lexical only")
	var count int
	if err := ownerDB.QueryRowContext(ctx, `SELECT count(*) FROM brain.embedding_jobs WHERE item_id=$1`, withoutGeneration.ItemID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("inactive embedding frontier jobs=%d err=%v", count, err)
	}

	var generationID string
	if err := ownerDB.QueryRowContext(ctx, `INSERT INTO brain.embedding_generations(model,model_revision,dimensions) VALUES ('local.e5-base','2026-07-01',768) RETURNING id::text`).Scan(&generationID); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE brain.embedding_generations SET dimensions=1024 WHERE id=$1`, generationID); err == nil {
		t.Fatal("embedding generation mutation succeeded")
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO brain.embedding_generations(model,model_revision,dimensions) VALUES ('local.e5-large','2026-07-01',1024)`); err == nil {
		t.Fatal("second active embedding generation succeeded")
	}
	created := create("19191919-1919-4191-8191-191919191912", "queue first")
	var job MemoryEmbeddingWork
	if err := ownerDB.QueryRowContext(ctx, `SELECT generation_id::text,item_id::text,revision,encode(content_sha256,'hex') FROM brain.embedding_jobs WHERE generation_id=$1 AND item_id=$2`, generationID, created.ItemID).Scan(&job.GenerationID, &job.ItemID, &job.Revision, &job.ContentSHA256); err != nil {
		t.Fatal(err)
	}
	if err := job.Validate(); err != nil || job.Revision != 1 {
		t.Fatalf("queued work=%#v err=%v", job, err)
	}
	retry, err := app.CreateMemory(ctx, MemoryCreateRequest{PrincipalID: actor.ID, ProjectID: projectID, IdempotencyKey: "19191919-1919-4191-8191-191919191912", LogicalKey: "embedding-19191919-1919-4191-8191-191919191912", Kind: "decision", Trust: "curated", Document: json.RawMessage(`{"title":"queue first"}`)})
	if err != nil || retry.ItemID != created.ItemID {
		t.Fatalf("create retry=%#v err=%v", retry, err)
	}
	if err := ownerDB.QueryRowContext(ctx, `SELECT count(*) FROM brain.embedding_jobs WHERE generation_id=$1 AND item_id=$2`, generationID, created.ItemID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("idempotent queue duplication count=%d err=%v", count, err)
	}
	updated, err := app.UpdateMemory(ctx, MemoryUpdateRequest{PrincipalID: actor.ID, ProjectID: projectID, ItemID: created.ItemID, IdempotencyKey: "19191919-1919-4191-8191-191919191913", ExpectedETag: created.ETag, LogicalKey: "embedding-19191919-1919-4191-8191-191919191912", Kind: "decision", Trust: "curated", Document: json.RawMessage(`{"title":"queue second"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := ownerDB.QueryRowContext(ctx, `SELECT generation_id::text,item_id::text,revision,encode(content_sha256,'hex') FROM brain.embedding_jobs WHERE generation_id=$1 AND item_id=$2`, generationID, created.ItemID).Scan(&job.GenerationID, &job.ItemID, &job.Revision, &job.ContentSHA256); err != nil || job.Revision != updated.Revision || job.ContentSHA256 == "" {
		t.Fatalf("coalesced work=%#v update=%#v err=%v", job, updated, err)
	}
}
