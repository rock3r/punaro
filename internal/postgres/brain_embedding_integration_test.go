package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func testMemoryEmbeddingSchemaDriftIntegration(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB) {
	t.Helper()
	for _, drift := range []struct {
		name, apply, restore string
	}{
		{"application write", `GRANT INSERT ON brain.embedding_jobs TO punaro_app`, `REVOKE INSERT ON brain.embedding_jobs FROM punaro_app`},
		{"application read", `REVOKE SELECT ON brain.embedding_generations FROM punaro_app`, `GRANT SELECT ON brain.embedding_generations TO punaro_app`},
		{"queue trigger", `ALTER TABLE brain.memory_revisions DISABLE TRIGGER memory_revision_embedding_queue`, `ALTER TABLE brain.memory_revisions ENABLE TRIGGER memory_revision_embedding_queue`},
		{"claim index", `DROP INDEX brain.embedding_jobs_claim_order`, `CREATE INDEX embedding_jobs_claim_order ON brain.embedding_jobs (generation_id, available_at, created_at, item_id) WHERE state='queued'`},
		{"worker routine ACL", `REVOKE EXECUTE ON FUNCTION brain.retry_embedding_job(uuid,uuid,bigint,bytea,uuid,bigint,bigint,text) FROM punaro_app`, `GRANT EXECUTE ON FUNCTION brain.retry_embedding_job(uuid,uuid,bigint,bytea,uuid,bigint,bigint,text) TO punaro_app`},
		{"worker routine public ACL", `GRANT EXECUTE ON FUNCTION brain.claim_embedding_jobs(uuid,integer,bigint) TO PUBLIC`, `REVOKE EXECUTE ON FUNCTION brain.claim_embedding_jobs(uuid,integer,bigint) FROM PUBLIC`},
		{"worker routine security", `ALTER FUNCTION brain.claim_embedding_jobs(uuid,integer,bigint) SECURITY INVOKER`, `ALTER FUNCTION brain.claim_embedding_jobs(uuid,integer,bigint) SECURITY DEFINER`},
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
	var invalidClaimCount int
	err = app.db.QueryRowContext(ctx, `SELECT count(*) FROM brain.claim_embedding_jobs($1,NULL,$2)`, "19191919-1919-4191-8191-191919191914", memoryEmbeddingMinLease.Microseconds()).Scan(&invalidClaimCount)
	if err == nil {
		t.Fatal("embedding claim accepted an unbounded NULL limit")
	}
	claimed, err := app.ClaimMemoryEmbeddingWork(ctx, MemoryEmbeddingClaimRequest{WorkerID: "19191919-1919-4191-8191-191919191914", Limit: 1, LeaseDuration: memoryEmbeddingMinLease})
	if err != nil || len(claimed) != 1 || claimed[0].ItemID != created.ItemID {
		t.Fatalf("claimed embedding work=%#v err=%v", claimed, err)
	}
	firstLease := claimed[0]
	if err := app.RetryMemoryEmbeddingWork(ctx, MemoryEmbeddingRetry{Lease: firstLease, ErrorCode: "provider_unavailable", Delay: time.Second}); err != nil {
		t.Fatalf("embedding retry: %v", err)
	}
	if delayed, claimErr := app.ClaimMemoryEmbeddingWork(ctx, MemoryEmbeddingClaimRequest{WorkerID: "19191919-1919-4191-8191-191919191915", Limit: 1, LeaseDuration: memoryEmbeddingMinLease}); claimErr != nil || len(delayed) != 0 {
		t.Fatalf("delayed embedding retry claim=%#v err=%v", delayed, claimErr)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE brain.embedding_jobs SET available_at=statement_timestamp() WHERE generation_id=$1 AND item_id=$2`, generationID, created.ItemID); err != nil {
		t.Fatal(err)
	}
	if err := app.RetryMemoryEmbeddingWork(ctx, MemoryEmbeddingRetry{Lease: firstLease, ErrorCode: "replayed", Delay: 0}); !errors.Is(err, ErrStaleEmbeddingLease) {
		t.Fatalf("replayed embedding retry error=%v", err)
	}
	claimed, err = app.ClaimMemoryEmbeddingWork(ctx, MemoryEmbeddingClaimRequest{WorkerID: "19191919-1919-4191-8191-191919191915", Limit: 1, LeaseDuration: memoryEmbeddingMinLease})
	if err != nil || len(claimed) != 1 || claimed[0].Token == firstLease.Token || claimed[0].LeaseGeneration <= firstLease.LeaseGeneration {
		t.Fatalf("reclaimed embedding work=%#v first=%#v err=%v", claimed, firstLease, err)
	}
	reclaimed := claimed[0]
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
	if err := app.RetryMemoryEmbeddingWork(ctx, MemoryEmbeddingRetry{Lease: reclaimed, ErrorCode: "stale_revision", Delay: 0}); !errors.Is(err, ErrStaleEmbeddingLease) {
		t.Fatalf("superseded embedding retry error=%v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE brain.embedding_jobs SET attempts=24,available_at=statement_timestamp() WHERE generation_id=$1 AND item_id=$2`, generationID, created.ItemID); err != nil {
		t.Fatal(err)
	}
	claimed, err = app.ClaimMemoryEmbeddingWork(ctx, MemoryEmbeddingClaimRequest{WorkerID: "19191919-1919-4191-8191-191919191916", Limit: 1, LeaseDuration: memoryEmbeddingMinLease})
	if err != nil || len(claimed) != 1 || claimed[0].Attempts != 25 {
		t.Fatalf("final embedding attempt=%#v err=%v", claimed, err)
	}
	if err := app.RetryMemoryEmbeddingWork(ctx, MemoryEmbeddingRetry{Lease: claimed[0], ErrorCode: "provider_terminal", Delay: 0}); err != nil {
		t.Fatalf("terminal embedding retry: %v", err)
	}
	var state, errorCode string
	if err := ownerDB.QueryRowContext(ctx, `SELECT state,last_error_code FROM brain.embedding_jobs WHERE generation_id=$1 AND item_id=$2`, generationID, created.ItemID).Scan(&state, &errorCode); err != nil || state != "failed" || errorCode != "provider_terminal" {
		t.Fatalf("terminal embedding state=%q code=%q err=%v", state, errorCode, err)
	}
}
