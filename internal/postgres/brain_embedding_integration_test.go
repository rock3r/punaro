package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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
		{"building generation index", `DROP INDEX brain.embedding_generations_one_building`, `CREATE UNIQUE INDEX embedding_generations_one_building ON brain.embedding_generations ((true)) WHERE state='building'`},
		{"building generation key expression", `DROP INDEX brain.embedding_generations_one_building; CREATE UNIQUE INDEX embedding_generations_one_building ON brain.embedding_generations (id) WHERE state='building'`, `DROP INDEX brain.embedding_generations_one_building; CREATE UNIQUE INDEX embedding_generations_one_building ON brain.embedding_generations ((true)) WHERE state='building'`},
		{"generation state fence", `ALTER TABLE brain.embedding_generations DROP CONSTRAINT embedding_generations_state_check; ALTER TABLE brain.embedding_generations ADD CONSTRAINT embedding_generations_state_check CHECK (state IS NOT NULL)`, `ALTER TABLE brain.embedding_generations DROP CONSTRAINT embedding_generations_state_check; ALTER TABLE brain.embedding_generations ADD CONSTRAINT embedding_generations_state_check CHECK ((state = 'active' AND start_change_sequence IS NULL) OR (state = 'building' AND start_change_sequence >= 0))`},
		{"legacy generation tuple uniqueness", `ALTER TABLE brain.embedding_generations ADD CONSTRAINT embedding_generations_model_model_revision_dimensions_key UNIQUE (model,model_revision,dimensions)`, `ALTER TABLE brain.embedding_generations DROP CONSTRAINT embedding_generations_model_model_revision_dimensions_key`},
		{"rebuild routine ACL", `GRANT EXECUTE ON FUNCTION brain.start_embedding_generation(text,text,integer) TO punaro_app`, `REVOKE EXECUTE ON FUNCTION brain.start_embedding_generation(text,text,integer) FROM punaro_app`},
		{"rebuild progress read", `GRANT SELECT ON brain.embedding_rebuild_progress TO punaro_app`, `REVOKE SELECT ON brain.embedding_rebuild_progress FROM punaro_app`},
		{"rebuild batch routine ACL", `GRANT EXECUTE ON FUNCTION brain.enqueue_embedding_rebuild_batch(uuid,integer) TO punaro_app`, `REVOKE EXECUTE ON FUNCTION brain.enqueue_embedding_rebuild_batch(uuid,integer) FROM punaro_app`},
		{"rebuild progress extra check", `ALTER TABLE brain.embedding_rebuild_progress ADD CONSTRAINT embedding_rebuild_progress_extra_check CHECK (complete OR NOT complete)`, `ALTER TABLE brain.embedding_rebuild_progress DROP CONSTRAINT embedding_rebuild_progress_extra_check`},
		{"activation routine ACL", `GRANT EXECUTE ON FUNCTION brain.activate_embedding_generation(uuid) TO punaro_app`, `REVOKE EXECUTE ON FUNCTION brain.activate_embedding_generation(uuid) FROM punaro_app`},
		{"activation immutable trigger", `ALTER TABLE brain.embedding_generations DISABLE TRIGGER embedding_generation_immutable`, `ALTER TABLE brain.embedding_generations ENABLE TRIGGER embedding_generation_immutable`},
		{"activation unexpected generation trigger", `CREATE TRIGGER embedding_generations_unexpected_guard BEFORE UPDATE ON brain.embedding_generations FOR EACH STATEMENT EXECUTE FUNCTION jobs.guard_application_mutation()`, `DROP TRIGGER embedding_generations_unexpected_guard ON brain.embedding_generations`},
		{"activation chunk-delete fence", `ALTER TABLE brain.embedding_chunks DISABLE TRIGGER embedding_chunks_delete_fence`, `ALTER TABLE brain.embedding_chunks ENABLE TRIGGER embedding_chunks_delete_fence`},
		{"worker routine ACL", `REVOKE EXECUTE ON FUNCTION brain.retry_embedding_job(uuid,uuid,bigint,bytea,uuid,bigint,bigint,text) FROM punaro_app`, `GRANT EXECUTE ON FUNCTION brain.retry_embedding_job(uuid,uuid,bigint,bytea,uuid,bigint,bigint,text) TO punaro_app`},
		{"worker routine public ACL", `GRANT EXECUTE ON FUNCTION brain.claim_embedding_jobs(uuid,integer,bigint) TO PUBLIC`, `REVOKE EXECUTE ON FUNCTION brain.claim_embedding_jobs(uuid,integer,bigint) FROM PUBLIC`},
		{"worker routine security", `ALTER FUNCTION brain.claim_embedding_jobs(uuid,integer,bigint) SECURITY INVOKER`, `ALTER FUNCTION brain.claim_embedding_jobs(uuid,integer,bigint) SECURITY DEFINER`},
		{"publication write", `GRANT INSERT ON brain.embedding_chunks TO punaro_app`, `REVOKE INSERT ON brain.embedding_chunks FROM punaro_app`},
		{"publication column write", `GRANT UPDATE (content_sha256) ON brain.embedding_chunks TO punaro_app`, `REVOKE UPDATE (content_sha256) ON brain.embedding_chunks FROM punaro_app`},
		{"publication public write", `GRANT UPDATE ON brain.embedding_chunks TO PUBLIC`, `REVOKE UPDATE ON brain.embedding_chunks FROM PUBLIC`},
		{"publication routine ACL", `REVOKE EXECUTE ON FUNCTION brain.publish_embedding_job(uuid,uuid,bigint,bytea,uuid,bigint,jsonb) FROM punaro_app`, `GRANT EXECUTE ON FUNCTION brain.publish_embedding_job(uuid,uuid,bigint,bytea,uuid,bigint,jsonb) TO punaro_app`},
		{"publication routine public ACL", `GRANT EXECUTE ON FUNCTION brain.publish_embedding_job(uuid,uuid,bigint,bytea,uuid,bigint,jsonb) TO PUBLIC`, `REVOKE EXECUTE ON FUNCTION brain.publish_embedding_job(uuid,uuid,bigint,bytea,uuid,bigint,jsonb) FROM PUBLIC`},
		{"publication unexpected trigger", `CREATE TRIGGER embedding_chunks_unexpected_guard BEFORE UPDATE ON brain.embedding_chunks FOR EACH STATEMENT EXECUTE FUNCTION jobs.guard_application_mutation()`, `DROP TRIGGER embedding_chunks_unexpected_guard ON brain.embedding_chunks`},
		{"publication renamed fence", `ALTER TRIGGER application_mutation_fence ON brain.embedding_chunks RENAME TO embedding_chunks_renamed_fence`, `ALTER TRIGGER embedding_chunks_renamed_fence ON brain.embedding_chunks RENAME TO application_mutation_fence`},
		{"publication chunk revision reference", `ALTER TABLE brain.embedding_chunks DROP CONSTRAINT embedding_chunks_item_id_revision_fkey`, `ALTER TABLE brain.embedding_chunks ADD CONSTRAINT embedding_chunks_item_id_revision_fkey FOREIGN KEY (item_id,revision) REFERENCES brain.memory_revisions(item_id,revision) ON DELETE CASCADE`},
		{"publication chunk range check", `ALTER TABLE brain.embedding_chunks DROP CONSTRAINT embedding_chunks_check`, `ALTER TABLE brain.embedding_chunks ADD CONSTRAINT embedding_chunks_check CHECK (end_offset > start_offset AND end_offset <= 262144)`},
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
	testMemoryEmbeddingPublicationReturnTypeDrift(ctx, t, app, ownerDB)
	testMemoryEmbeddingRebuildRoutineACLDrift(ctx, t, app, ownerDB)
}

func testMemoryEmbeddingRebuildRoutineACLDrift(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB) {
	t.Helper()
	const role = "embedding_rebuild_unexpected"
	if _, err := ownerDB.ExecContext(ctx, `CREATE ROLE `+role+` NOLOGIN`); err != nil { // #nosec G202 -- fixed role name.
		t.Fatal(err)
	}
	defer func() { _, _ = ownerDB.ExecContext(context.Background(), `DROP ROLE `+role) }()                                                        // #nosec G202 -- fixed role name.
	if _, err := ownerDB.ExecContext(ctx, `GRANT EXECUTE ON FUNCTION brain.start_embedding_generation(text,text,integer) TO `+role); err != nil { // #nosec G202 -- fixed role name.
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err == nil {
		t.Fatal("readiness accepted unexpected rebuild routine grantee")
	}
	if _, err := ownerDB.ExecContext(ctx, `REVOKE EXECUTE ON FUNCTION brain.start_embedding_generation(text,text,integer) FROM `+role); err != nil { // #nosec G202 -- fixed role name.
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err != nil {
		t.Fatalf("readiness did not recover after rebuild routine ACL restoration: %v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `GRANT EXECUTE ON FUNCTION brain.start_embedding_generation(text,text,integer) TO PUBLIC`); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err == nil {
		t.Fatal("readiness accepted public rebuild routine grantee")
	}
	if _, err := ownerDB.ExecContext(ctx, `REVOKE EXECUTE ON FUNCTION brain.start_embedding_generation(text,text,integer) FROM PUBLIC`); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err != nil {
		t.Fatalf("readiness did not recover after public rebuild routine ACL restoration: %v", err)
	}
}

func testMemoryEmbeddingPublicationReturnTypeDrift(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB) {
	t.Helper()
	const signature = "brain.publish_embedding_job(uuid,uuid,bigint,bytea,uuid,bigint,jsonb)"
	ownerConn, err := ownerDB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ownerConn.Close() }()
	var definition string
	if err := ownerConn.QueryRowContext(ctx, `SELECT pg_get_functiondef($1::regprocedure)`, signature).Scan(&definition); err != nil {
		t.Fatal(err)
	}
	altered := strings.Replace(definition, "RETURNS boolean", "RETURNS uuid", 1)
	if altered == definition {
		t.Fatal("publication routine definition did not contain its boolean return type")
	}
	if _, err := ownerConn.ExecContext(ctx, `DROP FUNCTION `+signature); err != nil { // #nosec G202 -- fixed signature.
		t.Fatal(err)
	}
	if _, err := ownerConn.ExecContext(ctx, `SET check_function_bodies=off`); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerConn.ExecContext(ctx, altered); err != nil { // #nosec G202 -- definition is read from PostgreSQL immediately above.
		t.Fatal(err)
	}
	if _, err := ownerConn.ExecContext(ctx, `RESET check_function_bodies`); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerConn.ExecContext(ctx, `REVOKE ALL ON FUNCTION `+signature+` FROM PUBLIC; GRANT EXECUTE ON FUNCTION `+signature+` TO punaro_app`); err != nil { // #nosec G202 -- fixed signature.
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err == nil {
		t.Fatal("readiness accepted publication routine return-type drift")
	}
	if _, err := ownerConn.ExecContext(ctx, `DROP FUNCTION `+signature); err != nil { // #nosec G202 -- fixed signature.
		t.Fatal(err)
	}
	if _, err := ownerConn.ExecContext(ctx, definition); err != nil { // #nosec G202 -- definition is read from PostgreSQL immediately above.
		t.Fatal(err)
	}
	if _, err := ownerConn.ExecContext(ctx, `REVOKE ALL ON FUNCTION `+signature+` FROM PUBLIC; GRANT EXECUTE ON FUNCTION `+signature+` TO punaro_app`); err != nil { // #nosec G202 -- fixed signature.
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err != nil {
		t.Fatalf("readiness did not recover after publication routine return-type restoration: %v", err)
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
	if err := ownerDB.QueryRowContext(ctx, `INSERT INTO brain.embedding_generations(model,model_revision,dimensions) VALUES ('local.e5-base','2026-07-01',3) RETURNING id::text`).Scan(&generationID); err != nil {
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
	publishable := create("19191919-1919-4191-8191-191919191917", "publish chunks")
	claimed, err = app.ClaimMemoryEmbeddingWork(ctx, MemoryEmbeddingClaimRequest{WorkerID: "19191919-1919-4191-8191-191919191918", Limit: 1, LeaseDuration: memoryEmbeddingMaxLease})
	if err != nil || len(claimed) != 1 || claimed[0].ItemID != publishable.ItemID {
		t.Fatalf("publishable embedding claim=%#v err=%v", claimed, err)
	}
	publication := MemoryEmbeddingPublication{Lease: claimed[0], Chunks: []MemoryEmbeddingChunk{
		{Ordinal: 0, ContentSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", StartOffset: 0, EndOffset: 12, Vector: []float64{0.25, 0.5, 0.75}},
		{Ordinal: 1, ContentSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", StartOffset: 12, EndOffset: 28, Vector: []float64{0.75, 0.5, 0.25}},
	}}
	rollback := create("19191919-1919-4191-8191-191919191925", "rollback publication")
	claimed, err = app.ClaimMemoryEmbeddingWork(ctx, MemoryEmbeddingClaimRequest{WorkerID: "19191919-1919-4191-8191-191919191926", Limit: 1, LeaseDuration: memoryEmbeddingMinLease})
	if err != nil || len(claimed) != 1 || claimed[0].ItemID != rollback.ItemID {
		t.Fatalf("rollback publication claim=%#v err=%v", claimed, err)
	}
	rollbackLease := claimed[0]
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO brain.embedding_chunks(generation_id,item_id,revision,ordinal,content_sha256,start_offset,end_offset,embedding) VALUES ($1,$2,$3,0,decode($4,'hex'),0,12,'[0.25,0.5,0.75]'::vector)`, rollbackLease.GenerationID, rollbackLease.ItemID, rollbackLease.Revision, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"); err != nil {
		t.Fatal(err)
	}
	rollbackConn, err := app.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	invalidChunks := `[{"ordinal":0,"content_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","start_offset":0,"end_offset":12,"embedding":[0.25,0.5,0.75]},{"ordinal":0,"content_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","start_offset":12,"end_offset":28,"embedding":[0.75,0.5,0.25]}]`
	var published bool
	err = rollbackConn.QueryRowContext(ctx, `SELECT brain.publish_embedding_job($1,$2,$3,decode($4,'hex'),$5,$6,$7::jsonb)`, rollbackLease.GenerationID, rollbackLease.ItemID, rollbackLease.Revision, rollbackLease.ContentSHA256, rollbackLease.Token, rollbackLease.LeaseGeneration, invalidChunks).Scan(&published)
	if closeErr := rollbackConn.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if err == nil {
		t.Fatalf("duplicate-ordinal publication succeeded: published=%t", published)
	}
	dimensionMismatchChunks := `[{"ordinal":0,"content_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","start_offset":0,"end_offset":12,"embedding":[0.25,0.5]}]`
	err = app.db.QueryRowContext(ctx, `SELECT brain.publish_embedding_job($1,$2,$3,decode($4,'hex'),$5,$6,$7::jsonb)`, rollbackLease.GenerationID, rollbackLease.ItemID, rollbackLease.Revision, rollbackLease.ContentSHA256, rollbackLease.Token, rollbackLease.LeaseGeneration, dimensionMismatchChunks).Scan(&published)
	if err == nil {
		t.Fatalf("wrong-dimension publication succeeded: published=%t", published)
	}
	var rollbackState, rollbackToken, rollbackDigest string
	var rollbackLeaseGeneration int64
	if err := ownerDB.QueryRowContext(ctx, `SELECT state,lease_token::text,encode(content_sha256,'hex'),lease_generation FROM brain.embedding_jobs WHERE generation_id=$1 AND item_id=$2`, rollbackLease.GenerationID, rollbackLease.ItemID).Scan(&rollbackState, &rollbackToken, &rollbackDigest, &rollbackLeaseGeneration); err != nil || rollbackState != "running" || rollbackToken != rollbackLease.Token || rollbackDigest != rollbackLease.ContentSHA256 || rollbackLeaseGeneration != rollbackLease.LeaseGeneration {
		t.Fatalf("failed publication changed embedding job state=%q token=%q digest=%q generation=%d err=%v", rollbackState, rollbackToken, rollbackDigest, rollbackLeaseGeneration, err)
	}
	var rollbackOrdinal, rollbackStart, rollbackEnd int
	var rollbackChunkDigest string
	if err := ownerDB.QueryRowContext(ctx, `SELECT ordinal,encode(content_sha256,'hex'),start_offset,end_offset FROM brain.embedding_chunks WHERE generation_id=$1 AND item_id=$2 AND revision=$3`, rollbackLease.GenerationID, rollbackLease.ItemID, rollbackLease.Revision).Scan(&rollbackOrdinal, &rollbackChunkDigest, &rollbackStart, &rollbackEnd); err != nil || rollbackOrdinal != 0 || rollbackChunkDigest != "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" || rollbackStart != 0 || rollbackEnd != 12 {
		t.Fatalf("failed publication changed embedding chunk ordinal=%d digest=%q range=[%d,%d] err=%v", rollbackOrdinal, rollbackChunkDigest, rollbackStart, rollbackEnd, err)
	}
	disconnected := create("19191919-1919-4191-8191-191919191927", "disconnect publication")
	claimed, err = app.ClaimMemoryEmbeddingWork(ctx, MemoryEmbeddingClaimRequest{WorkerID: "19191919-1919-4191-8191-191919191928", Limit: 1, LeaseDuration: memoryEmbeddingMinLease})
	if err != nil || len(claimed) != 1 || claimed[0].ItemID != disconnected.ItemID {
		t.Fatalf("disconnect publication claim=%#v err=%v", claimed, err)
	}
	disconnectLease := claimed[0]
	disconnectConn, err := app.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	disconnectTx, err := disconnectConn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	validChunks := `[{"ordinal":0,"content_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","start_offset":0,"end_offset":12,"embedding":[0.25,0.5,0.75]}]`
	if err := disconnectTx.QueryRowContext(ctx, `SELECT brain.publish_embedding_job($1,$2,$3,decode($4,'hex'),$5,$6,$7::jsonb)`, disconnectLease.GenerationID, disconnectLease.ItemID, disconnectLease.Revision, disconnectLease.ContentSHA256, disconnectLease.Token, disconnectLease.LeaseGeneration, validChunks).Scan(&published); err != nil || !published {
		t.Fatalf("uncommitted publication=%t err=%v", published, err)
	}
	if err := disconnectTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := disconnectConn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ownerDB.QueryRowContext(ctx, `SELECT state FROM brain.embedding_jobs WHERE generation_id=$1 AND item_id=$2`, disconnectLease.GenerationID, disconnectLease.ItemID).Scan(&state); err != nil || state != "running" {
		t.Fatalf("disconnect changed state=%q err=%v", state, err)
	}
	if err := ownerDB.QueryRowContext(ctx, `SELECT count(*) FROM brain.embedding_chunks WHERE generation_id=$1 AND item_id=$2`, disconnectLease.GenerationID, disconnectLease.ItemID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("disconnect chunks=%d err=%v", count, err)
	}
	unauthorized := create("19191919-1919-4191-8191-191919191929", "unauthorized publication")
	claimed, err = app.ClaimMemoryEmbeddingWork(ctx, MemoryEmbeddingClaimRequest{WorkerID: "19191919-1919-4191-8191-191919191930", Limit: 1, LeaseDuration: memoryEmbeddingMinLease})
	if err != nil || len(claimed) != 1 || claimed[0].ItemID != unauthorized.ItemID {
		t.Fatalf("unauthorized publication claim=%#v err=%v", claimed, err)
	}
	unauthorizedLease := claimed[0]
	if _, err := ownerDB.ExecContext(ctx, `CREATE ROLE embedding_publication_denied NOLOGIN`); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = ownerDB.ExecContext(context.Background(), `DROP ROLE embedding_publication_denied`) }()
	ownerConn, err := ownerDB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ownerConn.ExecContext(ctx, `SET ROLE embedding_publication_denied`); err != nil {
		t.Fatal(err)
	}
	err = ownerConn.QueryRowContext(ctx, `SELECT brain.publish_embedding_job($1,$2,$3,decode($4,'hex'),$5,$6,$7::jsonb)`, unauthorizedLease.GenerationID, unauthorizedLease.ItemID, unauthorizedLease.Revision, unauthorizedLease.ContentSHA256, unauthorizedLease.Token, unauthorizedLease.LeaseGeneration, validChunks).Scan(&published)
	_, _ = ownerConn.ExecContext(ctx, `RESET ROLE`)
	if closeErr := ownerConn.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if !isSQLState(err, "42501") {
		t.Fatalf("unauthorized publication error=%v, want permission denied", err)
	}
	if err := ownerDB.QueryRowContext(ctx, `SELECT state FROM brain.embedding_jobs WHERE generation_id=$1 AND item_id=$2`, unauthorizedLease.GenerationID, unauthorizedLease.ItemID).Scan(&state); err != nil || state != "running" {
		t.Fatalf("unauthorized publication changed state=%q err=%v", state, err)
	}
	if err := ownerDB.QueryRowContext(ctx, `SELECT count(*) FROM brain.embedding_chunks WHERE generation_id=$1 AND item_id=$2`, unauthorizedLease.GenerationID, unauthorizedLease.ItemID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("unauthorized publication chunks=%d err=%v", count, err)
	}
	if err := app.PublishMemoryEmbeddingWork(ctx, publication); err != nil {
		t.Fatalf("embedding publication: %v", err)
	}
	if err := ownerDB.QueryRowContext(ctx, `SELECT state FROM brain.embedding_jobs WHERE generation_id=$1 AND item_id=$2`, generationID, publishable.ItemID).Scan(&state); err != nil || state != "succeeded" {
		t.Fatalf("published embedding state=%q err=%v", state, err)
	}
	if err := ownerDB.QueryRowContext(ctx, `SELECT count(*) FROM brain.embedding_chunks WHERE generation_id=$1 AND item_id=$2 AND revision=$3`, generationID, publishable.ItemID, publication.Lease.Revision).Scan(&count); err != nil || count != len(publication.Chunks) {
		t.Fatalf("published embedding chunks=%d err=%v", count, err)
	}
	var storedVector string
	if err := ownerDB.QueryRowContext(ctx, `SELECT embedding::text FROM brain.embedding_chunks WHERE generation_id=$1 AND item_id=$2 AND revision=$3 AND ordinal=0`, generationID, publishable.ItemID, publication.Lease.Revision).Scan(&storedVector); err != nil || storedVector != "[0.25,0.5,0.75]" {
		t.Fatalf("published embedding vector=%q err=%v", storedVector, err)
	}
	if err := app.PublishMemoryEmbeddingWork(ctx, publication); !errors.Is(err, ErrStaleEmbeddingLease) {
		t.Fatalf("replayed embedding publication error=%v", err)
	}
	leaseExpired := create("19191919-1919-4191-8191-191919191919", "expired publication")
	claimed, err = app.ClaimMemoryEmbeddingWork(ctx, MemoryEmbeddingClaimRequest{WorkerID: "19191919-1919-4191-8191-191919191920", Limit: 1, LeaseDuration: memoryEmbeddingMinLease})
	if err != nil || len(claimed) != 1 || claimed[0].ItemID != leaseExpired.ItemID {
		t.Fatalf("expired publication claim=%#v err=%v", claimed, err)
	}
	expiredLease := claimed[0]
	if _, err := ownerDB.ExecContext(ctx, `UPDATE brain.embedding_jobs SET lease_until=statement_timestamp()-interval '1 second' WHERE generation_id=$1 AND item_id=$2`, generationID, leaseExpired.ItemID); err != nil {
		t.Fatal(err)
	}
	claimed, err = app.ClaimMemoryEmbeddingWork(ctx, MemoryEmbeddingClaimRequest{WorkerID: "19191919-1919-4191-8191-191919191921", Limit: 1, LeaseDuration: memoryEmbeddingMinLease})
	if err != nil || len(claimed) != 1 || claimed[0].ItemID != leaseExpired.ItemID || claimed[0].Token == expiredLease.Token || claimed[0].LeaseGeneration <= expiredLease.LeaseGeneration {
		t.Fatalf("reclaimed publication work=%#v expired=%#v err=%v", claimed, expiredLease, err)
	}
	if err := app.PublishMemoryEmbeddingWork(ctx, MemoryEmbeddingPublication{Lease: expiredLease, Chunks: publication.Chunks}); !errors.Is(err, ErrStaleEmbeddingLease) {
		t.Fatalf("expired embedding publication error=%v", err)
	}
	if err := ownerDB.QueryRowContext(ctx, `SELECT state FROM brain.embedding_jobs WHERE generation_id=$1 AND item_id=$2`, generationID, leaseExpired.ItemID).Scan(&state); err != nil || state != "running" {
		t.Fatalf("expired embedding state=%q err=%v", state, err)
	}
	if err := ownerDB.QueryRowContext(ctx, `SELECT count(*) FROM brain.embedding_chunks WHERE generation_id=$1 AND item_id=$2`, generationID, leaseExpired.ItemID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("expired embedding chunks=%d err=%v", count, err)
	}
	superseded := create("19191919-1919-4191-8191-191919191922", "superseded publication")
	claimed, err = app.ClaimMemoryEmbeddingWork(ctx, MemoryEmbeddingClaimRequest{WorkerID: "19191919-1919-4191-8191-191919191923", Limit: 1, LeaseDuration: memoryEmbeddingMinLease})
	if err != nil || len(claimed) != 1 || claimed[0].ItemID != superseded.ItemID {
		t.Fatalf("superseded publication claim=%#v err=%v", claimed, err)
	}
	supersededLease := claimed[0]
	if _, err := app.UpdateMemory(ctx, MemoryUpdateRequest{PrincipalID: actor.ID, ProjectID: projectID, ItemID: superseded.ItemID, IdempotencyKey: "19191919-1919-4191-8191-191919191924", ExpectedETag: superseded.ETag, LogicalKey: "embedding-19191919-1919-4191-8191-191919191922", Kind: "decision", Trust: "curated", Document: json.RawMessage(`{"title":"superseded publication revised"}`)}); err != nil {
		t.Fatal(err)
	}
	if err := app.PublishMemoryEmbeddingWork(ctx, MemoryEmbeddingPublication{Lease: supersededLease, Chunks: publication.Chunks}); !errors.Is(err, ErrStaleEmbeddingLease) {
		t.Fatalf("superseded embedding publication error=%v", err)
	}
	if err := ownerDB.QueryRowContext(ctx, `SELECT revision,state FROM brain.embedding_jobs WHERE generation_id=$1 AND item_id=$2`, generationID, superseded.ItemID).Scan(&job.Revision, &state); err != nil || job.Revision != supersededLease.Revision+1 || state != "queued" {
		t.Fatalf("superseded embedding job revision=%d state=%q err=%v", job.Revision, state, err)
	}
	if err := ownerDB.QueryRowContext(ctx, `SELECT count(*) FROM brain.embedding_chunks WHERE generation_id=$1 AND item_id=$2`, generationID, superseded.ItemID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("superseded embedding chunks=%d err=%v", count, err)
	}
}

func testMemoryEmbeddingGenerationRebuildIntegration(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB) {
	t.Helper()
	actor, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "embedding rebuild actor")
	if err != nil {
		t.Fatal(err)
	}
	var projectID string
	if err := ownerDB.QueryRowContext(ctx, `INSERT INTO relay.projects(display_name,created_by) VALUES ('embedding rebuild project',$1) RETURNING id::text`, actor.ID).Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants(principal_id,scope,project_id,capability) VALUES ($1,'project',$2,$3)`, actor.ID, projectID, CapabilityMemoryWrite); err != nil {
		t.Fatal(err)
	}
	create := func(key, title string) MemoryMutationResult {
		t.Helper()
		result, createErr := app.CreateMemory(ctx, MemoryCreateRequest{PrincipalID: actor.ID, ProjectID: projectID, IdempotencyKey: key, LogicalKey: "rebuild-" + key, Kind: "decision", Trust: "curated", Document: json.RawMessage(`{"title":` + strconvQuote(title) + `}`)})
		if createErr != nil {
			t.Fatal(createErr)
		}
		return result
	}
	before := create("19191919-1919-4191-8191-191919191941", "before rebuild")
	var restoredTimeline string
	if err := ownerDB.QueryRowContext(ctx, `WITH prior AS (
    SELECT installation_id,timeline_id,change_sequence FROM jobs.server_state WHERE singleton FOR UPDATE
), rotated AS (
    UPDATE jobs.server_state SET timeline_id=gen_random_uuid(),timeline_started_at=statement_timestamp()
    WHERE singleton RETURNING installation_id,timeline_id,change_sequence
), event AS (
    INSERT INTO jobs.restore_events(restore_id,backup_id,installation_id,previous_timeline_id,restored_timeline_id,restored_change_sequence)
    SELECT gen_random_uuid(),gen_random_uuid(),prior.installation_id,prior.timeline_id,rotated.timeline_id,prior.change_sequence FROM prior,rotated
)
SELECT timeline_id::text FROM rotated`).Scan(&restoredTimeline); err != nil {
		t.Fatalf("rotate test restore timeline: %v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `WITH advanced AS (
    UPDATE jobs.server_state SET change_sequence=change_sequence+1 WHERE singleton RETURNING timeline_id,change_sequence
)
INSERT INTO brain.memory_changes(timeline_id,change_sequence,scope_id,item_id,operation,revision)
SELECT advanced.timeline_id,advanced.change_sequence,item.scope_id,item.id,'update',item.current_revision
FROM advanced JOIN brain.memory_items AS item ON item.id=$1`, before.ItemID); err != nil {
		t.Fatalf("add same-revision change: %v", err)
	}
	var activeID string
	if err := ownerDB.QueryRowContext(ctx, `SELECT id::text FROM brain.embedding_generations WHERE state='active'`).Scan(&activeID); err != nil {
		t.Fatalf("active generation: %v", err)
	}
	var beforeSequence, buildingSequence int64
	if err := ownerDB.QueryRowContext(ctx, `SELECT change_sequence FROM jobs.server_state WHERE singleton`).Scan(&beforeSequence); err != nil {
		t.Fatal(err)
	}
	var buildingID string
	if err := ownerDB.QueryRowContext(ctx, `SELECT generation_id::text,start_change_sequence FROM brain.start_embedding_generation($1,$2,$3)`, "local.e5-base", "2026-07-01", 768).Scan(&buildingID, &buildingSequence); err != nil {
		t.Fatalf("start embedding rebuild: %v", err)
	}
	if buildingSequence != beforeSequence {
		t.Fatalf("building watermark=%d want start sequence %d", buildingSequence, beforeSequence)
	}
	if restoredTimeline == "" {
		t.Fatal("test restore timeline missing")
	}
	var state string
	if err := ownerDB.QueryRowContext(ctx, `SELECT state FROM brain.embedding_generations WHERE id=$1`, buildingID).Scan(&state); err != nil || state != "building" {
		t.Fatalf("building generation state=%q err=%v", state, err)
	}
	var revision int64
	var beforeJobs int
	if err := ownerDB.QueryRowContext(ctx, `SELECT count(*) FROM brain.embedding_jobs WHERE generation_id=$1 AND item_id=$2`, buildingID, before.ItemID).Scan(&beforeJobs); err != nil || beforeJobs != 0 {
		t.Fatalf("unbounded rebuild snapshot jobs=%d err=%v", beforeJobs, err)
	}
	beforeAfterStart, err := app.UpdateMemory(ctx, MemoryUpdateRequest{PrincipalID: actor.ID, ProjectID: projectID, ItemID: before.ItemID, IdempotencyKey: "19191919-1919-4191-8191-191919191940", ExpectedETag: before.ETag, LogicalKey: "rebuild-19191919-1919-4191-8191-191919191941", Kind: "decision", Trust: "curated", Document: json.RawMessage(`{"title":"before rebuild revised after start"}`)})
	if err != nil {
		t.Fatal(err)
	}
	var enqueued, rebuildCursor int64
	var rebuildComplete bool
	if err := ownerDB.QueryRowContext(ctx, `SELECT enqueued,cursor_change_sequence,complete FROM brain.enqueue_embedding_rebuild_batch($1,$2)`, buildingID, 128).Scan(&enqueued, &rebuildCursor, &rebuildComplete); err != nil {
		t.Fatalf("enqueue bounded rebuild batch: %v", err)
	}
	if rebuildCursor > buildingSequence {
		t.Fatalf("first rebuild batch enqueued=%d cursor=%d complete=%t watermark=%d", enqueued, rebuildCursor, rebuildComplete, buildingSequence)
	}
	for attempts := 0; !rebuildComplete && attempts < 64; attempts++ {
		previousCursor := rebuildCursor
		if err := ownerDB.QueryRowContext(ctx, `SELECT enqueued,cursor_change_sequence,complete FROM brain.enqueue_embedding_rebuild_batch($1,$2)`, buildingID, 128).Scan(&enqueued, &rebuildCursor, &rebuildComplete); err != nil {
			t.Fatalf("resume bounded rebuild batch: %v", err)
		}
		if rebuildCursor <= previousCursor {
			t.Fatalf("bounded rebuild cursor did not advance: previous=%d current=%d", previousCursor, rebuildCursor)
		}
	}
	if !rebuildComplete {
		t.Fatal("bounded rebuild did not finish within 64 batches")
	}
	completedCursor := rebuildCursor
	if err := ownerDB.QueryRowContext(ctx, `SELECT enqueued,cursor_change_sequence,complete FROM brain.enqueue_embedding_rebuild_batch($1,$2)`, buildingID, 128).Scan(&enqueued, &rebuildCursor, &rebuildComplete); err != nil {
		t.Fatalf("restart completed rebuild batch: %v", err)
	}
	if enqueued != 0 || !rebuildComplete || rebuildCursor != completedCursor {
		t.Fatalf("completed rebuild restart enqueued=%d cursor=%d complete=%t want cursor=%d", enqueued, rebuildCursor, rebuildComplete, completedCursor)
	}
	if err := ownerDB.QueryRowContext(ctx, `SELECT revision FROM brain.embedding_jobs WHERE generation_id=$1 AND item_id=$2`, buildingID, before.ItemID).Scan(&revision); err != nil || revision != beforeAfterStart.Revision {
		t.Fatalf("bounded rebuild job revision=%d want=%d err=%v", revision, beforeAfterStart.Revision, err)
	}
	after := create("19191919-1919-4191-8191-191919191942", "after rebuild")
	for _, generationID := range []string{activeID, buildingID} {
		if err := ownerDB.QueryRowContext(ctx, `SELECT revision FROM brain.embedding_jobs WHERE generation_id=$1 AND item_id=$2`, generationID, after.ItemID).Scan(&revision); err != nil || revision != after.Revision {
			t.Fatalf("generation %s post-start job revision=%d want=%d err=%v", generationID, revision, after.Revision, err)
		}
	}
	updated, err := app.UpdateMemory(ctx, MemoryUpdateRequest{PrincipalID: actor.ID, ProjectID: projectID, ItemID: after.ItemID, IdempotencyKey: "19191919-1919-4191-8191-191919191943", ExpectedETag: after.ETag, LogicalKey: "rebuild-19191919-1919-4191-8191-191919191942", Kind: "decision", Trust: "curated", Document: json.RawMessage(`{"title":"after rebuild revised"}`)})
	if err != nil {
		t.Fatal(err)
	}
	for _, generationID := range []string{activeID, buildingID} {
		if err := ownerDB.QueryRowContext(ctx, `SELECT revision FROM brain.embedding_jobs WHERE generation_id=$1 AND item_id=$2`, generationID, updated.ItemID).Scan(&revision); err != nil || revision != updated.Revision {
			t.Fatalf("generation %s coalesced job revision=%d want=%d err=%v", generationID, revision, updated.Revision, err)
		}
	}
	concurrentCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	concurrentResults := make(chan error, 8)
	for i := 0; i < cap(concurrentResults); i++ {
		i := i
		go func() {
			_, createErr := app.CreateMemory(concurrentCtx, MemoryCreateRequest{PrincipalID: actor.ID, ProjectID: projectID, IdempotencyKey: fmt.Sprintf("19191919-1919-4191-8191-%012d", 1944+i), LogicalKey: fmt.Sprintf("rebuild-concurrent-%d", i), Kind: "decision", Trust: "curated", Document: json.RawMessage(`{"title":"concurrent rebuild write"}`)})
			concurrentResults <- createErr
		}()
	}
	for i := 0; i < cap(concurrentResults); i++ {
		if createErr := <-concurrentResults; createErr != nil {
			t.Fatalf("concurrent embedding enqueue write %d: %v", i, createErr)
		}
	}
	if _, err := ownerDB.ExecContext(ctx, `SELECT generation_id FROM brain.start_embedding_generation($1,$2,$3)`, "local.e5-xl", "2026-07-01", 1536); err == nil {
		t.Fatal("second building generation succeeded")
	}
	if _, err := app.db.ExecContext(ctx, `SELECT generation_id FROM brain.start_embedding_generation($1,$2,$3)`, "local.e5-xl", "2026-07-01", 1536); err == nil {
		t.Fatal("application role started an embedding rebuild")
	}
	if _, err := app.db.ExecContext(ctx, `SELECT enqueued FROM brain.enqueue_embedding_rebuild_batch($1,$2)`, buildingID, 1); err == nil {
		t.Fatal("application role scanned an embedding rebuild")
	}
	if _, err := ownerDB.ExecContext(ctx, `SELECT generation_id FROM brain.activate_embedding_generation($1)`, buildingID); err == nil {
		t.Fatal("incomplete embedding rebuild activated")
	}
	if _, err := app.db.ExecContext(ctx, `SELECT generation_id FROM brain.activate_embedding_generation($1)`, buildingID); err == nil {
		t.Fatal("application role activated an embedding rebuild")
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE brain.embedding_jobs SET state='succeeded',completed_at=statement_timestamp(),updated_at=statement_timestamp() WHERE generation_id=$1`, buildingID); err != nil {
		t.Fatalf("complete rebuilt jobs: %v", err)
	}
	var activatedID string
	if err := ownerDB.QueryRowContext(ctx, `SELECT generation_id::text FROM brain.activate_embedding_generation($1)`, buildingID).Scan(&activatedID); err != nil || activatedID != buildingID {
		t.Fatalf("activate rebuilt generation=%q want=%q err=%v", activatedID, buildingID, err)
	}
	var active, building, oldJobs, rebuildProgress int
	if err := ownerDB.QueryRowContext(ctx, `
		SELECT
			(SELECT count(*) FROM brain.embedding_generations WHERE state='active'),
			(SELECT count(*) FROM brain.embedding_generations WHERE state='building'),
			(SELECT count(*) FROM brain.embedding_jobs WHERE generation_id=$1),
			(SELECT count(*) FROM brain.embedding_rebuild_progress WHERE generation_id=$2)`, activeID, buildingID).Scan(&active, &building, &oldJobs, &rebuildProgress); err != nil || active != 1 || building != 0 || oldJobs != 0 || rebuildProgress != 0 {
		t.Fatalf("activated generations active=%d building=%d old_jobs=%d rebuild_progress=%d err=%v", active, building, oldJobs, rebuildProgress, err)
	}
	if _, err := ownerDB.ExecContext(ctx, `SELECT generation_id FROM brain.activate_embedding_generation($1)`, buildingID); err == nil {
		t.Fatal("replayed embedding activation succeeded")
	}
	postActivation := create("19191919-1919-4191-8191-191919191952", "after activation")
	if err := ownerDB.QueryRowContext(ctx, `SELECT revision FROM brain.embedding_jobs WHERE generation_id=$1 AND item_id=$2`, buildingID, postActivation.ItemID).Scan(&revision); err != nil || revision != postActivation.Revision {
		t.Fatalf("activated generation post-write revision=%d want=%d err=%v", revision, postActivation.Revision, err)
	}
}
