package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
)

func testMemorySemanticCandidateIntegration(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB) {
	t.Helper()
	actor, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "semantic candidate actor")
	if err != nil {
		t.Fatal(err)
	}
	var projectID, generationID string
	var dimensions int
	if err := ownerDB.QueryRowContext(ctx, `INSERT INTO relay.projects(display_name,created_by) VALUES ('semantic candidate project',$1) RETURNING id::text`, actor.ID).Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	for _, capability := range []Capability{CapabilityMemoryWrite, CapabilityMemorySearch} {
		if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants(principal_id,scope,project_id,capability) VALUES ($1,'project',$2,$3)`, actor.ID, projectID, capability); err != nil {
			t.Fatal(err)
		}
	}
	if err := ownerDB.QueryRowContext(ctx, `SELECT id::text,dimensions FROM brain.embedding_generations WHERE state='active'`).Scan(&generationID, &dimensions); err != nil {
		t.Fatal(err)
	}
	query := make([]float64, dimensions)
	query[0] = 1
	farthestVector := make([]float64, dimensions)
	if dimensions > 1 {
		farthestVector[1] = 1
	} else {
		farthestVector[0] = -1
	}
	create := func(key, title string) MemoryMutationResult {
		t.Helper()
		result, createErr := app.CreateMemory(ctx, MemoryCreateRequest{PrincipalID: actor.ID, ProjectID: projectID, IdempotencyKey: key, LogicalKey: "semantic-" + key, Kind: "decision", Trust: "curated", Document: json.RawMessage(`{"title":` + strconvQuote(title) + `}`)})
		if createErr != nil {
			t.Fatal(createErr)
		}
		return result
	}
	nearest := create("28282828-2828-4282-8282-282828282801", "nearest semantic result")
	farthest := create("28282828-2828-4282-8282-282828282802", "farthest semantic result")
	zeroNorm := create("28282828-2828-4282-8282-282828282803", "zero norm semantic result")
	zeroVector := make([]float64, dimensions)
	for _, fixture := range []struct {
		item   MemoryMutationResult
		vector string
	}{
		{nearest, memorySemanticVector(query)},
		{farthest, memorySemanticVector(farthestVector)},
		{zeroNorm, memorySemanticVector(zeroVector)},
	} {
		if _, err := ownerDB.ExecContext(ctx, `INSERT INTO brain.embedding_chunks(generation_id,item_id,revision,ordinal,content_sha256,start_offset,end_offset,embedding)
VALUES ($1,$2,$3,0,decode('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','hex'),0,1,$4::public.vector)`, generationID, fixture.item.ItemID, fixture.item.Revision, fixture.vector); err != nil {
			t.Fatal(err)
		}
		if _, err := ownerDB.ExecContext(ctx, `UPDATE brain.embedding_jobs SET state='succeeded',completed_at=statement_timestamp(),updated_at=statement_timestamp() WHERE generation_id=$1 AND item_id=$2 AND revision=$3`, generationID, fixture.item.ItemID, fixture.item.Revision); err != nil {
			t.Fatal(err)
		}
	}
	page, err := app.SearchMemorySemanticCandidates(ctx, MemorySemanticSearchRequest{PrincipalID: actor.ID, ProjectID: projectID, Embedding: query, Limit: 2})
	if err != nil || len(page.Results) != 2 || page.Results[0].ItemID != nearest.ItemID || page.Results[1].ItemID != farthest.ItemID || page.Results[0].Distance != 0 || page.Results[1].Distance <= page.Results[0].Distance {
		t.Fatalf("semantic candidates=%#v err=%v", page, err)
	}
	outsider, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "semantic candidate outsider")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.SearchMemorySemanticCandidates(ctx, MemorySemanticSearchRequest{PrincipalID: outsider.ID, ProjectID: projectID, Embedding: query, Limit: 2}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unauthorized semantic candidates error=%v", err)
	}
}
