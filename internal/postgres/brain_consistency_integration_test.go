package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func testMemoryConsistencyIntegration(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB) {
	t.Helper()
	actor, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "memory consistency actor")
	if err != nil {
		t.Fatal(err)
	}
	outsider, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "memory consistency outsider")
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "memory consistency disabled")
	if err != nil {
		t.Fatal(err)
	}
	var canonical, retired, other, foreign string
	for name, target := range map[string]*string{
		"consistency canonical": &canonical,
		"consistency retired":   &retired,
		"consistency other":     &other,
		"consistency foreign":   &foreign,
	} {
		if err := ownerDB.QueryRowContext(ctx, `INSERT INTO relay.projects(display_name,created_by) VALUES ($1,$2) RETURNING id::text`, name, actor.ID).Scan(target); err != nil {
			t.Fatal(err)
		}
	}
	for _, projectID := range []string{canonical, retired, other, foreign} {
		for _, capability := range []Capability{CapabilityMemoryAdminister, CapabilityMemoryWrite} {
			if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants(principal_id,scope,project_id,capability)
VALUES ($1,'project',$2,$3)`, actor.ID, projectID, capability); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants(principal_id,scope,project_id,capability)
VALUES ($1,'project',$2,$3)`, disabled.ID, canonical, CapabilityMemoryAdminister); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE auth.principals SET disabled_at=statement_timestamp() WHERE id=$1`, disabled.ID); err != nil {
		t.Fatal(err)
	}
	create := func(projectID, key, logicalKey, title string) MemoryMutationResult {
		t.Helper()
		result, createErr := app.CreateMemory(ctx, MemoryCreateRequest{
			PrincipalID: actor.ID, ProjectID: projectID, IdempotencyKey: key,
			LogicalKey: logicalKey, Kind: "preference", Trust: "curated",
			Document: json.RawMessage(`{"title":` + strconvQuote(title) + `,"body":"stable body"}`),
		})
		if createErr != nil {
			t.Fatal(createErr)
		}
		return result
	}
	first := create(canonical, "23232323-2323-4232-8232-232323232311", "consistency.first", "healthy first")
	second := create(canonical, "23232323-2323-4232-8232-232323232312", "consistency.second", "corrupt second")
	retiredItem := create(retired, "23232323-2323-4232-8232-232323232313", "consistency.retired", "retired item")
	otherItem := create(other, "23232323-2323-4232-8232-232323232314", "consistency.other", "other item")
	foreignItem := create(foreign, "23232323-2323-4232-8232-232323232315", "consistency.foreign", "foreign item")
	if _, err := ownerDB.ExecContext(ctx, `UPDATE relay.projects
SET merged_into=$2,merged_at=statement_timestamp() WHERE id=$1`, retired, canonical); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO relay.project_lookup_aliases(alias_project_id,canonical_project_id)
VALUES ($1,$2),($3,$2)`, retired, canonical, foreign); err != nil {
		t.Fatal(err)
	}
	for _, itemID := range []string{second.ItemID, retiredItem.ItemID, otherItem.ItemID, foreignItem.ItemID} {
		if _, err := ownerDB.ExecContext(ctx, `UPDATE brain.memory_revisions
SET content_sha256=decode(repeat('00',32),'hex') WHERE item_id=$1 AND revision=1`, itemID); err != nil {
			t.Fatal(err)
		}
	}
	for _, projectID := range []string{other, foreign} {
		if _, err := ownerDB.ExecContext(ctx, `UPDATE auth.capability_grants
SET revoked_at=statement_timestamp()
WHERE principal_id=$1 AND project_id=$2 AND capability=$3 AND revoked_at IS NULL`,
			actor.ID, projectID, CapabilityMemoryAdminister); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := app.VerifyMemoryConsistency(ctx, MemoryConsistencyRequest{
		PrincipalID: outsider.ID, ProjectID: canonical, Limit: 1,
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unauthorized consistency error=%v", err)
	}
	if _, err := app.VerifyMemoryConsistency(ctx, MemoryConsistencyRequest{
		PrincipalID: disabled.ID, ProjectID: canonical, Limit: 1,
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("disabled consistency error=%v", err)
	}
	if _, err := app.VerifyMemoryConsistency(ctx, MemoryConsistencyRequest{
		PrincipalID: actor.ID, ProjectID: retired, Limit: 1,
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("alias consistency authority error=%v", err)
	}
	if _, err := app.VerifyMemoryConsistency(ctx, MemoryConsistencyRequest{
		PrincipalID: actor.ID, ProjectID: foreign, Limit: 1,
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("corrupt active alias consistency authority error=%v", err)
	}
	if _, err := app.VerifyMemoryConsistency(ctx, MemoryConsistencyRequest{
		PrincipalID: actor.ID, ProjectID: other, Limit: 1,
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-project consistency error=%v", err)
	}
	var checked int
	var issues []MemoryConsistencyIssue
	cursor := ""
	for {
		page, verifyErr := app.VerifyMemoryConsistency(ctx, MemoryConsistencyRequest{
			PrincipalID: actor.ID, ProjectID: canonical, AfterItemID: cursor, Limit: 1,
		})
		if verifyErr != nil || !page.LexicalControlsConsistent || page.Checked != 1 {
			t.Fatalf("consistency page=%#v err=%v", page, verifyErr)
		}
		checked += page.Checked
		issues = append(issues, page.Issues...)
		if !page.More {
			if page.NextAfterItemID != "" {
				t.Fatalf("terminal consistency cursor=%q", page.NextAfterItemID)
			}
			break
		}
		if !validOpaqueID(page.NextAfterItemID) || page.NextAfterItemID == cursor {
			t.Fatalf("invalid consistency cursor=%q after=%q", page.NextAfterItemID, cursor)
		}
		cursor = page.NextAfterItemID
	}
	if checked != 3 {
		t.Fatalf("checked=%d, want canonical plus retired rows only", checked)
	}
	if len(issues) != 2 {
		t.Fatalf("issues=%#v, want canonical and retired hash corruption", issues)
	}
	issueItems := map[string]bool{}
	for _, issue := range issues {
		if issue.Class != MemoryConsistencyContentHash || issue.Revision != 1 {
			t.Fatalf("unexpected consistency issue=%#v", issue)
		}
		issueItems[issue.ItemID] = true
	}
	if !issueItems[second.ItemID] || !issueItems[retiredItem.ItemID] ||
		issueItems[first.ItemID] || issueItems[otherItem.ItemID] || issueItems[foreignItem.ItemID] {
		t.Fatalf("consistency issue isolation=%#v", issueItems)
	}
	encoded, err := json.Marshal(issues)
	if err != nil || strings.Contains(string(encoded), "healthy first") || strings.Contains(string(encoded), "stable body") ||
		strings.Contains(string(encoded), "content_sha256") {
		t.Fatalf("consistency result leaked content/hash: %s err=%v", encoded, err)
	}
	if _, err := ownerDB.ExecContext(ctx, `ALTER INDEX brain.memory_revisions_search_vector
RENAME TO memory_revisions_search_vector_drift`); err != nil {
		t.Fatal(err)
	}
	drifted, driftErr := app.VerifyMemoryConsistency(ctx, MemoryConsistencyRequest{
		PrincipalID: actor.ID, ProjectID: canonical, Limit: 2,
	})
	if _, err := ownerDB.ExecContext(ctx, `ALTER INDEX brain.memory_revisions_search_vector_drift
RENAME TO memory_revisions_search_vector`); err != nil {
		t.Fatal(err)
	}
	if driftErr != nil || drifted.LexicalControlsConsistent || drifted.Checked != 0 || len(drifted.Issues) != 0 || drifted.More {
		t.Fatalf("lexical drift report=%#v err=%v", drifted, driftErr)
	}
	lockTx, err := ownerDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockTx.ExecContext(ctx, `LOCK TABLE brain.memory_items IN ACCESS EXCLUSIVE MODE`); err != nil {
		_ = lockTx.Rollback()
		t.Fatal(err)
	}
	started := time.Now()
	_, timeoutErr := app.VerifyMemoryConsistency(ctx, MemoryConsistencyRequest{
		PrincipalID: actor.ID, ProjectID: canonical, Limit: 2,
	})
	elapsed := time.Since(started)
	if err := lockTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if timeoutErr == nil || elapsed < time.Second || elapsed > 3*time.Second {
		t.Fatalf("consistency timeout err=%v elapsed=%s", timeoutErr, elapsed)
	}
	if recovered, err := app.VerifyMemoryConsistency(ctx, MemoryConsistencyRequest{
		PrincipalID: actor.ID, ProjectID: canonical, Limit: 2,
	}); err != nil || recovered.Checked != 2 {
		t.Fatalf("consistency recovery=%#v err=%v", recovered, err)
	}
	for _, itemID := range []string{second.ItemID, retiredItem.ItemID, otherItem.ItemID, foreignItem.ItemID} {
		var document string
		if err := ownerDB.QueryRowContext(ctx, `SELECT document::text FROM brain.memory_revisions
WHERE item_id=$1 AND revision=1`, itemID).Scan(&document); err != nil {
			t.Fatal(err)
		}
		documentHash := sha256.Sum256([]byte(document))
		if _, err := ownerDB.ExecContext(ctx, `UPDATE brain.memory_revisions SET content_sha256=$2
WHERE item_id=$1 AND revision=1`, itemID, documentHash[:]); err != nil {
			t.Fatal(err)
		}
	}
	if finalPage, err := app.VerifyMemoryConsistency(ctx, MemoryConsistencyRequest{
		PrincipalID: actor.ID, ProjectID: canonical, Limit: maxMemoryConsistencyRows,
	}); err != nil || finalPage.More || finalPage.Checked != 3 || len(finalPage.Issues) != 0 {
		t.Fatalf("restored consistency page=%#v err=%v", finalPage, err)
	}
	snapshotTx, err := app.brainPool().BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelRepeatableRead,
		ReadOnly:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshotBefore, err := verifyMemoryConsistencyInTx(ctx, snapshotTx, canonical, "", maxMemoryConsistencyRows)
	if err != nil {
		_ = snapshotTx.Rollback()
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE brain.memory_revisions
SET content_sha256=decode(repeat('00',32),'hex') WHERE item_id=$1 AND revision=1`, first.ItemID); err != nil {
		_ = snapshotTx.Rollback()
		t.Fatal(err)
	}
	snapshotAfter, err := verifyMemoryConsistencyInTx(ctx, snapshotTx, canonical, "", maxMemoryConsistencyRows)
	if err != nil {
		_ = snapshotTx.Rollback()
		t.Fatal(err)
	}
	if !reflect.DeepEqual(snapshotAfter, snapshotBefore) || len(snapshotAfter.Issues) != 0 {
		_ = snapshotTx.Rollback()
		t.Fatalf("repeatable-read report changed before=%#v after=%#v", snapshotBefore, snapshotAfter)
	}
	if err := snapshotTx.Commit(); err != nil {
		t.Fatal(err)
	}
	freshAfterMutation, err := app.VerifyMemoryConsistency(ctx, MemoryConsistencyRequest{
		PrincipalID: actor.ID, ProjectID: canonical, Limit: maxMemoryConsistencyRows,
	})
	if err != nil || len(freshAfterMutation.Issues) != 1 ||
		freshAfterMutation.Issues[0].ItemID != first.ItemID ||
		freshAfterMutation.Issues[0].Class != MemoryConsistencyContentHash {
		t.Fatalf("fresh consistency report=%#v err=%v", freshAfterMutation, err)
	}
	var firstDocument string
	if err := ownerDB.QueryRowContext(ctx, `SELECT document::text FROM brain.memory_revisions
WHERE item_id=$1 AND revision=1`, first.ItemID).Scan(&firstDocument); err != nil {
		t.Fatal(err)
	}
	firstHash := sha256.Sum256([]byte(firstDocument))
	if _, err := ownerDB.ExecContext(ctx, `UPDATE brain.memory_revisions SET content_sha256=$2
WHERE item_id=$1 AND revision=1`, first.ItemID, firstHash[:]); err != nil {
		t.Fatal(err)
	}
	if converged, err := app.VerifyMemoryConsistency(ctx, MemoryConsistencyRequest{
		PrincipalID: actor.ID, ProjectID: canonical, Limit: maxMemoryConsistencyRows,
	}); err != nil || len(converged.Issues) != 0 {
		t.Fatalf("converged consistency report=%#v err=%v", converged, err)
	}
}

func strconvQuote(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}
