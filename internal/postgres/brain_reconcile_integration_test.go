package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func testMemoryReconciliationSchemaDriftIntegration(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB) {
	t.Helper()
	var definition string
	if err := ownerDB.QueryRowContext(ctx, `SELECT pg_get_functiondef('brain.reconcile_memory_references(uuid,uuid,integer)'::regprocedure)`).Scan(&definition); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `GRANT EXECUTE ON FUNCTION brain.reconcile_memory_references(uuid,uuid,integer) TO PUBLIC`); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err == nil {
		t.Fatal("readiness accepted public reconciliation execution")
	}
	if _, err := ownerDB.ExecContext(ctx, `REVOKE EXECUTE ON FUNCTION brain.reconcile_memory_references(uuid,uuid,integer) FROM PUBLIC`); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `CREATE OR REPLACE FUNCTION brain.reconcile_memory_references(
requested_principal uuid,requested_project uuid,requested_limit integer)
RETURNS TABLE(alias_repairs integer,orphan_edges_removed integer,more boolean,change_sequence bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$ BEGIN RETURN QUERY SELECT 0,0,false,0::bigint; END $function$`); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err == nil {
		t.Fatal("readiness accepted replacement reconciliation routine")
	}
	if _, err := ownerDB.ExecContext(ctx, definition); err != nil {
		t.Fatal(err)
	}
	if err := app.Ready(ctx); err != nil {
		t.Fatalf("readiness did not recover after reconciliation drift: %v", err)
	}
}

func testMemoryReferenceReconciliationRaces(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB) {
	t.Helper()
	actor, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "reference reconciliation race actor")
	if err != nil {
		t.Fatal(err)
	}
	const (
		source    = "22222222-2222-4222-8222-222222222310"
		legacy    = "22222222-2222-4222-8222-222222222311"
		canonical = "22222222-2222-4222-8222-222222222320"
	)
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO relay.projects(id,display_name,created_by) VALUES
($1,'reconcile race source',$4),($2,'reconcile race legacy',$4),
($3,'reconcile race canonical',$4)`, source, legacy, canonical, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE relay.projects
SET merged_into=$1,merged_at=statement_timestamp() WHERE id=$2`, source, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO relay.project_identities(project_id,kind,normalized_locator,created_by)
VALUES ($1,'operator_alias','reconcile race canonical',$3),
       ($2,'operator_alias','reconcile race source',$3)`, canonical, source, actor.ID); err != nil {
		t.Fatal(err)
	}
	for _, projectID := range []string{canonical, source} {
		for _, capability := range []Capability{
			CapabilityProjectAdminister, CapabilityMemoryAdminister,
			CapabilityMemoryWrite, CapabilityMemoryPurge,
		} {
			if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants
(principal_id,scope,project_id,capability) VALUES ($1,'project',$2,$3)`,
				actor.ID, projectID, capability); err != nil {
				t.Fatal(err)
			}
		}
	}
	preview, err := app.PreviewProjectIdentityMerge(ctx, ProjectMergePreviewRequest{
		ActorPrincipalID: actor.ID, SourceProjectID: source,
		IdempotencyKey: "22222222-2222-4222-8222-222222222323",
		Kind:           ProjectIdentityOperatorAlias, Locator: "reconcile race canonical",
	})
	if err != nil {
		t.Fatal(err)
	}
	lockTx, err := ownerDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockTx.ExecContext(ctx, `SELECT id FROM relay.projects WHERE id=$1 FOR UPDATE`, legacy); err != nil {
		_ = lockTx.Rollback()
		t.Fatal(err)
	}
	raceCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	mergeResult := make(chan error, 1)
	reconcileResult := make(chan struct {
		result MemoryReconcileResult
		err    error
	}, 1)
	go func() {
		result, reconcileErr := app.ReconcileMemoryReferences(raceCtx, MemoryReconcileRequest{
			PrincipalID: actor.ID, ProjectID: source, Limit: maxMemoryReconcileBatch,
		})
		reconcileResult <- struct {
			result MemoryReconcileResult
			err    error
		}{result: result, err: reconcileErr}
	}()
	waitDeadline := time.Now().Add(time.Second)
	for {
		var lockWaiters int
		if err := ownerDB.QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity
WHERE usename='punaro_app' AND wait_event_type='Lock'
  AND query LIKE '%reconcile_memory_references%'`).Scan(&lockWaiters); err != nil {
			_ = lockTx.Rollback()
			t.Fatal(err)
		}
		if lockWaiters > 0 {
			break
		}
		if time.Now().After(waitDeadline) {
			_ = lockTx.Rollback()
			t.Fatal("reconciliation did not reach the held legacy-project lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	go func() {
		_, mergeErr := app.ApproveProjectIdentityMerge(raceCtx, ProjectMergeApproval{
			ActorPrincipalID: actor.ID, PreviewID: preview.PreviewID,
		})
		mergeResult <- mergeErr
	}()
	waitDeadline = time.Now().Add(time.Second)
	for {
		var lockWaiters int
		if err := ownerDB.QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity
WHERE usename='punaro_app' AND wait_event_type='Lock'`).Scan(&lockWaiters); err != nil {
			_ = lockTx.Rollback()
			t.Fatal(err)
		}
		if lockWaiters >= 2 {
			break
		}
		if time.Now().After(waitDeadline) {
			_ = lockTx.Rollback()
			t.Fatal("project merge did not serialize behind reconciliation")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := lockTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	reconciled := <-reconcileResult
	if mergeErr := <-mergeResult; !errors.Is(mergeErr, ErrStaleProjectMerge) || reconciled.err != nil ||
		reconciled.result.AliasRepairs != 1 {
		t.Fatalf("merge/reconciliation overlap merge=%v reconciliation=%#v err=%v",
			mergeErr, reconciled.result, reconciled.err)
	}
	preview, err = app.PreviewProjectIdentityMerge(ctx, ProjectMergePreviewRequest{
		ActorPrincipalID: actor.ID, SourceProjectID: source,
		IdempotencyKey: "22222222-2222-4222-8222-222222222327",
		Kind:           ProjectIdentityOperatorAlias, Locator: "reconcile race canonical",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.ApproveProjectIdentityMerge(ctx, ProjectMergeApproval{
		ActorPrincipalID: actor.ID, PreviewID: preview.PreviewID,
	}); err != nil {
		t.Fatalf("fresh project merge after reconciliation: %v", err)
	}
	if _, err := app.ReconcileMemoryReferences(ctx, MemoryReconcileRequest{
		PrincipalID: actor.ID, ProjectID: canonical, Limit: maxMemoryReconcileBatch,
	}); err != nil {
		t.Fatal(err)
	}
	var sourceAlias, legacyAlias, legacyMergedInto string
	if err := ownerDB.QueryRowContext(ctx, `SELECT
(SELECT canonical_project_id::text FROM relay.project_lookup_aliases WHERE alias_project_id=$1),
(SELECT canonical_project_id::text FROM relay.project_lookup_aliases WHERE alias_project_id=$2),
(SELECT merged_into::text FROM relay.projects WHERE id=$2)`,
		source, legacy).Scan(&sourceAlias, &legacyAlias, &legacyMergedInto); err != nil ||
		sourceAlias != canonical || legacyAlias != canonical || legacyMergedInto != canonical {
		t.Fatalf("merge overlap source_alias=%s legacy_alias=%s legacy_merged_into=%s err=%v",
			sourceAlias, legacyAlias, legacyMergedInto, err)
	}

	purgeOrigin, err := app.CreateMemory(ctx, MemoryCreateRequest{
		PrincipalID: actor.ID, ProjectID: canonical,
		IdempotencyKey: "22222222-2222-4222-8222-222222222324",
		Kind:           "decision", Trust: "curated", Document: json.RawMessage(`{"fact":"purge-race origin"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	purgeTarget, err := app.CreateMemory(ctx, MemoryCreateRequest{
		PrincipalID: actor.ID, ProjectID: canonical,
		IdempotencyKey: "22222222-2222-4222-8222-222222222325",
		Kind:           "decision", Trust: "curated", Document: json.RawMessage(`{"fact":"purge-race target"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO brain.memory_edges
(from_item_id,from_revision,ordinal,edge_type,to_item_id,to_revision,created_by)
VALUES ($1,$2,0,'supports',$3,$4,$5)`,
		purgeOrigin.ItemID, purgeOrigin.Revision, purgeTarget.ItemID, purgeTarget.Revision, actor.ID); err != nil {
		t.Fatal(err)
	}
	purgeLock, err := ownerDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := purgeLock.ExecContext(ctx, `SELECT id FROM brain.memory_items WHERE id=$1 FOR UPDATE`, purgeTarget.ItemID); err != nil {
		_ = purgeLock.Rollback()
		t.Fatal(err)
	}
	purgeCtx, purgeCancel := context.WithTimeout(ctx, 5*time.Second)
	defer purgeCancel()
	purgeDone := make(chan error, 1)
	purgeStarted := make(chan struct{})
	go func() {
		close(purgeStarted)
		_, purgeErr := app.DeleteMemory(purgeCtx, MemoryDeleteRequest{
			PrincipalID: actor.ID, ProjectID: canonical, ItemID: purgeTarget.ItemID,
			IdempotencyKey: "22222222-2222-4222-8222-222222222326", ExpectedETag: purgeTarget.ETag,
		})
		purgeDone <- purgeErr
	}()
	<-purgeStarted
	waitDeadline = time.Now().Add(time.Second)
	for {
		var lockWaiters int
		if err := ownerDB.QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity
WHERE usename='punaro_app' AND wait_event_type='Lock'
  AND query LIKE '%brain.memory_items%'`).Scan(&lockWaiters); err != nil {
			_ = purgeLock.Rollback()
			t.Fatal(err)
		}
		if lockWaiters > 0 {
			break
		}
		if time.Now().After(waitDeadline) {
			_ = purgeLock.Rollback()
			t.Fatal("purge did not reach the held memory lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	reconcileDone := make(chan struct {
		result MemoryReconcileResult
		err    error
	}, 1)
	go func() {
		result, reconcileErr := app.ReconcileMemoryReferences(purgeCtx, MemoryReconcileRequest{
			PrincipalID: actor.ID, ProjectID: canonical, Limit: maxMemoryReconcileBatch,
		})
		reconcileDone <- struct {
			result MemoryReconcileResult
			err    error
		}{result: result, err: reconcileErr}
	}()
	if err := purgeLock.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := <-purgeDone; err != nil {
		t.Fatalf("purge/reconciliation overlap purge=%v", err)
	}
	overlap := <-reconcileDone
	if overlap.err != nil {
		t.Fatalf("purge/reconciliation overlap reconciliation=%v", overlap.err)
	}
	afterPurge, err := app.ReconcileMemoryReferences(ctx, MemoryReconcileRequest{
		PrincipalID: actor.ID, ProjectID: canonical, Limit: maxMemoryReconcileBatch,
	})
	if err != nil || overlap.result.OrphanEdgesRemoved+afterPurge.OrphanEdgesRemoved != 1 {
		t.Fatalf("purge overlap reconciliation=%#v follow-up=%#v err=%v", overlap.result, afterPurge, err)
	}
}

func testMemoryReferenceReconciliationIntegration(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB) {
	t.Helper()
	actor, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "reference reconciliation actor")
	if err != nil {
		t.Fatal(err)
	}
	outsider, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "reference reconciliation outsider")
	if err != nil {
		t.Fatal(err)
	}
	const (
		canonical = "22222222-2222-4222-8222-222222222210"
		other     = "22222222-2222-4222-8222-222222222220"
		retiredA  = "22222222-2222-4222-8222-222222222211"
		retiredB  = "22222222-2222-4222-8222-222222222212"
	)
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO relay.projects(id,display_name,created_by) VALUES
($1,'reconcile canonical',$5),($2,'reconcile other',$5),
($3,'reconcile retired a',$5),($4,'reconcile retired b',$5)`,
		canonical, other, retiredA, retiredB, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE relay.projects
SET merged_into=$1,merged_at=statement_timestamp()
WHERE id=ANY($2::uuid[])`, canonical, []string{retiredA, retiredB}); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO relay.project_lookup_aliases(alias_project_id,canonical_project_id) VALUES ($1,$2)`, retiredB, other); err != nil {
		t.Fatal(err)
	}
	for _, capability := range []Capability{CapabilityMemoryAdminister, CapabilityMemoryWrite, CapabilityMemoryPurge} {
		if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants(principal_id,scope,project_id,capability)
VALUES ($1,'project',$2,$3)`, actor.ID, canonical, capability); err != nil {
			t.Fatal(err)
		}
	}
	for _, capability := range []Capability{CapabilityMemoryWrite, CapabilityMemoryPurge} {
		if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants(principal_id,scope,project_id,capability)
VALUES ($1,'project',$2,$3)`, actor.ID, other, capability); err != nil {
			t.Fatal(err)
		}
	}
	source, err := app.CreateMemory(ctx, MemoryCreateRequest{
		PrincipalID: actor.ID, ProjectID: canonical,
		IdempotencyKey: "22222222-2222-4222-8222-222222222230",
		Kind:           "decision", Trust: "curated", Document: json.RawMessage(`{"fact":"source"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	target, err := app.CreateMemory(ctx, MemoryCreateRequest{
		PrincipalID: actor.ID, ProjectID: canonical,
		IdempotencyKey: "22222222-2222-4222-8222-222222222231",
		Kind:           "decision", Trust: "curated", Document: json.RawMessage(`{"fact":"target"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	validTarget, err := app.CreateMemory(ctx, MemoryCreateRequest{
		PrincipalID: actor.ID, ProjectID: canonical,
		IdempotencyKey: "22222222-2222-4222-8222-222222222232",
		Kind:           "decision", Trust: "curated", Document: json.RawMessage(`{"fact":"valid target"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO brain.memory_edges
(from_item_id,from_revision,ordinal,edge_type,to_item_id,to_revision,created_by)
VALUES ($1,$2,0,'supports',$3,$4,$5),($1,$2,1,'contradicts',$6,$7,$5)`,
		source.ItemID, source.Revision, target.ItemID, target.Revision, actor.ID, validTarget.ItemID, validTarget.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO brain.memory_sources
(item_id,revision,ordinal,mode,kind,reference_sha256,created_by)
VALUES ($1,$2,0,'copied','external',decode(repeat('ab',32),'hex'),$3)`,
		source.ItemID, source.Revision, actor.ID); err != nil {
		t.Fatal(err)
	}
	proposalTx, err := ownerDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var proposalID string
	if err := proposalTx.QueryRowContext(ctx, `INSERT INTO brain.memory_proposals
(scope_id,action,proposed_by,payload_sha256,payload)
SELECT id,'create',$2,decode(repeat('cd',32),'hex'),convert_to('{}','UTF8')
FROM brain.scopes WHERE project_id=$1 RETURNING id::text`, canonical, actor.ID).Scan(&proposalID); err != nil {
		_ = proposalTx.Rollback()
		t.Fatal(err)
	}
	if _, err := proposalTx.ExecContext(ctx, `INSERT INTO brain.memory_proposal_evidence
(proposal_id,ordinal,item_id,revision) VALUES ($1,0,$2,$3)`, proposalID, target.ItemID, target.Revision); err != nil {
		_ = proposalTx.Rollback()
		t.Fatal(err)
	}
	if err := proposalTx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DeleteMemory(ctx, MemoryDeleteRequest{
		PrincipalID: actor.ID, ProjectID: canonical, ItemID: target.ItemID,
		IdempotencyKey: "22222222-2222-4222-8222-222222222233", ExpectedETag: target.ETag,
	}); err != nil {
		t.Fatal(err)
	}
	foreignSource, err := app.CreateMemory(ctx, MemoryCreateRequest{
		PrincipalID: actor.ID, ProjectID: other,
		IdempotencyKey: "22222222-2222-4222-8222-222222222234",
		Kind:           "decision", Trust: "curated", Document: json.RawMessage(`{"fact":"foreign source"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	foreignTarget, err := app.CreateMemory(ctx, MemoryCreateRequest{
		PrincipalID: actor.ID, ProjectID: other,
		IdempotencyKey: "22222222-2222-4222-8222-222222222235",
		Kind:           "decision", Trust: "curated", Document: json.RawMessage(`{"fact":"foreign target"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO brain.memory_edges
(from_item_id,from_revision,ordinal,edge_type,to_item_id,to_revision,created_by)
VALUES ($1,$2,0,'supports',$3,$4,$5)`,
		foreignSource.ItemID, foreignSource.Revision, foreignTarget.ItemID, foreignTarget.Revision, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DeleteMemory(ctx, MemoryDeleteRequest{
		PrincipalID: actor.ID, ProjectID: other, ItemID: foreignTarget.ItemID,
		IdempotencyKey: "22222222-2222-4222-8222-222222222236", ExpectedETag: foreignTarget.ETag,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO relay.project_lookup_aliases(alias_project_id,canonical_project_id)
VALUES ($1,$2)`, other, canonical); err != nil {
		t.Fatal(err)
	}

	for name, request := range map[string]MemoryReconcileRequest{
		"unauthorized":  {PrincipalID: outsider.ID, ProjectID: canonical, Limit: 1},
		"indirect":      {PrincipalID: actor.ID, ProjectID: retiredA, Limit: 1},
		"cross project": {PrincipalID: actor.ID, ProjectID: other, Limit: 1},
	} {
		if _, err := app.ReconcileMemoryReferences(ctx, request); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s reconciliation error=%v", name, err)
		}
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants(principal_id,scope,project_id,capability)
VALUES ($1,'project',$2,'memory.administer')`, outsider.ID, canonical); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE auth.principals SET disabled_at=statement_timestamp() WHERE id=$1`, outsider.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.ReconcileMemoryReferences(ctx, MemoryReconcileRequest{
		PrincipalID: outsider.ID, ProjectID: canonical, Limit: 1,
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("disabled reconciliation error=%v", err)
	}
	var directAliasRepairs, directOrphans int
	var directMore bool
	var directSequence int64
	directErr := app.brainPool().QueryRowContext(ctx, `SELECT alias_repairs,orphan_edges_removed,more,change_sequence
FROM brain.reconcile_memory_references($1,$2,NULL)`, actor.ID, canonical).
		Scan(&directAliasRepairs, &directOrphans, &directMore, &directSequence)
	if !isSQLState(directErr, "22023") {
		t.Fatalf("NULL reconciliation limit error=%v, want SQLSTATE 22023", directErr)
	}
	var prematureAliases int
	if err := ownerDB.QueryRowContext(ctx, `SELECT count(*) FROM relay.project_lookup_aliases
WHERE alias_project_id=ANY($1::uuid[]) AND canonical_project_id=$2`,
		[]string{retiredA, retiredB}, canonical).Scan(&prematureAliases); err != nil || prematureAliases != 0 {
		t.Fatalf("NULL reconciliation mutated aliases=%d err=%v", prematureAliases, err)
	}

	before, err := app.InstallationState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	first, err := app.ReconcileMemoryReferences(ctx, MemoryReconcileRequest{PrincipalID: actor.ID, ProjectID: canonical, Limit: 1})
	if err != nil || first.AliasRepairs != 1 || first.OrphanEdgesRemoved != 0 || !first.More || first.ChangeSequence != before.ChangeSequence+1 {
		t.Fatalf("first reconciliation=%#v err=%v", first, err)
	}
	second, err := app.ReconcileMemoryReferences(ctx, MemoryReconcileRequest{PrincipalID: actor.ID, ProjectID: canonical, Limit: 1})
	if err != nil || second.AliasRepairs != 1 || second.OrphanEdgesRemoved != 0 || !second.More || second.ChangeSequence != first.ChangeSequence+1 {
		t.Fatalf("second reconciliation=%#v err=%v", second, err)
	}
	third, err := app.ReconcileMemoryReferences(ctx, MemoryReconcileRequest{PrincipalID: actor.ID, ProjectID: canonical, Limit: 1})
	if err != nil || third.AliasRepairs != 0 || third.OrphanEdgesRemoved != 1 || third.More || third.ChangeSequence != second.ChangeSequence+1 {
		t.Fatalf("third reconciliation=%#v err=%v", third, err)
	}
	noOp, err := app.ReconcileMemoryReferences(ctx, MemoryReconcileRequest{PrincipalID: actor.ID, ProjectID: canonical, Limit: maxMemoryReconcileBatch})
	if err != nil || noOp != (MemoryReconcileResult{}) {
		t.Fatalf("converged reconciliation=%#v err=%v", noOp, err)
	}

	var repairedA, repairedB string
	if err := ownerDB.QueryRowContext(ctx, `SELECT
(SELECT canonical_project_id::text FROM relay.project_lookup_aliases WHERE alias_project_id=$1),
(SELECT canonical_project_id::text FROM relay.project_lookup_aliases WHERE alias_project_id=$2)`,
		retiredA, retiredB).Scan(&repairedA, &repairedB); err != nil || repairedA != canonical || repairedB != canonical {
		t.Fatalf("repaired aliases=(%s,%s) err=%v", repairedA, repairedB, err)
	}
	var orphanEdges, validEdges, foreignEdges, sources, proposalEvidence, audits int
	if err := ownerDB.QueryRowContext(ctx, `SELECT
(SELECT count(*) FROM brain.memory_edges WHERE from_item_id=$1 AND to_item_id=$2),
(SELECT count(*) FROM brain.memory_edges WHERE from_item_id=$1 AND to_item_id=$3),
(SELECT count(*) FROM brain.memory_edges WHERE from_item_id=$4 AND to_item_id=$5),
(SELECT count(*) FROM brain.memory_sources WHERE item_id=$1),
(SELECT count(*) FROM brain.memory_proposal_evidence WHERE proposal_id=$6 AND item_id=$2),
(SELECT count(*) FROM audit.events WHERE project_id=$7 AND action='memory.reconcile')`,
		source.ItemID, target.ItemID, validTarget.ItemID, foreignSource.ItemID, foreignTarget.ItemID, proposalID, canonical).
		Scan(&orphanEdges, &validEdges, &foreignEdges, &sources, &proposalEvidence, &audits); err != nil {
		t.Fatal(err)
	}
	if orphanEdges != 0 || validEdges != 1 || foreignEdges != 1 || sources != 1 || proposalEvidence != 1 || audits != 3 {
		t.Fatalf("reconciled rows orphan=%d valid=%d foreign=%d sources=%d proposal_evidence=%d audits=%d",
			orphanEdges, validEdges, foreignEdges, sources, proposalEvidence, audits)
	}
	var identityGeneration, contentGeneration int64
	if err := ownerDB.QueryRowContext(ctx, `SELECT identity_generation,content_generation FROM relay.projects WHERE id=$1`, canonical).
		Scan(&identityGeneration, &contentGeneration); err != nil || identityGeneration != 2 || contentGeneration < 6 {
		t.Fatalf("reconciliation generations identity=%d content=%d err=%v", identityGeneration, contentGeneration, err)
	}
}
