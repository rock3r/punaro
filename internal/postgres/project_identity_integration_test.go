package postgres

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
)

func testProjectIdentityIntegration(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB) {
	t.Helper()
	actor, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "identity administrator")
	if err != nil {
		t.Fatal(err)
	}
	sourceOnly, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "source member")
	if err != nil {
		t.Fatal(err)
	}
	canonicalOnly, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "canonical member")
	if err != nil {
		t.Fatal(err)
	}
	outsider, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "identity outsider")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants (principal_id, scope, capability) VALUES
($1, 'installation', 'project.create'), ($1, 'all_projects', 'project.administer')`, actor.ID); err != nil {
		t.Fatal(err)
	}
	create := func(key, name string) ProjectResult {
		t.Helper()
		result, err := app.CreateProject(ctx, ProjectCreate{PrincipalID: actor.ID, IdempotencyKey: key, DisplayName: name})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	source := create("77777777-7777-4777-8777-777777777771", "local source")
	canonical := create("77777777-7777-4777-8777-777777777772", "remote canonical")
	competitor := create("77777777-7777-4777-8777-777777777773", "concurrent competitor")
	grantFixture := func(principalID, projectID string, capability Capability) {
		t.Helper()
		if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants (principal_id, scope, project_id, capability) VALUES ($1, 'project', $2, $3)`, principalID, projectID, capability); err != nil {
			t.Fatal(err)
		}
	}
	for _, projectID := range []string{source.ProjectID, canonical.ProjectID, competitor.ProjectID} {
		for _, capability := range []Capability{CapabilityProjectAttachUnclaimed, CapabilityProjectAdminister} {
			grantFixture(actor.ID, projectID, capability)
		}
	}
	grantFixture(sourceOnly.ID, source.ProjectID, CapabilityProjectRead)
	grantFixture(canonicalOnly.ID, source.ProjectID, CapabilityProjectRead)
	grantFixture(canonicalOnly.ID, canonical.ProjectID, CapabilityProjectRead)
	grantFixture(canonicalOnly.ID, canonical.ProjectID, CapabilityProjectWrite)

	local, err := app.AttachProjectIdentity(ctx, ProjectIdentityAttachRequest{
		ActorPrincipalID: actor.ID,
		ProjectID:        source.ProjectID,
		IdempotencyKey:   "88888888-8888-4888-8888-888888888881",
		Kind:             ProjectIdentityLocalGit,
		Locator:          "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
	})
	if err != nil || local.ProjectID != source.ProjectID || local.NormalizedLocator != "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" {
		t.Fatalf("local attachment=%#v err=%v", local, err)
	}
	localRetry, err := app.AttachProjectIdentity(ctx, ProjectIdentityAttachRequest{ActorPrincipalID: actor.ID, ProjectID: source.ProjectID, IdempotencyKey: "88888888-8888-4888-8888-888888888881", Kind: ProjectIdentityLocalGit, Locator: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"})
	if err != nil || localRetry != local {
		t.Fatalf("local attachment retry=%#v err=%v, want %#v", localRetry, err, local)
	}
	if _, err := app.AttachProjectIdentity(ctx, ProjectIdentityAttachRequest{ActorPrincipalID: actor.ID, ProjectID: source.ProjectID, IdempotencyKey: "88888888-8888-4888-8888-888888888881", Kind: ProjectIdentityOperatorAlias, Locator: "changed retry"}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed attachment retry error=%v", err)
	}
	if _, err := app.AttachProjectIdentity(ctx, ProjectIdentityAttachRequest{ActorPrincipalID: outsider.ID, ProjectID: source.ProjectID, IdempotencyKey: "88888888-8888-4888-8888-888888888882", Kind: ProjectIdentityOperatorAlias, Locator: "forbidden alias"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unauthorized attach error=%v", err)
	}
	if allowed, err := app.HasCapability(ctx, actor.ID, source.ProjectID, CapabilityMemoryRead); err != nil || allowed {
		t.Fatalf("identity attachment changed authority allowed=%t err=%v", allowed, err)
	}

	concurrent := []ProjectIdentityAttachRequest{
		{ActorPrincipalID: actor.ID, ProjectID: source.ProjectID, IdempotencyKey: "88888888-8888-4888-8888-888888888883", Kind: ProjectIdentityGitRemote, Locator: "git@claims.example:Team/Concurrent.git"},
		{ActorPrincipalID: actor.ID, ProjectID: competitor.ProjectID, IdempotencyKey: "88888888-8888-4888-8888-888888888884", Kind: ProjectIdentityGitRemote, Locator: "https://claims.example/Team/Concurrent.git"},
	}
	var wg sync.WaitGroup
	claimErrors := make(chan error, len(concurrent))
	for _, request := range concurrent {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, attachErr := app.AttachProjectIdentity(ctx, request)
			claimErrors <- attachErr
		}()
	}
	wg.Wait()
	close(claimErrors)
	var claimed, rejected int
	for claimErr := range claimErrors {
		switch {
		case claimErr == nil:
			claimed++
		case errors.Is(claimErr, ErrProjectIdentityClaimed):
			rejected++
		default:
			t.Fatalf("concurrent claim error=%v", claimErr)
		}
	}
	if claimed != 1 || rejected != 1 {
		t.Fatalf("concurrent claims accepted=%d rejected=%d", claimed, rejected)
	}

	remote, err := app.AttachProjectIdentity(ctx, ProjectIdentityAttachRequest{
		ActorPrincipalID: actor.ID,
		ProjectID:        canonical.ProjectID,
		IdempotencyKey:   "88888888-8888-4888-8888-888888888885",
		Kind:             ProjectIdentityGitRemote,
		Locator:          "https://user:secret@GitHub.com/Owner/Canonical.git", // #nosec G101 -- deliberate fake normalization fixture.
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.AttachProjectIdentity(ctx, ProjectIdentityAttachRequest{ActorPrincipalID: actor.ID, ProjectID: source.ProjectID, IdempotencyKey: "88888888-8888-4888-8888-888888888886", Kind: ProjectIdentityGitRemote, Locator: "git@github.com:Owner/Canonical.git"}); !errors.Is(err, ErrProjectIdentityClaimed) {
		t.Fatalf("claimed attach error=%v", err)
	}
	resolved, err := app.ResolveProjectIdentity(ctx, actor.ID, ProjectIdentityGitRemote, "ssh://git@GITHUB.COM:22/Owner/Canonical.git")
	if err != nil || resolved.ProjectID != canonical.ProjectID || resolved.IdentityID != remote.IdentityID {
		t.Fatalf("resolved=%#v err=%v", resolved, err)
	}
	if _, err := app.ResolveProjectIdentity(ctx, outsider.ID, ProjectIdentityGitRemote, "git@github.com:Owner/Canonical.git"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unauthorized resolution leaked identity: %v", err)
	}

	reciprocalA := create("77777777-7777-4777-8777-777777777769", "reciprocal merge A")
	reciprocalB := create("77777777-7777-4777-8777-777777777770", "reciprocal merge B")
	for _, projectID := range []string{reciprocalA.ProjectID, reciprocalB.ProjectID} {
		grantFixture(actor.ID, projectID, CapabilityProjectAttachUnclaimed)
	}
	if _, err := app.AttachProjectIdentity(ctx, ProjectIdentityAttachRequest{ActorPrincipalID: actor.ID, ProjectID: reciprocalA.ProjectID, IdempotencyKey: "88888888-8888-4888-8888-888888888878", Kind: ProjectIdentityGitRemote, Locator: "https://reciprocal.example/Owner/A.git"}); err != nil {
		t.Fatal(err)
	}
	if _, err := app.AttachProjectIdentity(ctx, ProjectIdentityAttachRequest{ActorPrincipalID: actor.ID, ProjectID: reciprocalB.ProjectID, IdempotencyKey: "88888888-8888-4888-8888-888888888879", Kind: ProjectIdentityGitRemote, Locator: "https://reciprocal.example/Owner/B.git"}); err != nil {
		t.Fatal(err)
	}
	reciprocalPreviewA, err := app.PreviewProjectIdentityMerge(ctx, ProjectMergePreviewRequest{ActorPrincipalID: actor.ID, SourceProjectID: reciprocalA.ProjectID, IdempotencyKey: "99999999-9999-4999-8999-999999999977", Kind: ProjectIdentityGitRemote, Locator: "https://reciprocal.example/Owner/B.git"})
	if err != nil {
		t.Fatal(err)
	}
	reciprocalPreviewB, err := app.PreviewProjectIdentityMerge(ctx, ProjectMergePreviewRequest{ActorPrincipalID: actor.ID, SourceProjectID: reciprocalB.ProjectID, IdempotencyKey: "99999999-9999-4999-8999-999999999978", Kind: ProjectIdentityGitRemote, Locator: "https://reciprocal.example/Owner/A.git"})
	if err != nil {
		t.Fatal(err)
	}
	reciprocalErrors := make(chan error, 2)
	for _, previewID := range []string{reciprocalPreviewA.PreviewID, reciprocalPreviewB.PreviewID} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, approveErr := app.ApproveProjectIdentityMerge(ctx, ProjectMergeApproval{ActorPrincipalID: actor.ID, PreviewID: previewID})
			reciprocalErrors <- approveErr
		}()
	}
	wg.Wait()
	close(reciprocalErrors)
	var reciprocalMerged, reciprocalRefused int
	for approveErr := range reciprocalErrors {
		switch {
		case approveErr == nil:
			reciprocalMerged++
		case errors.Is(approveErr, ErrStaleProjectMerge), errors.Is(approveErr, ErrMergedProject):
			reciprocalRefused++
		default:
			t.Fatalf("reciprocal merge error=%v", approveErr)
		}
	}
	if reciprocalMerged != 1 || reciprocalRefused != 1 {
		t.Fatalf("reciprocal merges accepted=%d refused=%d", reciprocalMerged, reciprocalRefused)
	}

	previewRequest := ProjectMergePreviewRequest{
		ActorPrincipalID: actor.ID,
		SourceProjectID:  source.ProjectID,
		IdempotencyKey:   "99999999-9999-4999-8999-999999999991",
		Kind:             ProjectIdentityGitRemote,
		Locator:          "git@github.com:Owner/Canonical.git",
	}
	oneSidedAdmin, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "one sided administrator")
	if err != nil {
		t.Fatal(err)
	}
	grantFixture(oneSidedAdmin.ID, source.ProjectID, CapabilityProjectAdminister)
	deniedRequest := previewRequest
	deniedRequest.ActorPrincipalID = oneSidedAdmin.ID
	deniedRequest.IdempotencyKey = "99999999-9999-4999-8999-999999999990"
	if _, err := app.PreviewProjectIdentityMerge(ctx, deniedRequest); !errors.Is(err, ErrForbidden) {
		t.Fatalf("one-sided administrator preview error=%v", err)
	}
	preview, err := app.PreviewProjectIdentityMerge(ctx, previewRequest)
	if err != nil {
		t.Fatal(err)
	}
	if preview.SourceProjectID != source.ProjectID || preview.CanonicalProjectID != canonical.ProjectID || preview.IdentityCount < 1 || preview.PrivateRecordCount != 0 || preview.ConflictCount != 0 || len(preview.NewlyAuthorizedPrincipalIDs) != 1 || preview.NewlyAuthorizedPrincipalIDs[0] != canonicalOnly.ID {
		t.Fatalf("unexpected preview: %#v", preview)
	}
	previewRetry, err := app.PreviewProjectIdentityMerge(ctx, previewRequest)
	if err != nil || previewRetry.PreviewID != preview.PreviewID {
		t.Fatalf("preview retry=%#v err=%v, want %#v", previewRetry, err, preview)
	}
	changedPreviewRequest := previewRequest
	changedPreviewRequest.Locator = "https://claims.example/Team/Concurrent.git"
	if _, err := app.PreviewProjectIdentityMerge(ctx, changedPreviewRequest); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed preview retry error=%v", err)
	}
	if _, err := app.advanceProjectContentGeneration(ctx, actor.ID, source.ProjectID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.ApproveProjectIdentityMerge(ctx, ProjectMergeApproval{ActorPrincipalID: actor.ID, PreviewID: preview.PreviewID}); !errors.Is(err, ErrStaleProjectMerge) {
		t.Fatalf("content-stale approval error=%v", err)
	}

	previewRequest.IdempotencyKey = "99999999-9999-4999-8999-999999999992"
	preview, err = app.PreviewProjectIdentityMerge(ctx, previewRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.GrantCapability(ctx, actor.ID, Grant{PrincipalID: outsider.ID, Scope: ScopeProject, ProjectID: source.ProjectID, Capability: CapabilityProjectRead}); err != nil {
		t.Fatal(err)
	}
	if _, err := app.ApproveProjectIdentityMerge(ctx, ProjectMergeApproval{ActorPrincipalID: actor.ID, PreviewID: preview.PreviewID}); !errors.Is(err, ErrStaleProjectMerge) {
		t.Fatalf("ACL-stale approval error=%v", err)
	}

	previewRequest.IdempotencyKey = "99999999-9999-4999-8999-999999999993"
	preview, err = app.PreviewProjectIdentityMerge(ctx, previewRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.AttachProjectIdentity(ctx, ProjectIdentityAttachRequest{ActorPrincipalID: actor.ID, ProjectID: source.ProjectID, IdempotencyKey: "88888888-8888-4888-8888-888888888887", Kind: ProjectIdentityOperatorAlias, Locator: "generation change"}); err != nil {
		t.Fatal(err)
	}
	if _, err := app.ApproveProjectIdentityMerge(ctx, ProjectMergeApproval{ActorPrincipalID: actor.ID, PreviewID: preview.PreviewID}); !errors.Is(err, ErrStaleProjectMerge) {
		t.Fatalf("identity-stale approval error=%v", err)
	}

	previewRequest.IdempotencyKey = "99999999-9999-4999-8999-999999999994"
	preview, err = app.PreviewProjectIdentityMerge(ctx, previewRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.GrantCapability(ctx, actor.ID, Grant{PrincipalID: outsider.ID, Scope: ScopeAllProjects, Capability: CapabilityProjectDiscover}); err != nil {
		t.Fatal(err)
	}
	if _, err := app.ApproveProjectIdentityMerge(ctx, ProjectMergeApproval{ActorPrincipalID: actor.ID, PreviewID: preview.PreviewID}); !errors.Is(err, ErrStaleProjectMerge) {
		t.Fatalf("global-ACL-stale approval error=%v", err)
	}

	previewRequest.IdempotencyKey = "99999999-9999-4999-8999-999999999996"
	preview, err = app.PreviewProjectIdentityMerge(ctx, previewRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE relay.project_merge_previews SET created_at = statement_timestamp() - interval '2 hours', expires_at = statement_timestamp() - interval '1 hour' WHERE id = $1`, preview.PreviewID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.ApproveProjectIdentityMerge(ctx, ProjectMergeApproval{ActorPrincipalID: actor.ID, PreviewID: preview.PreviewID}); !errors.Is(err, ErrStaleProjectMerge) {
		t.Fatalf("expired approval error=%v", err)
	}

	var liveActorPreviews int
	if err := ownerDB.QueryRowContext(ctx, `SELECT count(*) FROM relay.project_merge_previews WHERE actor_principal_id = $1 AND consumed_at IS NULL AND expires_at > statement_timestamp()`, actor.ID).Scan(&liveActorPreviews); err != nil {
		t.Fatal(err)
	}
	if liveActorPreviews < maxLiveProjectPreviewsActor {
		if _, err := ownerDB.ExecContext(ctx, `INSERT INTO relay.project_merge_previews (
    actor_principal_id, source_project_id, canonical_project_id, identity_id,
    source_identity_generation, source_acl_generation, source_content_generation,
    canonical_identity_generation, canonical_acl_generation, canonical_content_generation,
    global_acl_generation, identity_count, grant_count, alias_count,
    newly_authorized_principal_ids, private_record_count, conflict_count, expires_at, created_at
) SELECT actor_principal_id, source_project_id, canonical_project_id, identity_id,
    source_identity_generation, source_acl_generation, source_content_generation,
    canonical_identity_generation, canonical_acl_generation, canonical_content_generation,
    global_acl_generation, identity_count, grant_count, alias_count,
    newly_authorized_principal_ids, private_record_count, conflict_count,
    statement_timestamp() + interval '10 minutes', statement_timestamp()
FROM relay.project_merge_previews CROSS JOIN generate_series(1, $2)
WHERE id = $1`, preview.PreviewID, maxLiveProjectPreviewsActor-liveActorPreviews); err != nil {
			t.Fatal(err)
		}
	}
	capacityRequest := previewRequest
	capacityRequest.IdempotencyKey = "99999999-9999-4999-8999-999999999997"
	if _, err := app.PreviewProjectIdentityMerge(ctx, capacityRequest); !errors.Is(err, ErrProjectPreviewCapacity) {
		t.Fatalf("per-actor preview capacity error=%v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `DELETE FROM relay.project_merge_previews WHERE actor_principal_id = $1 AND consumed_at IS NULL`, actor.ID); err != nil {
		t.Fatal(err)
	}

	previewRequest.IdempotencyKey = "99999999-9999-4999-8999-999999999995"
	preview, err = app.PreviewProjectIdentityMerge(ctx, previewRequest)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := app.ApproveProjectIdentityMerge(ctx, ProjectMergeApproval{ActorPrincipalID: actor.ID, PreviewID: preview.PreviewID})
	if err != nil || merged.AliasProjectID != source.ProjectID || merged.CanonicalProjectID != canonical.ProjectID {
		t.Fatalf("merge=%#v err=%v", merged, err)
	}
	retry, err := app.ApproveProjectIdentityMerge(ctx, ProjectMergeApproval{ActorPrincipalID: actor.ID, PreviewID: preview.PreviewID})
	if err != nil || retry != merged {
		t.Fatalf("merge retry=%#v err=%v, want %#v", retry, err, merged)
	}
	if _, err := app.ApproveProjectIdentityMerge(ctx, ProjectMergeApproval{ActorPrincipalID: outsider.ID, PreviewID: preview.PreviewID}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("cross-actor preview replay error=%v", err)
	}
	if _, err := app.AttachProjectIdentity(ctx, ProjectIdentityAttachRequest{ActorPrincipalID: actor.ID, ProjectID: source.ProjectID, IdempotencyKey: "88888888-8888-4888-8888-888888888888", Kind: ProjectIdentityOperatorAlias, Locator: "stale source"}); !errors.Is(err, ErrMergedProject) {
		t.Fatalf("source mutation error=%v", err)
	}
	if allowed, err := app.HasCapability(ctx, sourceOnly.ID, source.ProjectID, CapabilityProjectRead); err != nil || allowed {
		t.Fatalf("source membership unioned allowed=%t err=%v", allowed, err)
	}
	if allowed, err := app.HasCapability(ctx, canonicalOnly.ID, source.ProjectID, CapabilityProjectRead); err != nil || !allowed {
		t.Fatalf("canonical member could not use permanent alias allowed=%t err=%v", allowed, err)
	}
	var identityProject string
	if err := ownerDB.QueryRowContext(ctx, `SELECT project_id::text FROM relay.project_identities WHERE id = $1`, local.IdentityID).Scan(&identityProject); err != nil || identityProject != canonical.ProjectID {
		t.Fatalf("moved identity project=%q err=%v", identityProject, err)
	}
	var activeSourceGrants int
	if err := ownerDB.QueryRowContext(ctx, `SELECT count(*) FROM auth.capability_grants WHERE project_id = $1 AND revoked_at IS NULL`, source.ProjectID).Scan(&activeSourceGrants); err != nil || activeSourceGrants != 0 {
		t.Fatalf("active source grants=%d err=%v", activeSourceGrants, err)
	}

	destination := create("77777777-7777-4777-8777-777777777774", "second canonical")
	grantFixture(actor.ID, destination.ProjectID, CapabilityProjectAttachUnclaimed)
	destinationOnly, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "second canonical member")
	if err != nil {
		t.Fatal(err)
	}
	grantFixture(destinationOnly.ID, destination.ProjectID, CapabilityProjectRead)
	if _, err := app.AttachProjectIdentity(ctx, ProjectIdentityAttachRequest{ActorPrincipalID: actor.ID, ProjectID: destination.ProjectID, IdempotencyKey: "88888888-8888-4888-8888-888888888889", Kind: ProjectIdentityGitRemote, Locator: "https://example.com/Owner/Second.git"}); err != nil {
		t.Fatal(err)
	}
	secondPreview, err := app.PreviewProjectIdentityMerge(ctx, ProjectMergePreviewRequest{ActorPrincipalID: actor.ID, SourceProjectID: canonical.ProjectID, IdempotencyKey: "99999999-9999-4999-8999-999999999998", Kind: ProjectIdentityGitRemote, Locator: "git@example.com:Owner/Second.git"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.ApproveProjectIdentityMerge(ctx, ProjectMergeApproval{ActorPrincipalID: actor.ID, PreviewID: secondPreview.PreviewID}); err != nil {
		t.Fatal(err)
	}
	if allowed, err := app.HasCapability(ctx, destinationOnly.ID, source.ProjectID, CapabilityProjectRead); err != nil || !allowed {
		t.Fatalf("oldest permanent alias after chained merge allowed=%t err=%v", allowed, err)
	}
	if err := ownerDB.QueryRowContext(ctx, `SELECT project_id::text FROM relay.project_identities WHERE id = $1`, local.IdentityID).Scan(&identityProject); err != nil || identityProject != destination.ProjectID {
		t.Fatalf("twice-moved identity project=%q err=%v", identityProject, err)
	}
	globalCapacityActor, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "global preview capacity actor")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants (principal_id, scope, capability) VALUES ($1, 'all_projects', 'project.administer')`, globalCapacityActor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO relay.project_merge_previews (
    actor_principal_id, source_project_id, canonical_project_id, identity_id,
    source_identity_generation, source_acl_generation, source_content_generation,
    canonical_identity_generation, canonical_acl_generation, canonical_content_generation,
    global_acl_generation, identity_count, grant_count, alias_count,
    newly_authorized_principal_ids, private_record_count, conflict_count, expires_at, created_at
) SELECT $2, source_project_id, canonical_project_id, identity_id,
    source_identity_generation, source_acl_generation, source_content_generation,
    canonical_identity_generation, canonical_acl_generation, canonical_content_generation,
    global_acl_generation, identity_count, grant_count, alias_count,
    newly_authorized_principal_ids, private_record_count, conflict_count,
    statement_timestamp() + interval '10 minutes', statement_timestamp()
FROM relay.project_merge_previews CROSS JOIN generate_series(1, $3)
WHERE id = $1`, secondPreview.PreviewID, actor.ID, maxLiveProjectPreviews); err != nil {
		t.Fatal(err)
	}
	if _, err := app.PreviewProjectIdentityMerge(ctx, ProjectMergePreviewRequest{ActorPrincipalID: globalCapacityActor.ID, SourceProjectID: competitor.ProjectID, IdempotencyKey: "99999999-9999-4999-8999-999999999980", Kind: ProjectIdentityGitRemote, Locator: "https://example.com/Owner/Second.git"}); !errors.Is(err, ErrProjectPreviewCapacity) {
		t.Fatalf("global preview capacity error=%v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `DELETE FROM relay.project_merge_previews WHERE consumed_at IS NULL`); err != nil {
		t.Fatal(err)
	}
	if _, err := app.AttachProjectIdentity(ctx, ProjectIdentityAttachRequest{ActorPrincipalID: actor.ID, ProjectID: competitor.ProjectID, IdempotencyKey: "88888888-8888-4888-8888-888888888880", Kind: ProjectIdentityOperatorAlias, Locator: "preview pruning source"}); err != nil {
		t.Fatal(err)
	}
	var oldPreviewID string
	if err := ownerDB.QueryRowContext(ctx, `INSERT INTO relay.project_merge_previews (
    actor_principal_id, source_project_id, canonical_project_id, identity_id,
    source_identity_generation, source_acl_generation, source_content_generation,
    canonical_identity_generation, canonical_acl_generation, canonical_content_generation,
    global_acl_generation, identity_count, grant_count, alias_count,
    newly_authorized_principal_ids, private_record_count, conflict_count, expires_at, created_at
) SELECT $2, source_project_id, canonical_project_id, identity_id,
    source_identity_generation, source_acl_generation, source_content_generation,
    canonical_identity_generation, canonical_acl_generation, canonical_content_generation,
    global_acl_generation, identity_count, grant_count, alias_count,
    newly_authorized_principal_ids, private_record_count, conflict_count,
    statement_timestamp() - interval '3 days', statement_timestamp() - interval '4 days'
FROM relay.project_merge_previews WHERE id = $1 RETURNING id::text`, secondPreview.PreviewID, actor.ID).Scan(&oldPreviewID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.PreviewProjectIdentityMerge(ctx, ProjectMergePreviewRequest{ActorPrincipalID: globalCapacityActor.ID, SourceProjectID: competitor.ProjectID, IdempotencyKey: "99999999-9999-4999-8999-999999999979", Kind: ProjectIdentityGitRemote, Locator: "https://example.com/Owner/Second.git"}); err != nil {
		t.Fatal(err)
	}
	var oldPreviewExists bool
	if err := ownerDB.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM relay.project_merge_previews WHERE id = $1)`, oldPreviewID).Scan(&oldPreviewExists); err != nil || oldPreviewExists {
		t.Fatalf("retained expired preview exists=%t err=%v", oldPreviewExists, err)
	}
	if _, err := ownerDB.ExecContext(ctx, `DELETE FROM relay.project_merge_previews WHERE consumed_at IS NULL`); err != nil {
		t.Fatal(err)
	}

	identityBoundSource := create("77777777-7777-4777-8777-777777777775", "identity bound source")
	identityBoundCanonical := create("77777777-7777-4777-8777-777777777776", "identity bound canonical")
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO relay.project_identities (project_id, kind, normalized_locator, created_by)
VALUES ($1, 'local_git', 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', $3),
       ($2, 'git_remote', 'bounds.example/Owner/Canonical', $3)`, identityBoundSource.ProjectID, identityBoundCanonical.ProjectID, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO relay.project_identities (project_id, kind, normalized_locator, created_by)
SELECT $1, 'operator_alias', 'identity-bound-' || value::text, $2 FROM generate_series(1, 99) AS value`, identityBoundCanonical.ProjectID, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.PreviewProjectIdentityMerge(ctx, ProjectMergePreviewRequest{ActorPrincipalID: actor.ID, SourceProjectID: identityBoundSource.ProjectID, IdempotencyKey: "99999999-9999-4999-8999-999999999981", Kind: ProjectIdentityGitRemote, Locator: "https://bounds.example/Owner/Canonical.git"}); !errors.Is(err, ErrProjectMergeTooLarge) {
		t.Fatalf("combined identity bound error=%v", err)
	}

	aliasBoundSource := create("77777777-7777-4777-8777-777777777779", "alias bound source")
	aliasBoundCanonical := create("77777777-7777-4777-8777-777777777778", "alias bound canonical")
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO relay.project_identities (project_id, kind, normalized_locator, created_by)
VALUES ($1, 'local_git', 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', $3),
       ($2, 'git_remote', 'alias-bounds.example/Owner/Canonical', $3)`, aliasBoundSource.ProjectID, aliasBoundCanonical.ProjectID, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `WITH inserted AS (
    INSERT INTO relay.projects (display_name, created_by)
    SELECT 'bounded historical alias ' || value::text, $2 FROM generate_series(1, 1000) AS value
    RETURNING id
), retired AS (
    UPDATE relay.projects SET merged_into = $1, merged_at = statement_timestamp()
    WHERE id IN (SELECT id FROM inserted) RETURNING id
) INSERT INTO relay.project_lookup_aliases (alias_project_id, canonical_project_id)
SELECT id, $1 FROM retired`, aliasBoundSource.ProjectID, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.PreviewProjectIdentityMerge(ctx, ProjectMergePreviewRequest{ActorPrincipalID: actor.ID, SourceProjectID: aliasBoundSource.ProjectID, IdempotencyKey: "99999999-9999-4999-8999-999999999982", Kind: ProjectIdentityGitRemote, Locator: "https://alias-bounds.example/Owner/Canonical.git"}); !errors.Is(err, ErrProjectMergeTooLarge) {
		t.Fatalf("alias rewrite bound error=%v", err)
	}
}
