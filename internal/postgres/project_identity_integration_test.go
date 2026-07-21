package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"sync"
	"testing"
	"time"
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
	contentOnlyMembers := make([]struct {
		principalID string
		capability  Capability
	}, 0, 5)
	for _, capability := range []Capability{
		CapabilityConversationSend,
		CapabilityMemorySearch,
		CapabilityMemoryPropose,
		CapabilityMemoryWrite,
		CapabilityAttachmentUpload,
	} {
		principal, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "canonical "+string(capability)+" member")
		if err != nil {
			t.Fatal(err)
		}
		contentOnlyMembers = append(contentOnlyMembers, struct {
			principalID string
			capability  Capability
		}{principalID: principal.ID, capability: capability})
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
	for _, member := range contentOnlyMembers {
		grantFixture(member.principalID, canonical.ProjectID, member.capability)
	}

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
	grantFixture(actor.ID, source.ProjectID, CapabilityAttachmentUpload)
	attachmentDigest := sha256.Sum256([]byte("merge fence"))
	mergeFence, err := app.ReserveAttachment(ctx, AttachmentReservationRequest{PrincipalID: actor.ID, ProjectID: source.ProjectID, IdempotencyKey: "99999999-9999-4999-8999-999999999989", SizeBytes: 11, SHA256: attachmentDigest, DisplayName: "merge-fence.txt", MediaType: "text/plain", Lifetime: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.PreviewProjectIdentityMerge(ctx, previewRequest); !errors.Is(err, ErrProjectMergeAttachmentState) {
		t.Fatalf("attachment-bearing project merge preview error=%v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE attachment.uploads SET created_at=statement_timestamp()-interval '2 seconds',expires_at=statement_timestamp()-interval '1 second' WHERE artifact_id=$1`, mergeFence.ArtifactID); err != nil {
		t.Fatal(err)
	}
	reapTestAttachment(ctx, t, app, mergeFence.ArtifactID)
	recipientFenceConversation := "99999999-9999-4999-8999-999999999988"
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO relay.mail_conversations(id) VALUES ($1); INSERT INTO attachment.conversation_projects(conversation_id,project_id,bound_by) VALUES ($1,$2,$3)`, recipientFenceConversation, source.ProjectID, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.PreviewProjectIdentityMerge(ctx, previewRequest); !errors.Is(err, ErrProjectMergeAttachmentState) {
		t.Fatalf("recipient-bound project merge preview error=%v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `DELETE FROM attachment.conversation_projects WHERE conversation_id=$1; DELETE FROM relay.mail_conversations WHERE id=$1`, recipientFenceConversation); err != nil {
		t.Fatal(err)
	}
	preview, err := app.PreviewProjectIdentityMerge(ctx, previewRequest)
	if err != nil {
		t.Fatal(err)
	}
	expectedNewlyAuthorized := []string{canonicalOnly.ID}
	for _, member := range contentOnlyMembers {
		expectedNewlyAuthorized = append(expectedNewlyAuthorized, member.principalID)
	}
	sort.Strings(expectedNewlyAuthorized)
	if preview.SourceProjectID != source.ProjectID || preview.CanonicalProjectID != canonical.ProjectID || preview.IdentityCount < 1 || preview.PrivateRecordCount != 1 || preview.PendingEnrollmentCount != 0 || preview.ConflictCount != 0 || !slices.Equal(preview.NewlyAuthorizedPrincipalIDs, expectedNewlyAuthorized) {
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
	canonicalWorker, err := app.CreatePrincipal(ctx, PrincipalKindService, "canonical project worker")
	if err != nil {
		t.Fatal(err)
	}
	grantFixture(canonicalWorker.ID, source.ProjectID, CapabilityProjectAdminister)
	grantFixture(canonicalWorker.ID, canonical.ProjectID, CapabilityProjectAdminister)
	preMergeLeases, err := app.ClaimJobs(ctx, ClaimJobs{Kind: "project.created", Holder: canonicalWorker.ID, Limit: 10, LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	var leasedSourceJob bool
	for _, lease := range preMergeLeases {
		leasedSourceJob = leasedSourceJob || lease.ProjectID == source.ProjectID
		if lease.ProjectID == source.ProjectID {
			if _, err := ownerDB.ExecContext(ctx, `UPDATE jobs.outbox SET attempts = max_attempts WHERE id = $1`, lease.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !leasedSourceJob {
		t.Fatal("source project job was not leased before merge")
	}
	var queuedSourceJobID string
	if err := ownerDB.QueryRowContext(ctx, `INSERT INTO jobs.outbox (project_id, kind, payload, max_attempts)
VALUES ($1::uuid, 'project.created', jsonb_build_object('project_id', ($1::uuid)::text), 4) RETURNING id::text`, source.ProjectID).Scan(&queuedSourceJobID); err != nil {
		t.Fatal(err)
	}
	var pendingSourceEnrollmentID string
	pendingClientBinding := "66666666-6666-4666-8666-666666666666"
	pendingCodeBytes := []byte("merge-invalidated-enrollment-code")
	pendingCode := base64.RawURLEncoding.EncodeToString(pendingCodeBytes)
	pendingCodeDigest := sha256.Sum256(pendingCodeBytes)
	if err := ownerDB.QueryRowContext(ctx, `INSERT INTO auth.pending_enrollments
    (issuer_principal_id, client_binding, label, code_digest, preview_hash, expires_at)
VALUES ($1, $2, 'source enrollment', $3, decode(repeat('22', 32), 'hex'), statement_timestamp() + interval '10 minutes')
RETURNING id::text`, actor.ID, pendingClientBinding, pendingCodeDigest[:]).Scan(&pendingSourceEnrollmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.pending_enrollment_grants
    (enrollment_id, ordinal, scope, project_id, capability)
VALUES ($1, 0, 'project', $2, 'memory.read'),
	   ($1, 1, 'project', $3, 'attachment.download')`, pendingSourceEnrollmentID, source.ProjectID, canonical.ProjectID); err != nil {
		t.Fatal(err)
	}
	var disclosedGrantCount, disclosedPendingEnrollmentCount int
	if err := ownerDB.QueryRowContext(ctx, `WITH affected_enrollments AS MATERIALIZED (
    SELECT enrollment.id FROM auth.pending_enrollments AS enrollment
    WHERE enrollment.redeemed_at IS NULL AND enrollment.invalidated_at IS NULL
      AND enrollment.expires_at > statement_timestamp()
      AND EXISTS (
          SELECT 1 FROM auth.pending_enrollment_grants AS source_grant
          WHERE source_grant.enrollment_id = enrollment.id
            AND source_grant.scope = 'project' AND source_grant.project_id = $1
      )
)
SELECT
    (SELECT count(*) FROM auth.capability_grants WHERE project_id = $1 AND revoked_at IS NULL)
	+ (SELECT count(*) FROM auth.pending_enrollment_grants
	   WHERE enrollment_id IN (SELECT id FROM affected_enrollments)),
	(SELECT count(*) FROM affected_enrollments)`, source.ProjectID).Scan(&disclosedGrantCount, &disclosedPendingEnrollmentCount); err != nil {
		t.Fatal(err)
	}
	var disclosedPrivateRecordCount int
	if err := ownerDB.QueryRowContext(ctx, `SELECT count(*) FROM jobs.outbox WHERE project_id = $1 AND state IN ('queued', 'running')`, source.ProjectID).Scan(&disclosedPrivateRecordCount); err != nil {
		t.Fatal(err)
	}

	previewRequest.IdempotencyKey = "99999999-9999-4999-8999-999999999995"
	preview, err = app.PreviewProjectIdentityMerge(ctx, previewRequest)
	if err != nil {
		t.Fatal(err)
	}
	if preview.GrantCount != disclosedGrantCount || preview.PendingEnrollmentCount != disclosedPendingEnrollmentCount || preview.PrivateRecordCount != disclosedPrivateRecordCount {
		t.Fatalf("preview impact=%#v, want grants=%d pending enrollments=%d private records=%d", preview, disclosedGrantCount, disclosedPendingEnrollmentCount, disclosedPrivateRecordCount)
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
	for _, lease := range preMergeLeases {
		err := app.CompleteJob(ctx, JobLease{ID: lease.ID, Token: lease.Token, Generation: lease.Generation})
		if lease.ProjectID == source.ProjectID && !errors.Is(err, ErrStaleLease) {
			t.Fatalf("source lease completion error=%v, want stale fence", err)
		}
		if lease.ProjectID == canonical.ProjectID && err != nil {
			t.Fatalf("unrelated canonical lease completion error=%v", err)
		}
	}
	postMergeLeases, err := app.ClaimJobs(ctx, ClaimJobs{Kind: "project.created", Holder: canonicalWorker.ID, Limit: 10, LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	var claimedQueuedSourceJob, reclaimedSourceLease bool
	for _, lease := range postMergeLeases {
		claimedQueuedSourceJob = claimedQueuedSourceJob || lease.ID == queuedSourceJobID
		for _, oldLease := range preMergeLeases {
			reclaimedSourceLease = reclaimedSourceLease || (oldLease.ProjectID == source.ProjectID && oldLease.ID == lease.ID)
		}
		var payload struct {
			ProjectID string `json:"project_id"`
		}
		if lease.ProjectID != canonical.ProjectID || json.Unmarshal(lease.Payload, &payload) != nil || payload.ProjectID != canonical.ProjectID {
			t.Fatalf("reclaimed job envelope=%#v payload=%s", lease, lease.Payload)
		}
		if err := app.CompleteJob(ctx, JobLease{ID: lease.ID, Token: lease.Token, Generation: lease.Generation}); err != nil {
			t.Fatal(err)
		}
	}
	if !claimedQueuedSourceJob || !reclaimedSourceLease {
		t.Fatalf("queued source claimed=%t running source reclaimed=%t", claimedQueuedSourceJob, reclaimedSourceLease)
	}
	var pendingEnrollmentInvalidated bool
	var pendingGrantProjects []byte
	if err := ownerDB.QueryRowContext(ctx, `SELECT enrollment.invalidated_at IS NOT NULL,
	jsonb_agg(pending_grant.project_id::text ORDER BY pending_grant.ordinal)
FROM auth.pending_enrollments AS enrollment
JOIN auth.pending_enrollment_grants AS pending_grant ON pending_grant.enrollment_id = enrollment.id
WHERE enrollment.id = $1 GROUP BY enrollment.invalidated_at`, pendingSourceEnrollmentID).Scan(&pendingEnrollmentInvalidated, &pendingGrantProjects); err != nil {
		t.Fatal(err)
	}
	var retainedGrantProjects []string
	if json.Unmarshal(pendingGrantProjects, &retainedGrantProjects) != nil || len(retainedGrantProjects) != 2 || retainedGrantProjects[0] != source.ProjectID || retainedGrantProjects[1] != canonical.ProjectID {
		t.Fatalf("retained pending grant projects=%s", pendingGrantProjects)
	}
	if !pendingEnrollmentInvalidated {
		t.Fatalf("source enrollment invalidated=%t grant projects=%s, want invalidated without retargeting", pendingEnrollmentInvalidated, pendingGrantProjects)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE auth.pending_enrollments SET invalidated_at = NULL WHERE id = $1`, pendingSourceEnrollmentID); err == nil {
		t.Fatal("enrollment invalidation marker was reversible")
	}
	if _, err := app.RedeemEnrollment(ctx, RedeemEnrollment{EnrollmentID: pendingSourceEnrollmentID, ClientBinding: pendingClientBinding, Code: pendingCode, IdempotencyKey: "66666666-6666-4666-8666-666666666667"}); !errors.Is(err, ErrInvalidEnrollment) {
		t.Fatalf("invalidated enrollment redemption error=%v", err)
	}
	reenrollmentBinding := "66666666-6666-4666-8666-666666666668"
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.pending_enrollments
	(issuer_principal_id, client_binding, label, code_digest, preview_hash, expires_at, invalidated_at)
SELECT $1,
	CASE WHEN value = 101 THEN $2::uuid ELSE gen_random_uuid() END,
	'invalidated enrollment ' || value::text,
	decode(repeat('33', 32), 'hex'), decode(repeat('44', 32), 'hex'),
	statement_timestamp() + interval '1 hour' + value * interval '1 second', statement_timestamp()
FROM generate_series(1, 101) AS value`, actor.ID, reenrollmentBinding); err != nil {
		t.Fatal(err)
	}
	var ownerPrincipalID string
	if err := ownerDB.QueryRowContext(ctx, `SELECT principal_id::text FROM auth.installation_owner WHERE singleton`).Scan(&ownerPrincipalID); err != nil {
		t.Fatal(err)
	}
	_, reenrollmentHash, err := PreviewTrustedAgentEnrollment(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&Administration{db: ownerDB}).CreateEnrollment(ctx, ownerPrincipalID, EnrollmentRequest{ClientBinding: reenrollmentBinding, Label: "replacement enrollment", AllProjects: true, TTL: time.Minute}, reenrollmentHash); err != nil {
		t.Fatalf("invalidated binding blocked replacement after bounded prune: %v", err)
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
    INSERT INTO relay.projects (display_name, created_by, merged_into, merged_at)
    SELECT 'bounded historical alias ' || value::text, $2, $1, statement_timestamp()
    FROM generate_series(1, 1000) AS value
    RETURNING id
) INSERT INTO relay.project_lookup_aliases (alias_project_id, canonical_project_id)
SELECT id, $1 FROM inserted`, aliasBoundSource.ProjectID, actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.PreviewProjectIdentityMerge(ctx, ProjectMergePreviewRequest{ActorPrincipalID: actor.ID, SourceProjectID: aliasBoundSource.ProjectID, IdempotencyKey: "99999999-9999-4999-8999-999999999982", Kind: ProjectIdentityGitRemote, Locator: "https://alias-bounds.example/Owner/Canonical.git"}); !errors.Is(err, ErrProjectMergeTooLarge) {
		t.Fatalf("alias rewrite bound error=%v", err)
	}
}
