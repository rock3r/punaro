package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"
)

func testTrustedAttachmentIntegration(ctx context.Context, t *testing.T, app *Database, ownerDB *sql.DB) {
	t.Helper()
	uploader, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "trusted attachment uploader")
	if err != nil {
		t.Fatal(err)
	}
	outsider, err := app.CreatePrincipal(ctx, PrincipalKindDevice, "trusted attachment outsider")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants(principal_id,scope,capability) VALUES ($1,'installation','project.create')`, uploader.ID); err != nil {
		t.Fatal(err)
	}
	project, err := app.CreateProject(ctx, ProjectCreate{PrincipalID: uploader.ID, IdempotencyKey: "a1000000-0000-4000-8000-000000000001", DisplayName: "trusted attachment project"})
	if err != nil {
		t.Fatal(err)
	}
	grantResult, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants(principal_id,scope,project_id,capability) VALUES ($1,'project',$2,'attachment.upload') RETURNING id`, uploader.ID, project.ProjectID)
	if err != nil {
		t.Fatal(err)
	}
	_ = grantResult

	body := []byte("trusted attachment integration body")
	digest := sha256.Sum256(body)
	request := AttachmentReservationRequest{PrincipalID: uploader.ID, ProjectID: project.ProjectID, IdempotencyKey: "a2000000-0000-4000-8000-000000000001", SizeBytes: int64(len(body)), SHA256: digest, DisplayName: "evidence.txt", MediaType: "text/plain", Lifetime: 10 * time.Minute}
	reservation, err := app.ReserveAttachment(ctx, request)
	if err != nil || reservation.State != AttachmentReserved || reservation.ProjectID != project.ProjectID || reservation.SHA256 != digest {
		t.Fatalf("reservation=%#v err=%v", reservation, err)
	}
	if retry, retryErr := app.ReserveAttachment(ctx, request); retryErr != nil || retry != reservation {
		t.Fatalf("reservation retry=%#v err=%v", retry, retryErr)
	}
	changed := request
	changed.DisplayName = "changed.txt"
	if _, err := app.ReserveAttachment(ctx, changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed reservation retry error=%v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE auth.capability_grants SET revoked_at=statement_timestamp() WHERE principal_id=$1 AND project_id=$2 AND capability='attachment.upload' AND revoked_at IS NULL`, uploader.ID, project.ProjectID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.ReserveAttachment(ctx, request); !errors.Is(err, ErrForbidden) {
		t.Fatalf("revoked exact reservation retry error=%v", err)
	}
	if _, err := app.ReserveAttachment(ctx, changed); !errors.Is(err, ErrForbidden) {
		t.Fatalf("revoked changed reservation retry error=%v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants(principal_id,scope,project_id,capability) VALUES ($1,'project',$2,'attachment.upload')`, uploader.ID, project.ProjectID); err != nil {
		t.Fatal(err)
	}
	denied := request
	denied.PrincipalID = outsider.ID
	denied.IdempotencyKey = "a2000000-0000-4000-8000-000000000002"
	if _, err := app.ReserveAttachment(ctx, denied); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unauthorized reservation error=%v", err)
	}

	claim, err := app.ClaimAttachmentUpload(ctx, uploader.ID, reservation.ArtifactID, time.Minute)
	if err != nil || claim.AttemptGeneration != 1 || claim.ClaimToken == "" {
		t.Fatalf("claim=%#v err=%v", claim, err)
	}
	publish := AttachmentPublishRequest{PrincipalID: uploader.ID, ArtifactID: reservation.ArtifactID, AttemptGeneration: claim.AttemptGeneration, ClaimToken: claim.ClaimToken, StoragePath: "ready/" + reservation.ArtifactID + ".blob", SizeBytes: reservation.SizeBytes, SHA256: reservation.SHA256}
	ready, err := app.PublishAttachment(ctx, publish)
	if err != nil || ready.State != AttachmentReady || ready.StoragePath != publish.StoragePath {
		t.Fatalf("ready=%#v err=%v", ready, err)
	}
	if retry, retryErr := app.PublishAttachment(ctx, publish); retryErr != nil || retry != ready {
		t.Fatalf("READY retry=%#v err=%v", retry, retryErr)
	}

	duplicate := request
	duplicate.IdempotencyKey = "a2000000-0000-4000-8000-000000000003"
	duplicate.DisplayName = "same-content.txt"
	duplicateReservation, err := app.ReserveAttachment(ctx, duplicate)
	if err != nil || duplicateReservation.ArtifactID == reservation.ArtifactID {
		t.Fatalf("duplicate reservation=%#v err=%v", duplicateReservation, err)
	}
	duplicateClaim, err := app.ClaimAttachmentUpload(ctx, uploader.ID, duplicateReservation.ArtifactID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	duplicateReady, err := app.PublishAttachment(ctx, AttachmentPublishRequest{PrincipalID: uploader.ID, ArtifactID: duplicateReservation.ArtifactID, AttemptGeneration: duplicateClaim.AttemptGeneration, ClaimToken: duplicateClaim.ClaimToken, StoragePath: "ready/" + duplicateReservation.ArtifactID + ".blob", SizeBytes: duplicateReservation.SizeBytes, SHA256: duplicateReservation.SHA256})
	if err != nil || duplicateReady.StoragePath == ready.StoragePath || duplicateReady.SHA256 != ready.SHA256 {
		t.Fatalf("duplicate READY=%#v err=%v", duplicateReady, err)
	}
	if marked, err := app.MarkAttachmentCorrupt(ctx, duplicateReservation.ArtifactID); err != nil || !marked {
		t.Fatalf("mark duplicate corrupt=%t err=%v", marked, err)
	}
	var corruptBackupRows int
	if err := ownerDB.QueryRowContext(ctx, `SELECT count(*) FROM attachment.ready_blob_manifest WHERE storage_path=$1`, duplicateReady.StoragePath).Scan(&corruptBackupRows); err != nil || corruptBackupRows != 0 {
		t.Fatalf("corrupt backup projection rows=%d err=%v", corruptBackupRows, err)
	}

	revoked := request
	revoked.IdempotencyKey = "a2000000-0000-4000-8000-000000000004"
	revoked.DisplayName = "revoked.txt"
	revokedReservation, err := app.ReserveAttachment(ctx, revoked)
	if err != nil {
		t.Fatal(err)
	}
	revokedClaim, err := app.ClaimAttachmentUpload(ctx, uploader.ID, revokedReservation.ArtifactID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE auth.capability_grants SET revoked_at=statement_timestamp() WHERE principal_id=$1 AND project_id=$2 AND capability='attachment.upload' AND revoked_at IS NULL`, uploader.ID, project.ProjectID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.PublishAttachment(ctx, AttachmentPublishRequest{PrincipalID: uploader.ID, ArtifactID: revokedReservation.ArtifactID, AttemptGeneration: revokedClaim.AttemptGeneration, ClaimToken: revokedClaim.ClaimToken, StoragePath: "ready/" + revokedReservation.ArtifactID + ".blob", SizeBytes: revokedReservation.SizeBytes, SHA256: revokedReservation.SHA256}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("revoked completion error=%v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants(principal_id,scope,project_id,capability) VALUES ($1,'project',$2,'attachment.upload')`, uploader.ID, project.ProjectID); err != nil {
		t.Fatal(err)
	}

	if _, err := app.db.ExecContext(ctx, `SELECT * FROM attachment.uploads`); err == nil {
		t.Fatal("application role read trusted attachment lifecycle directly")
	}
	if _, err := app.db.ExecContext(ctx, `UPDATE attachment.global_quota SET max_active_uploads=100000`); err == nil {
		t.Fatal("application role mutated trusted attachment quota directly")
	}

	if _, err := ownerDB.ExecContext(ctx, `UPDATE attachment.uploads SET created_at=statement_timestamp()-interval '2 seconds',expires_at=statement_timestamp()-interval '1 second',claim_token=NULL,claim_until=NULL WHERE artifact_id=$1`, revokedReservation.ArtifactID); err != nil {
		t.Fatal(err)
	}
	reapTestAttachment(ctx, t, app, revokedReservation.ArtifactID)
	lifetimeBound := request
	lifetimeBound.IdempotencyKey = "a2000000-0000-4000-8000-000000000007"
	lifetimeBound.DisplayName = "lifetime-bound.txt"
	lifetimeReservation, err := app.ReserveAttachment(ctx, lifetimeBound)
	if err != nil {
		t.Fatal(err)
	}
	changedLifetime := lifetimeBound
	changedLifetime.Lifetime += 100 * time.Millisecond
	if _, err := app.ReserveAttachment(ctx, changedLifetime); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed subsecond lifetime retry error=%v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE attachment.uploads SET created_at=statement_timestamp()-interval '2 seconds',expires_at=statement_timestamp()-interval '1 second' WHERE artifact_id=$1`, lifetimeReservation.ArtifactID); err != nil {
		t.Fatal(err)
	}
	reapTestAttachment(ctx, t, app, lifetimeReservation.ArtifactID)

	if _, err := ownerDB.ExecContext(ctx, `UPDATE attachment.global_quota SET max_active_uploads=1,default_project_uploads=1,default_principal_uploads=1`); err != nil {
		t.Fatal(err)
	}
	races := []AttachmentReservationRequest{request, request}
	races[0].IdempotencyKey, races[0].DisplayName = "a2000000-0000-4000-8000-000000000005", "race-a.txt"
	races[1].IdempotencyKey, races[1].DisplayName = "a2000000-0000-4000-8000-000000000006", "race-b.txt"
	var wait sync.WaitGroup
	errorsSeen := make(chan error, len(races))
	artifacts := make(chan string, len(races))
	for _, race := range races {
		wait.Add(1)
		go func(request AttachmentReservationRequest) {
			defer wait.Done()
			result, reserveErr := app.ReserveAttachment(ctx, request)
			if reserveErr == nil {
				artifacts <- result.ArtifactID
			}
			errorsSeen <- reserveErr
		}(race)
	}
	wait.Wait()
	close(errorsSeen)
	close(artifacts)
	var succeeded, quotaRejected int
	for reserveErr := range errorsSeen {
		switch {
		case reserveErr == nil:
			succeeded++
		case errors.Is(reserveErr, ErrAttachmentQuota):
			quotaRejected++
		default:
			t.Fatalf("quota race error=%v", reserveErr)
		}
	}
	if succeeded != 1 || quotaRejected != 1 {
		t.Fatalf("quota race succeeded=%d rejected=%d", succeeded, quotaRejected)
	}
	for artifactID := range artifacts {
		if _, err := ownerDB.ExecContext(ctx, `UPDATE attachment.uploads SET created_at=statement_timestamp()-interval '2 seconds',expires_at=statement_timestamp()-interval '1 second' WHERE artifact_id=$1`, artifactID); err != nil {
			t.Fatal(err)
		}
		reapTestAttachment(ctx, t, app, artifactID)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE attachment.global_quota SET max_active_uploads=1024,default_project_uploads=256,default_principal_uploads=64`); err != nil {
		t.Fatal(err)
	}

	candidates, _, err := app.AttachmentReconcileCandidates(ctx, AttachmentReconcileCursor{}, 100)
	if err != nil || len(candidates) < 2 {
		t.Fatalf("reconcile candidates=%d err=%v", len(candidates), err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants(principal_id,scope,project_id,capability) VALUES ($1,'project',$2,'project.administer')`, uploader.ID, project.ProjectID); err != nil {
		t.Fatal(err)
	}
	if hasRecords, err := app.ProjectHasAttachmentRecords(ctx, uploader.ID, project.ProjectID); err != nil || !hasRecords {
		t.Fatalf("project attachment records=%t err=%v", hasRecords, err)
	}
	if _, err := app.ProjectHasAttachmentRecords(ctx, outsider.ID, project.ProjectID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unauthorized project attachment-state query error=%v", err)
	}

	// Leave the shared integration database content-free for backup and merge tests.
	if _, err := ownerDB.ExecContext(ctx, `DELETE FROM attachment.ready_artifacts; DELETE FROM attachment.ready_blob_manifest; DELETE FROM attachment.uploads; DELETE FROM attachment.project_quotas; DELETE FROM attachment.principal_quotas; UPDATE attachment.global_quota SET reserved_bytes=0,used_bytes=0,reserved_uploads=0,ready_artifacts=0`); err != nil {
		t.Fatal(err)
	}
}

func reapTestAttachment(ctx context.Context, t *testing.T, app *Database, artifactID string) {
	t.Helper()
	token, fenced, err := app.BeginAttachmentReap(ctx, artifactID)
	if err != nil || !fenced {
		t.Fatalf("reap fence token=%q fenced=%t err=%v", token, fenced, err)
	}
	if released, err := app.ReleaseExpiredAttachment(ctx, artifactID, token); err != nil || !released {
		t.Fatalf("reap release=%t err=%v", released, err)
	}
}
