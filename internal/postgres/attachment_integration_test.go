package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/rock3r/punaro/internal/relay"
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
	uploaderLookup := "a3000000-0000-4000-8000-000000000001"
	uploaderCredentialDigest := sha256.Sum256([]byte("attachment uploader credential"))
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.device_credentials(lookup_id,principal_id,label,secret_digest) VALUES ($1,$2,'attachment uploader credential',$3)`, uploaderLookup, uploader.ID, uploaderCredentialDigest[:]); err != nil {
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
	lockOrderRequest := AttachmentReservationRequest{PrincipalID: uploader.ID, ProjectID: project.ProjectID, IdempotencyKey: "a2000000-0000-4000-8000-000000000000", SizeBytes: int64(len(body)), SHA256: digest, DisplayName: "lock-order.txt", MediaType: "text/plain", Lifetime: 10 * time.Minute}
	lockOrderReservation, err := app.ReserveAttachment(ctx, lockOrderRequest)
	if err != nil {
		t.Fatal(err)
	}
	assertAttachmentProjectBeforeUpload(ctx, t, app, ownerDB, project.ProjectID, lockOrderReservation.ArtifactID, "claim", func(conn *sql.Conn) error {
		var claimed bool
		if err := conn.QueryRowContext(ctx, `SELECT count(*) = 1 FROM attachment.claim_upload($1,$2,$3::interval)`, uploader.ID, lockOrderReservation.ArtifactID, attachmentInterval(time.Minute)).Scan(&claimed); err != nil {
			return err
		}
		if !claimed {
			return errors.New("attachment claim returned no row")
		}
		return nil
	})
	var lockOrderGeneration int64
	var lockOrderToken string
	if err := ownerDB.QueryRowContext(ctx, `SELECT attempt_generation,claim_token::text FROM attachment.uploads WHERE artifact_id=$1`, lockOrderReservation.ArtifactID).Scan(&lockOrderGeneration, &lockOrderToken); err != nil {
		t.Fatal(err)
	}
	assertAttachmentProjectBeforeUpload(ctx, t, app, ownerDB, project.ProjectID, lockOrderReservation.ArtifactID, "publication", func(conn *sql.Conn) error {
		var published bool
		if err := conn.QueryRowContext(ctx, `SELECT count(*) = 1 FROM attachment.publish_upload($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			uploader.ID, uploaderLookup, 1, lockOrderReservation.ArtifactID, lockOrderGeneration, lockOrderToken,
			"ready/"+lockOrderReservation.ArtifactID+".blob", lockOrderReservation.SizeBytes, hex.EncodeToString(lockOrderReservation.SHA256[:])).Scan(&published); err != nil {
			return err
		}
		if !published {
			return errors.New("attachment publication returned no row")
		}
		return nil
	})
	assertAttachmentProjectBeforeUpload(ctx, t, app, ownerDB, project.ProjectID, lockOrderReservation.ArtifactID, "corruption marker", func(conn *sql.Conn) error {
		var marked bool
		if err := conn.QueryRowContext(ctx, `SELECT attachment.mark_corrupt($1)`, lockOrderReservation.ArtifactID).Scan(&marked); err != nil {
			return err
		}
		if !marked {
			return errors.New("attachment corruption marker returned false")
		}
		return nil
	})
	lockOrderReleaseRequest := lockOrderRequest
	lockOrderReleaseRequest.IdempotencyKey = "a2000000-0000-4000-8000-000000000009"
	lockOrderReleaseRequest.DisplayName = "lock-order-release.txt"
	lockOrderRelease, err := app.ReserveAttachment(ctx, lockOrderReleaseRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE attachment.uploads SET created_at=statement_timestamp()-interval '2 seconds',expires_at=statement_timestamp()-interval '1 second' WHERE artifact_id=$1`, lockOrderRelease.ArtifactID); err != nil {
		t.Fatal(err)
	}
	cleanupToken, fenced, err := app.BeginAttachmentReap(ctx, lockOrderRelease.ArtifactID)
	if err != nil || !fenced {
		t.Fatalf("lock-order reap token=%q fenced=%t err=%v", cleanupToken, fenced, err)
	}
	assertAttachmentProjectBeforeUpload(ctx, t, app, ownerDB, project.ProjectID, lockOrderRelease.ArtifactID, "expired release", func(conn *sql.Conn) error {
		var released bool
		if err := conn.QueryRowContext(ctx, `SELECT attachment.release_expired_upload($1,$2)`, lockOrderRelease.ArtifactID, cleanupToken).Scan(&released); err != nil {
			return err
		}
		if !released {
			return errors.New("expired attachment release returned false")
		}
		return nil
	})
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
	publish := AttachmentPublishRequest{PrincipalID: uploader.ID, CredentialLookupID: uploaderLookup, CredentialGeneration: 1, ArtifactID: reservation.ArtifactID, AttemptGeneration: claim.AttemptGeneration, ClaimToken: claim.ClaimToken, StoragePath: "ready/" + reservation.ArtifactID + ".blob", SizeBytes: reservation.SizeBytes, SHA256: reservation.SHA256}
	ready, err := app.PublishAttachment(ctx, publish)
	if err != nil || ready.State != AttachmentReady || ready.StoragePath != publish.StoragePath {
		t.Fatalf("ready=%#v err=%v", ready, err)
	}
	if retry, retryErr := app.PublishAttachment(ctx, publish); retryErr != nil || retry != ready {
		t.Fatalf("READY retry=%#v err=%v", retry, retryErr)
	}

	recipientLookup := "a3000000-0000-4000-8000-000000000002"
	recipientCredentialDigest := sha256.Sum256([]byte("attachment recipient credential"))
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.device_credentials(lookup_id,principal_id,label,secret_digest) VALUES ($1,$2,'attachment recipient credential',$3)`, recipientLookup, outsider.ID, recipientCredentialDigest[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants(principal_id,scope,project_id,capability) VALUES
($1,'project',$3,'conversation.send'),($2,'project',$3,'attachment.download')`, uploader.ID, outsider.ID, project.ProjectID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	uploaderAuthority := relay.PrincipalAuthority{PrincipalID: uploader.ID, CredentialLookupID: uploaderLookup, CredentialGeneration: 1}
	recipientAuthority := relay.PrincipalAuthority{PrincipalID: outsider.ID, CredentialLookupID: recipientLookup, CredentialGeneration: 1}
	if err := app.AdvertiseEndpointsForPrincipal("attachment-uploader-machine", uploaderAuthority, []string{"agent/attachment/uploader"}, now, time.Hour); err != nil {
		t.Fatalf("bind uploader endpoint: %v", err)
	}
	if err := app.AdvertiseEndpointsForPrincipal("attachment-recipient-machine", recipientAuthority, []string{"agent/attachment/recipient"}, now, time.Hour); err != nil {
		t.Fatalf("bind recipient endpoint: %v", err)
	}
	conversation, err := app.CreateConversationIdempotent(relay.CreateConversationInput{
		MachineID: "attachment-uploader-machine", PrincipalID: uploader.ID,
		CredentialLookupID: uploaderLookup, CredentialGeneration: 1,
		ProjectID: project.ProjectID, IdempotencyKey: "attachment-conversation-create",
		CreatorEndpoint: "agent/attachment/uploader", Now: now,
		Members: []relay.Member{
			{Endpoint: "agent/attachment/uploader", Capabilities: relay.CapSend | relay.CapReceive | relay.CapAdmin},
			{Endpoint: "agent/attachment/recipient", Capabilities: relay.CapReceive},
		},
	})
	if err != nil {
		t.Fatalf("project conversation: %v", err)
	}
	message, duplicateMessage, err := app.AppendMessage(relay.AppendInput{
		ConversationID: conversation.ID, SenderMachineID: "attachment-uploader-machine",
		PrincipalID: uploader.ID, CredentialLookupID: uploaderLookup, CredentialGeneration: 1,
		FromEndpoint: "agent/attachment/uploader", Body: "trusted attachment reference",
		ArtifactIDs: []string{reservation.ArtifactID}, IdempotencyKey: "attachment-message-append", Now: now,
	})
	if err != nil || duplicateMessage {
		t.Fatalf("attachment message=%#v duplicate=%t err=%v", message, duplicateMessage, err)
	}
	if retried, duplicate, err := app.AppendMessage(relay.AppendInput{
		ConversationID: conversation.ID, SenderMachineID: "attachment-uploader-machine",
		PrincipalID: uploader.ID, CredentialLookupID: uploaderLookup, CredentialGeneration: 1,
		FromEndpoint: "agent/attachment/uploader", Body: "trusted attachment reference",
		ArtifactIDs: []string{reservation.ArtifactID}, IdempotencyKey: "attachment-message-append", Now: now,
	}); err != nil || !duplicate || retried.ID != message.ID {
		t.Fatalf("attachment message retry=%#v duplicate=%t err=%v", retried, duplicate, err)
	}
	revokeSend, err := ownerDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := revokeSend.ExecContext(ctx, `UPDATE auth.capability_grants SET revoked_at=statement_timestamp() WHERE principal_id=$1 AND project_id=$2 AND capability='conversation.send' AND revoked_at IS NULL`, uploader.ID, project.ProjectID); err != nil {
		_ = revokeSend.Rollback()
		t.Fatal(err)
	}
	retryResult := make(chan error, 1)
	go func() {
		_, _, retryErr := app.AppendMessage(relay.AppendInput{
			ConversationID: conversation.ID, SenderMachineID: "attachment-uploader-machine",
			PrincipalID: uploader.ID, CredentialLookupID: uploaderLookup, CredentialGeneration: 1,
			FromEndpoint: "agent/attachment/uploader", Body: "trusted attachment reference",
			ArtifactIDs: []string{reservation.ArtifactID}, IdempotencyKey: "attachment-message-append", Now: now,
		})
		retryResult <- retryErr
	}()
	select {
	case retryErr := <-retryResult:
		_ = revokeSend.Rollback()
		t.Fatalf("attachment retry bypassed uncommitted capability revocation: %v", retryErr)
	case <-time.After(100 * time.Millisecond):
	}
	if err := revokeSend.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-retryResult; !errors.Is(err, relay.ErrForbidden) {
		t.Fatalf("revoked attachment message retry error=%v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants(principal_id,scope,project_id,capability) VALUES ($1,'project',$2,'conversation.send')`, uploader.ID, project.ProjectID); err != nil {
		t.Fatal(err)
	}
	downloadRequest := AttachmentDownloadRequest{PrincipalID: outsider.ID, CredentialLookupID: recipientLookup, CredentialGeneration: 1, ArtifactID: reservation.ArtifactID}
	if download, err := app.AuthorizeAttachmentDownload(ctx, downloadRequest); err != nil || download.ArtifactID != reservation.ArtifactID || download.ProjectID != project.ProjectID || download.StoragePath != ready.StoragePath {
		t.Fatalf("recipient download=%#v err=%v", download, err)
	}
	if err := app.AdvertiseEndpointsForPrincipal("attachment-recipient-machine", uploaderAuthority, []string{"agent/attachment/recipient"}, now.Add(time.Second), time.Hour); err != nil {
		t.Fatalf("reassign recipient endpoint: %v", err)
	}
	if _, err := app.AuthorizeAttachmentDownload(ctx, downloadRequest); err != nil {
		t.Fatalf("endpoint reassignment transferred historical principal grant: %v", err)
	}
	if err := app.AdvertiseEndpoints("attachment-recipient-machine", []string{"agent/attachment/recipient"}, now.Add(2*time.Second), time.Hour); err != nil {
		t.Fatalf("legacy endpoint advertisement: %v", err)
	}
	var legacyBindingCount int
	if err := ownerDB.QueryRowContext(ctx, `SELECT count(*) FROM attachment.endpoint_principals WHERE endpoint='agent/attachment/recipient'`).Scan(&legacyBindingCount); err != nil || legacyBindingCount != 0 {
		t.Fatalf("legacy advertisement retained principal binding count=%d err=%v", legacyBindingCount, err)
	}
	if _, err := app.AuthorizeAttachmentDownload(ctx, downloadRequest); err != nil {
		t.Fatalf("legacy endpoint advertisement changed historical principal grant: %v", err)
	}
	revokeCredential, err := ownerDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := revokeCredential.ExecContext(ctx, `UPDATE auth.device_credentials SET revoked_at=statement_timestamp() WHERE lookup_id=$1`, recipientLookup); err != nil {
		_ = revokeCredential.Rollback()
		t.Fatal(err)
	}
	advertiseResult := make(chan error, 1)
	go func() {
		advertiseResult <- app.AdvertiseEndpointsForPrincipal("attachment-recipient-machine", recipientAuthority, []string{"agent/attachment/recipient"}, now.Add(3*time.Second), time.Hour)
	}()
	select {
	case advertiseErr := <-advertiseResult:
		_ = revokeCredential.Rollback()
		t.Fatalf("endpoint binding bypassed uncommitted credential revocation: %v", advertiseErr)
	case <-time.After(100 * time.Millisecond):
	}
	if err := revokeCredential.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-advertiseResult; !errors.Is(err, relay.ErrForbidden) {
		t.Fatalf("revoked endpoint binding error=%v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE auth.device_credentials SET revoked_at=NULL WHERE lookup_id=$1`, recipientLookup); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE auth.device_credentials SET generation=2 WHERE lookup_id=$1`, recipientLookup); err != nil {
		t.Fatal(err)
	}
	if _, err := app.AuthorizeAttachmentDownload(ctx, downloadRequest); !errors.Is(err, ErrForbidden) {
		t.Fatalf("stale credential generation download error=%v", err)
	}
	downloadRequest.CredentialGeneration = 2
	if _, err := app.AuthorizeAttachmentDownload(ctx, downloadRequest); err != nil {
		t.Fatalf("credential rotation lost stable recipient grant: %v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE auth.capability_grants SET revoked_at=statement_timestamp() WHERE principal_id=$1 AND project_id=$2 AND capability='attachment.download' AND revoked_at IS NULL`, outsider.ID, project.ProjectID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.AuthorizeAttachmentDownload(ctx, downloadRequest); !errors.Is(err, ErrForbidden) {
		t.Fatalf("revoked download capability error=%v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants(principal_id,scope,project_id,capability) VALUES ($1,'project',$2,'attachment.delete')`, uploader.ID, project.ProjectID); err != nil {
		t.Fatal(err)
	}
	deleteRequest := AttachmentDeleteRequest{
		PrincipalID: uploader.ID, CredentialLookupID: uploaderLookup, CredentialGeneration: 1,
		ArtifactID: reservation.ArtifactID, IdempotencyKey: "a4000000-0000-4000-8000-000000000001",
	}
	unauthorizedDelete := deleteRequest
	unauthorizedDelete.PrincipalID = outsider.ID
	unauthorizedDelete.CredentialLookupID = recipientLookup
	unauthorizedDelete.CredentialGeneration = 2
	unauthorizedDelete.IdempotencyKey = "a4000000-0000-4000-8000-000000000002"
	if _, err := app.DeleteAttachment(ctx, unauthorizedDelete); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unauthorized attachment delete error=%v", err)
	}
	guessedDelete := deleteRequest
	guessedDelete.ArtifactID = "a4000000-0000-4000-8000-000000000003"
	guessedDelete.IdempotencyKey = "a4000000-0000-4000-8000-000000000004"
	if _, err := app.DeleteAttachment(ctx, guessedDelete); !errors.Is(err, ErrForbidden) {
		t.Fatalf("guessed attachment delete error=%v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE auth.device_credentials SET created_at=statement_timestamp()-interval '2 seconds',expires_at=statement_timestamp()-interval '1 second' WHERE lookup_id=$1`, uploaderLookup); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DeleteAttachment(ctx, deleteRequest); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expired credential attachment delete error=%v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE auth.device_credentials SET expires_at=NULL WHERE lookup_id=$1`, uploaderLookup); err != nil {
		t.Fatal(err)
	}
	deletion, err := app.DeleteAttachment(ctx, deleteRequest)
	if err != nil || deletion.State != AttachmentTombstoned || deletion.ArtifactID != reservation.ArtifactID || deletion.ProjectID != project.ProjectID || deletion.StoragePath != ready.StoragePath || !deletion.DeletedAt.IsZero() || !deletion.GCAfter.After(time.Now().UTC()) {
		t.Fatalf("attachment tombstone=%#v err=%v", deletion, err)
	}
	if retry, retryErr := app.DeleteAttachment(ctx, deleteRequest); retryErr != nil || retry != deletion {
		t.Fatalf("attachment tombstone retry=%#v err=%v", retry, retryErr)
	}
	if _, err := app.AuthorizeAttachmentDownload(ctx, AttachmentDownloadRequest{PrincipalID: outsider.ID, CredentialLookupID: recipientLookup, CredentialGeneration: 2, ArtifactID: reservation.ArtifactID}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("tombstoned attachment download error=%v", err)
	}
	var usedBeforeGC int64
	if err := ownerDB.QueryRowContext(ctx, `SELECT used_bytes FROM attachment.global_quota WHERE singleton`).Scan(&usedBeforeGC); err != nil || usedBeforeGC < reservation.SizeBytes {
		t.Fatalf("tombstone quota used=%d err=%v", usedBeforeGC, err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE auth.capability_grants SET revoked_at=statement_timestamp() WHERE principal_id=$1 AND project_id=$2 AND capability='attachment.delete' AND revoked_at IS NULL`, uploader.ID, project.ProjectID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DeleteAttachment(ctx, deleteRequest); !errors.Is(err, ErrForbidden) {
		t.Fatalf("revoked exact delete retry error=%v", err)
	}
	if _, err := ownerDB.ExecContext(ctx, `INSERT INTO auth.capability_grants(principal_id,scope,project_id,capability) VALUES ($1,'project',$2,'attachment.delete')`, uploader.ID, project.ProjectID); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := app.ClaimAttachmentGC(ctx, reservation.ArtifactID, time.Minute); err != nil || claimed {
		t.Fatalf("pre-cutoff GC claimed=%t err=%v", claimed, err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE attachment.deletions SET tombstoned_at=statement_timestamp()-interval '2 seconds',gc_after=statement_timestamp()-interval '1 second' WHERE artifact_id=$1`, reservation.ArtifactID); err != nil {
		t.Fatal(err)
	}
	var backupFence string
	if err := ownerDB.QueryRowContext(ctx, `SELECT jobs.acquire_backup_gc_fence(interval '5 minutes')::text`).Scan(&backupFence); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := app.ClaimAttachmentGC(ctx, reservation.ArtifactID, time.Minute); err != nil || claimed {
		t.Fatalf("backup-fenced GC claimed=%t err=%v", claimed, err)
	}
	if releasePhysicalGC, permitted, err := app.BeginAttachmentPhysicalGC(ctx); err != nil || permitted || releasePhysicalGC != nil {
		t.Fatalf("backup-fenced physical GC permitted=%t release=%v err=%v", permitted, releasePhysicalGC != nil, err)
	}
	var fenceReleased bool
	if err := ownerDB.QueryRowContext(ctx, `SELECT jobs.cancel_unbound_backup_gc_fence($1)`, backupFence).Scan(&fenceReleased); err != nil || !fenceReleased {
		t.Fatalf("release GC test fence=%t err=%v", fenceReleased, err)
	}
	releasePhysicalGC, permitted, err := app.BeginAttachmentPhysicalGC(ctx)
	if err != nil || !permitted || releasePhysicalGC == nil {
		t.Fatalf("physical GC fence permitted=%t release=%v err=%v", permitted, releasePhysicalGC != nil, err)
	}
	secondGCCtx, cancelSecondGC := context.WithTimeout(ctx, 100*time.Millisecond)
	if secondRelease, secondPermitted, secondErr := app.BeginAttachmentPhysicalGC(secondGCCtx); !errors.Is(secondErr, context.DeadlineExceeded) || secondPermitted || secondRelease != nil {
		cancelSecondGC()
		t.Fatalf("concurrent physical GC holder release=%v permitted=%t err=%v", secondRelease != nil, secondPermitted, secondErr)
	}
	cancelSecondGC()
	type backupAcquireResult struct {
		token string
		err   error
	}
	backupAcquireDone := make(chan backupAcquireResult, 1)
	go func() {
		var token string
		acquireErr := ownerDB.QueryRowContext(ctx, `SELECT jobs.acquire_backup_gc_fence(interval '5 minutes')::text`).Scan(&token)
		backupAcquireDone <- backupAcquireResult{token: token, err: acquireErr}
	}()
	select {
	case result := <-backupAcquireDone:
		t.Fatalf("backup crossed active physical GC fence: token=%s err=%v", result.token, result.err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := releasePhysicalGC(); err != nil {
		t.Fatalf("release physical GC fence: %v", err)
	}
	var acquiredAfterGC backupAcquireResult
	select {
	case acquiredAfterGC = <-backupAcquireDone:
	case <-time.After(2 * time.Second):
		t.Fatal("backup did not acquire after physical GC fence release")
	}
	if acquiredAfterGC.err != nil || acquiredAfterGC.token == "" {
		t.Fatalf("backup after physical GC token=%s err=%v", acquiredAfterGC.token, acquiredAfterGC.err)
	}
	if err := ownerDB.QueryRowContext(ctx, `SELECT jobs.cancel_unbound_backup_gc_fence($1)`, acquiredAfterGC.token).Scan(&fenceReleased); err != nil || !fenceReleased {
		t.Fatalf("release post-GC backup fence=%t err=%v", fenceReleased, err)
	}
	gcClaim, claimed, err := app.ClaimAttachmentGC(ctx, reservation.ArtifactID, time.Minute)
	if err != nil || !claimed || gcClaim.State != AttachmentGCClaimed || gcClaim.GCGeneration != 1 || gcClaim.GCToken == "" {
		t.Fatalf("attachment GC claim=%#v claimed=%t err=%v", gcClaim, claimed, err)
	}
	if _, claimed, err := app.ClaimAttachmentGC(ctx, reservation.ArtifactID, time.Minute); err != nil || claimed {
		t.Fatalf("competing GC claim acquired=%t err=%v", claimed, err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE attachment.deletions SET gc_lease_until=statement_timestamp()-interval '1 second' WHERE artifact_id=$1`, reservation.ArtifactID); err != nil {
		t.Fatal(err)
	}
	reclaimed, claimed, err := app.ClaimAttachmentGC(ctx, reservation.ArtifactID, time.Minute)
	if err != nil || !claimed || reclaimed.GCGeneration != gcClaim.GCGeneration+1 || reclaimed.GCToken == gcClaim.GCToken {
		t.Fatalf("attachment GC reclaim=%#v claimed=%t err=%v", reclaimed, claimed, err)
	}
	if _, finalized, err := app.FinalizeAttachmentGC(ctx, reservation.ArtifactID, gcClaim.GCGeneration, gcClaim.GCToken); err != nil || finalized {
		t.Fatalf("expired GC claim finalized=%t err=%v", finalized, err)
	}
	gcClaim = reclaimed
	if _, finalized, err := app.FinalizeAttachmentGC(ctx, reservation.ArtifactID, gcClaim.GCGeneration, "a5000000-0000-4000-8000-000000000001"); err != nil || finalized {
		t.Fatalf("stale GC finalized=%t err=%v", finalized, err)
	}
	deleted, finalized, err := app.FinalizeAttachmentGC(ctx, reservation.ArtifactID, gcClaim.GCGeneration, gcClaim.GCToken)
	if err != nil || !finalized || deleted.State != AttachmentDeleted || deleted.DeletedAt.IsZero() {
		t.Fatalf("attachment GC deletion=%#v finalized=%t err=%v", deleted, finalized, err)
	}
	if retry, finalized, err := app.FinalizeAttachmentGC(ctx, reservation.ArtifactID, gcClaim.GCGeneration, gcClaim.GCToken); err != nil || !finalized || retry != deleted {
		t.Fatalf("duplicate GC result=%#v finalized=%t err=%v", retry, finalized, err)
	}
	var usedAfterGC int64
	if err := ownerDB.QueryRowContext(ctx, `SELECT used_bytes FROM attachment.global_quota WHERE singleton`).Scan(&usedAfterGC); err != nil || usedAfterGC != usedBeforeGC-reservation.SizeBytes {
		t.Fatalf("finalized quota used=%d before=%d err=%v", usedAfterGC, usedBeforeGC, err)
	}
	if _, err := app.db.ExecContext(ctx, `SELECT * FROM attachment.recipient_grants`); err == nil {
		t.Fatal("application role read attachment recipient grants directly")
	}
	if _, err := app.db.ExecContext(ctx, `SELECT * FROM attachment.deletions`); err == nil {
		t.Fatal("application role read attachment deletion state directly")
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
	duplicateReady, err := app.PublishAttachment(ctx, AttachmentPublishRequest{PrincipalID: uploader.ID, CredentialLookupID: uploaderLookup, CredentialGeneration: 1, ArtifactID: duplicateReservation.ArtifactID, AttemptGeneration: duplicateClaim.AttemptGeneration, ClaimToken: duplicateClaim.ClaimToken, StoragePath: "ready/" + duplicateReservation.ArtifactID + ".blob", SizeBytes: duplicateReservation.SizeBytes, SHA256: duplicateReservation.SHA256})
	if err != nil || duplicateReady.StoragePath == ready.StoragePath || duplicateReady.SHA256 != ready.SHA256 {
		t.Fatalf("duplicate READY=%#v err=%v", duplicateReady, err)
	}
	changedDelete := deleteRequest
	changedDelete.ArtifactID = duplicateReservation.ArtifactID
	if _, err := app.DeleteAttachment(ctx, changedDelete); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed attachment delete retry error=%v", err)
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
	if _, err := app.PublishAttachment(ctx, AttachmentPublishRequest{PrincipalID: uploader.ID, CredentialLookupID: uploaderLookup, CredentialGeneration: 1, ArtifactID: revokedReservation.ArtifactID, AttemptGeneration: revokedClaim.AttemptGeneration, ClaimToken: revokedClaim.ClaimToken, StoragePath: "ready/" + revokedReservation.ArtifactID + ".blob", SizeBytes: revokedReservation.SizeBytes, SHA256: revokedReservation.SHA256}); !errors.Is(err, ErrForbidden) {
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
	credentialRevoked := request
	credentialRevoked.IdempotencyKey = "a2000000-0000-4000-8000-000000000008"
	credentialRevoked.DisplayName = "credential-revoked.txt"
	credentialRevokedReservation, err := app.ReserveAttachment(ctx, credentialRevoked)
	if err != nil {
		t.Fatal(err)
	}
	credentialRevokedClaim, err := app.ClaimAttachmentUpload(ctx, uploader.ID, credentialRevokedReservation.ArtifactID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.ExecContext(ctx, `UPDATE auth.device_credentials SET revoked_at=statement_timestamp() WHERE lookup_id=$1`, uploaderLookup); err != nil {
		t.Fatal(err)
	}
	credentialRevokedPublish := AttachmentPublishRequest{PrincipalID: uploader.ID, CredentialLookupID: uploaderLookup, CredentialGeneration: 1, ArtifactID: credentialRevokedReservation.ArtifactID, AttemptGeneration: credentialRevokedClaim.AttemptGeneration, ClaimToken: credentialRevokedClaim.ClaimToken, StoragePath: "ready/" + credentialRevokedReservation.ArtifactID + ".blob", SizeBytes: credentialRevokedReservation.SizeBytes, SHA256: credentialRevokedReservation.SHA256}
	if _, err := app.PublishAttachment(ctx, credentialRevokedPublish); !errors.Is(err, ErrForbidden) {
		t.Fatalf("revoked credential completion error=%v", err)
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
	cleanupTx, err := ownerDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	cleanup := []struct {
		query string
		args  []any
	}{
		{`DELETE FROM attachment.recipient_grant_endpoints WHERE message_id=$1`, []any{message.ID}},
		{`DELETE FROM attachment.recipient_grants WHERE message_id=$1`, []any{message.ID}},
		{`DELETE FROM attachment.message_artifacts WHERE message_id=$1`, []any{message.ID}},
		{`DELETE FROM attachment.conversation_projects WHERE conversation_id=$1`, []any{conversation.ID}},
		{`DELETE FROM attachment.endpoint_principals WHERE endpoint IN ('agent/attachment/uploader','agent/attachment/recipient')`, nil},
		{`DELETE FROM relay.mail_deliveries WHERE message_id=$1`, []any{message.ID}},
		{`DELETE FROM relay.mail_message_idempotency WHERE message_id=$1`, []any{message.ID}},
		{`DELETE FROM relay.mail_messages WHERE id=$1`, []any{message.ID}},
		{`DELETE FROM relay.mail_memberships WHERE conversation_id=$1`, []any{conversation.ID}},
		{`DELETE FROM relay.mail_recipient_cursors WHERE conversation_id=$1`, []any{conversation.ID}},
		{`DELETE FROM relay.mail_conversation_idempotency WHERE conversation_id=$1`, []any{conversation.ID}},
		{`DELETE FROM relay.mail_conversations WHERE id=$1`, []any{conversation.ID}},
		{`DELETE FROM relay.mail_endpoints WHERE endpoint IN ('agent/attachment/uploader','agent/attachment/recipient')`, nil},
		{`DELETE FROM attachment.ready_artifacts`, nil},
		{`DELETE FROM attachment.ready_blob_manifest`, nil},
		{`DELETE FROM attachment.deletions`, nil},
		{`DELETE FROM attachment.uploads`, nil},
		{`DELETE FROM attachment.project_quotas`, nil},
		{`DELETE FROM attachment.principal_quotas`, nil},
		{`UPDATE attachment.global_quota SET reserved_bytes=0,used_bytes=0,reserved_uploads=0,ready_artifacts=0`, nil},
	}
	for _, statement := range cleanup {
		if _, err := cleanupTx.ExecContext(ctx, statement.query, statement.args...); err != nil {
			_ = cleanupTx.Rollback()
			t.Fatal(err)
		}
	}
	if err := cleanupTx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func assertAttachmentProjectBeforeUpload(
	ctx context.Context,
	t *testing.T,
	app *Database,
	ownerDB *sql.DB,
	projectID string,
	artifactID string,
	operation string,
	mutate func(*sql.Conn) error,
) {
	t.Helper()
	projectBlocker, err := ownerDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := projectBlocker.ExecContext(ctx, `SELECT 1 FROM relay.projects WHERE id=$1 FOR UPDATE`, projectID); err != nil {
		_ = projectBlocker.Rollback()
		t.Fatal(err)
	}
	mutationConn, err := app.db.Conn(ctx)
	if err != nil {
		_ = projectBlocker.Rollback()
		t.Fatal(err)
	}
	defer func() { _ = mutationConn.Close() }()
	var mutationPID int
	if err := mutationConn.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&mutationPID); err != nil {
		_ = projectBlocker.Rollback()
		t.Fatal(err)
	}
	mutationResult := make(chan error, 1)
	go func() { mutationResult <- mutate(mutationConn) }()
	waitDeadline := time.Now().Add(5 * time.Second)
	for {
		var waitType sql.NullString
		if err := ownerDB.QueryRowContext(ctx, `SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1`, mutationPID).Scan(&waitType); err != nil {
			_ = projectBlocker.Rollback()
			t.Fatal(err)
		}
		if waitType.Valid && waitType.String == "Lock" {
			break
		}
		if time.Now().After(waitDeadline) {
			_ = projectBlocker.Rollback()
			t.Fatalf("attachment %s did not block on the project lock", operation)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := ownerDB.ExecContext(ctx, `SELECT 1 FROM attachment.uploads WHERE artifact_id=$1 FOR UPDATE NOWAIT`, artifactID); err != nil {
		_ = projectBlocker.Rollback()
		t.Fatalf("attachment %s locked upload before project: %v", operation, err)
	}
	if err := projectBlocker.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-mutationResult; err != nil {
		t.Fatalf("lock-ordered attachment %s: %v", operation, err)
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
