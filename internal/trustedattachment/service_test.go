package trustedattachment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rock3r/punaro/internal/postgres"
)

type fakeRepository struct {
	mu                sync.Mutex
	claim             postgres.AttachmentClaim
	claimErr          error
	publishResult     postgres.AttachmentArtifact
	publishErrors     []error
	publishCalls      int
	candidates        []postgres.AttachmentReconcileCandidate
	markCorruptCalls  []string
	releaseCalls      []string
	beginToken        string
	beginAllowed      bool
	beginCalls        int
	releaseTokens     []string
	publishMakesReady bool
	publishHook       func()
	download          postgres.AttachmentDownload
	downloadErr       error
}

type testDownloadWriter struct {
	io.Writer
}

func (writer testDownloadWriter) SetWriteDeadline(time.Time) error { return nil }

func (repository *fakeRepository) ClaimAttachmentUpload(context.Context, string, string, time.Duration) (postgres.AttachmentClaim, error) {
	return repository.claim, repository.claimErr
}

func (repository *fakeRepository) PublishAttachment(_ context.Context, _ postgres.AttachmentPublishRequest) (postgres.AttachmentArtifact, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	index := repository.publishCalls
	repository.publishCalls++
	if index < len(repository.publishErrors) && repository.publishErrors[index] != nil {
		return postgres.AttachmentArtifact{}, repository.publishErrors[index]
	}
	if repository.publishMakesReady {
		repository.beginAllowed = false
	}
	if repository.publishHook != nil {
		repository.publishHook()
	}
	return repository.publishResult, nil
}

func (repository *fakeRepository) AttachmentReconcileCandidates(context.Context, postgres.AttachmentReconcileCursor, int) ([]postgres.AttachmentReconcileCandidate, postgres.AttachmentReconcileCursor, error) {
	next := postgres.AttachmentReconcileCursor{}
	if len(repository.candidates) != 0 {
		last := repository.candidates[len(repository.candidates)-1]
		next = postgres.AttachmentReconcileCursor{State: last.State, ExpiresAt: last.ExpiresAt, ArtifactID: last.ArtifactID}
	}
	return repository.candidates, next, nil
}

func (repository *fakeRepository) MarkAttachmentCorrupt(_ context.Context, artifactID string) (bool, error) {
	repository.markCorruptCalls = append(repository.markCorruptCalls, artifactID)
	return true, nil
}

func (repository *fakeRepository) BeginAttachmentReap(_ context.Context, _ string) (string, bool, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.beginCalls++
	return repository.beginToken, repository.beginAllowed, nil
}

func (repository *fakeRepository) ReleaseExpiredAttachment(_ context.Context, artifactID, cleanupToken string) (bool, error) {
	repository.releaseCalls = append(repository.releaseCalls, artifactID)
	repository.releaseTokens = append(repository.releaseTokens, cleanupToken)
	return true, nil
}

func (repository *fakeRepository) AuthorizeAttachmentDownload(context.Context, postgres.AttachmentDownloadRequest) (postgres.AttachmentDownload, error) {
	return repository.download, repository.downloadErr
}

func TestServiceAuthorizesAndVerifiesBeforeDownloadBytes(t *testing.T) {
	body := []byte("recipient snapshot body")
	digest := sha256.Sum256(body)
	download := postgres.AttachmentDownload{ArtifactID: testArtifactID, ProjectID: "11111111-1111-4111-8111-111111111111", StoragePath: "ready/" + testArtifactID + ".blob", SizeBytes: int64(len(body)), SHA256: digest, DisplayName: "report.txt", MediaType: "text/plain"}
	repository := &fakeRepository{download: download}
	service := newTestService(t, repository)
	if _, err := service.store.Publish(context.Background(), UploadClaim{ArtifactID: testArtifactID, AttemptGeneration: 1, SizeBytes: int64(len(body)), SHA256: digest}, bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	request := postgres.AttachmentDownloadRequest{PrincipalID: "22222222-2222-4222-8222-222222222222", CredentialLookupID: "33333333-3333-4333-8333-333333333333", CredentialGeneration: 1, ArtifactID: testArtifactID}
	var output bytes.Buffer
	got, err := service.Download(context.Background(), request, testDownloadWriter{Writer: &output})
	if err != nil || got != download || !bytes.Equal(output.Bytes(), body) {
		t.Fatalf("download=%#v output=%q err=%v", got, output.Bytes(), err)
	}
	repository.downloadErr = postgres.ErrForbidden
	output.Reset()
	if _, err := service.Download(context.Background(), request, testDownloadWriter{Writer: &output}); !errors.Is(err, postgres.ErrForbidden) || output.Len() != 0 {
		t.Fatalf("denied download emitted=%d err=%v", output.Len(), err)
	}
}

func TestServiceBoundsConcurrentDownloadsBeforeAuthorization(t *testing.T) {
	repository := &fakeRepository{}
	service := newTestService(t, repository)
	for range maxConcurrentDownloads {
		service.downloadSlots <- struct{}{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var output bytes.Buffer
	request := postgres.AttachmentDownloadRequest{PrincipalID: "22222222-2222-4222-8222-222222222222", CredentialLookupID: "33333333-3333-4333-8333-333333333333", CredentialGeneration: 1, ArtifactID: testArtifactID}
	if _, err := service.Download(ctx, request, testDownloadWriter{Writer: &output}); !errors.Is(err, context.Canceled) || output.Len() != 0 {
		t.Fatalf("saturated download emitted=%d err=%v", output.Len(), err)
	}
}

func TestServiceDownloadLockWaitHonorsCancellation(t *testing.T) {
	service := newTestService(t, &fakeRepository{})
	unlock, err := service.lockArtifact(context.Background(), testArtifactID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := service.Download(ctx, postgres.AttachmentDownloadRequest{PrincipalID: "22222222-2222-4222-8222-222222222222", CredentialLookupID: "33333333-3333-4333-8333-333333333333", CredentialGeneration: 1, ArtifactID: testArtifactID}, testDownloadWriter{Writer: io.Discard})
		done <- err
	}()
	deadline := time.Now().Add(time.Second)
	for len(service.downloadSlots) != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(service.downloadSlots) != 1 {
		_ = unlock()
		t.Fatal("download did not reach the artifact lock")
	}
	cancel()
	select {
	case err := <-done:
		_ = unlock()
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled lock wait error=%v", err)
		}
	case <-time.After(100 * time.Millisecond):
		_ = unlock()
		<-done
		t.Fatal("canceled download remained blocked on the in-process artifact lock")
	}
}

func TestServiceDownloadDeadlineInterruptsBlockedWrite(t *testing.T) {
	body := bytes.Repeat([]byte("x"), 128<<10)
	digest := sha256.Sum256(body)
	download := postgres.AttachmentDownload{ArtifactID: testArtifactID, ProjectID: "11111111-1111-4111-8111-111111111111", StoragePath: "ready/" + testArtifactID + ".blob", SizeBytes: int64(len(body)), SHA256: digest, DisplayName: "report.bin", MediaType: "application/octet-stream"}
	service := newTestService(t, &fakeRepository{download: download})
	service.downloadLifetime = 25 * time.Millisecond
	if _, err := service.store.Publish(context.Background(), UploadClaim{ArtifactID: testArtifactID, AttemptGeneration: 1, SizeBytes: int64(len(body)), SHA256: digest}, bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	destination, blockedPeer := net.Pipe()
	defer func() { _ = destination.Close() }()
	defer func() { _ = blockedPeer.Close() }()
	request := postgres.AttachmentDownloadRequest{PrincipalID: "22222222-2222-4222-8222-222222222222", CredentialLookupID: "33333333-3333-4333-8333-333333333333", CredentialGeneration: 1, ArtifactID: testArtifactID}
	started := time.Now()
	if _, err := service.Download(context.Background(), request, destination); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked download error=%v", err)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("blocked download exceeded cancellation fence: %s", elapsed)
	}
	if len(service.downloadSlots) != 0 {
		t.Fatal("over-lifetime download retained a concurrency slot")
	}
}

func TestServicePublishesBytesBeforeConditionalReady(t *testing.T) {
	body := []byte("trusted body")
	digest := sha256.Sum256(body)
	claim := postgres.AttachmentClaim{ArtifactID: testArtifactID, PrincipalID: "11111111-1111-4111-8111-111111111111", AttemptGeneration: 2, ClaimToken: "22222222-2222-4222-8222-222222222222", SizeBytes: int64(len(body)), SHA256: digest}
	want := postgres.AttachmentArtifact{ArtifactID: testArtifactID, StoragePath: "ready/" + testArtifactID + ".blob", SizeBytes: int64(len(body)), SHA256: digest, State: postgres.AttachmentReady}
	repository := &fakeRepository{claim: claim, publishResult: want}
	service := newTestService(t, repository)
	got, err := service.Upload(context.Background(), claim.PrincipalID, claim.ArtifactID, time.Minute, bytes.NewReader(body))
	if err != nil || got != want || repository.publishCalls != 1 {
		t.Fatalf("got=%#v calls=%d err=%v", got, repository.publishCalls, err)
	}
	if err := service.store.Verify(PublishedBlob{StoragePath: got.StoragePath, SizeBytes: got.SizeBytes, SHA256: got.SHA256}); err != nil {
		t.Fatalf("READY preceded durable bytes: %v", err)
	}
}

func TestServiceRetriesAmbiguousReadyCommitWithExactClaim(t *testing.T) {
	body := []byte("trusted body")
	digest := sha256.Sum256(body)
	claim := postgres.AttachmentClaim{ArtifactID: testArtifactID, PrincipalID: "11111111-1111-4111-8111-111111111111", AttemptGeneration: 2, ClaimToken: "22222222-2222-4222-8222-222222222222", SizeBytes: int64(len(body)), SHA256: digest}
	want := postgres.AttachmentArtifact{ArtifactID: testArtifactID, StoragePath: "ready/" + testArtifactID + ".blob", SizeBytes: int64(len(body)), SHA256: digest, State: postgres.AttachmentReady}
	repository := &fakeRepository{claim: claim, publishResult: want, publishErrors: []error{errors.New("ambiguous connection loss")}}
	service := newTestService(t, repository)
	got, err := service.Upload(context.Background(), claim.PrincipalID, claim.ArtifactID, time.Minute, bytes.NewReader(body))
	if err != nil || got != want || repository.publishCalls != 2 {
		t.Fatalf("got=%#v calls=%d err=%v", got, repository.publishCalls, err)
	}
}

func TestServiceReturnsReadyArtifactWhenStageCleanupIsDeferred(t *testing.T) {
	body := []byte("trusted body")
	digest := sha256.Sum256(body)
	claim := postgres.AttachmentClaim{ArtifactID: testArtifactID, PrincipalID: "11111111-1111-4111-8111-111111111111", AttemptGeneration: 2, ClaimToken: "22222222-2222-4222-8222-222222222222", SizeBytes: int64(len(body)), SHA256: digest}
	want := postgres.AttachmentArtifact{ArtifactID: testArtifactID, StoragePath: "ready/" + testArtifactID + ".blob", SizeBytes: int64(len(body)), SHA256: digest, State: postgres.AttachmentReady}
	repository := &fakeRepository{claim: claim, publishResult: want}
	service := newTestService(t, repository)
	unsafeStage := filepath.Join(service.store.stagingDir, claim.ArtifactID, "unexpected")
	repository.publishHook = func() {
		if err := os.WriteFile(unsafeStage, []byte("defer cleanup"), 0o600); err != nil {
			t.Errorf("create deferred-cleanup fixture: %v", err)
		}
	}
	got, err := service.Upload(context.Background(), claim.PrincipalID, claim.ArtifactID, time.Minute, bytes.NewReader(body))
	if err != nil || got != want {
		t.Fatalf("got=%#v err=%v", got, err)
	}
	if _, err := os.Stat(unsafeStage); err != nil {
		t.Fatalf("post-commit cleanup was not deferred: %v", err)
	}
	if err := os.Remove(unsafeStage); err != nil {
		t.Fatal(err)
	}
	repository.candidates = []postgres.AttachmentReconcileCandidate{{ArtifactID: claim.ArtifactID, State: postgres.AttachmentReady, StoragePath: want.StoragePath, SizeBytes: want.SizeBytes, SHA256: want.SHA256}}
	if _, err := service.ReconcileBatch(context.Background(), postgres.AttachmentReconcileCursor{}, 10); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(unsafeStage)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reconciliation did not retire deferred stages: %v", err)
	}
}

func TestServiceLeavesRevokedPublicationHiddenUntilReconciliation(t *testing.T) {
	body := []byte("trusted body")
	digest := sha256.Sum256(body)
	claim := postgres.AttachmentClaim{ArtifactID: testArtifactID, PrincipalID: "11111111-1111-4111-8111-111111111111", AttemptGeneration: 2, ClaimToken: "22222222-2222-4222-8222-222222222222", SizeBytes: int64(len(body)), SHA256: digest}
	repository := &fakeRepository{claim: claim, publishErrors: []error{postgres.ErrForbidden}}
	service := newTestService(t, repository)
	if _, err := service.Upload(context.Background(), claim.PrincipalID, claim.ArtifactID, time.Minute, bytes.NewReader(body)); !errors.Is(err, postgres.ErrForbidden) {
		t.Fatalf("upload error=%v", err)
	}
	hidden := PublishedBlob{StoragePath: "ready/" + testArtifactID + ".blob", SizeBytes: int64(len(body)), SHA256: digest}
	if err := service.store.Verify(hidden); err != nil {
		t.Fatalf("hidden durable final missing: %v", err)
	}
	repository.candidates = []postgres.AttachmentReconcileCandidate{{ArtifactID: testArtifactID, State: postgres.AttachmentReserved, ExpiresAt: time.Unix(100, 0), CurrentTimeline: true}}
	repository.beginToken = "33333333-3333-4333-8333-333333333333"
	repository.beginAllowed = true
	if _, err := service.ReconcileBatch(context.Background(), postgres.AttachmentReconcileCursor{}, 10); err != nil {
		t.Fatal(err)
	}
	if err := service.store.Verify(hidden); err == nil || len(repository.releaseCalls) != 1 {
		t.Fatalf("hidden final survived reconciliation; releases=%v", repository.releaseCalls)
	}
}

func TestServiceDoesNotDeleteUntilDatabaseFencesReaping(t *testing.T) {
	body := []byte("still live")
	digest := sha256.Sum256(body)
	repository := &fakeRepository{candidates: []postgres.AttachmentReconcileCandidate{{ArtifactID: testArtifactID, State: postgres.AttachmentReserved, ExpiresAt: time.Unix(100, 0), CurrentTimeline: true}}}
	service := newTestService(t, repository)
	path := PublishedBlob{StoragePath: "ready/" + testArtifactID + ".blob", SizeBytes: int64(len(body)), SHA256: digest}
	if _, err := service.store.Publish(context.Background(), UploadClaim{ArtifactID: testArtifactID, AttemptGeneration: 1, SizeBytes: int64(len(body)), SHA256: digest}, bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReconcileBatch(context.Background(), postgres.AttachmentReconcileCursor{}, 10); err != nil {
		t.Fatal(err)
	}
	if err := service.store.Verify(path); err != nil || len(repository.releaseCalls) != 0 {
		t.Fatalf("unfenced bytes deleted or quota released: verify=%v releases=%v", err, repository.releaseCalls)
	}
}

func TestServiceResumesDurableReapingFenceAfterCrash(t *testing.T) {
	body := []byte("hidden final")
	digest := sha256.Sum256(body)
	token := "33333333-3333-4333-8333-333333333333"
	repository := &fakeRepository{candidates: []postgres.AttachmentReconcileCandidate{{ArtifactID: testArtifactID, State: postgres.AttachmentReaping, CleanupToken: token, ExpiresAt: time.Unix(100, 0)}}}
	service := newTestService(t, repository)
	path := PublishedBlob{StoragePath: "ready/" + testArtifactID + ".blob", SizeBytes: int64(len(body)), SHA256: digest}
	if _, err := service.store.Publish(context.Background(), UploadClaim{ArtifactID: testArtifactID, AttemptGeneration: 9, SizeBytes: int64(len(body)), SHA256: digest}, bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReconcileBatch(context.Background(), postgres.AttachmentReconcileCursor{}, 10); err != nil {
		t.Fatal(err)
	}
	if err := service.store.Verify(path); err == nil || repository.beginCalls != 0 || len(repository.releaseTokens) != 1 || repository.releaseTokens[0] != token {
		t.Fatalf("reaping resume verify=%v begins=%d releaseTokens=%v", err, repository.beginCalls, repository.releaseTokens)
	}
}

func TestServiceSerializesPublicationAgainstReapingFence(t *testing.T) {
	body := []byte("publication wins")
	digest := sha256.Sum256(body)
	claim := postgres.AttachmentClaim{ArtifactID: testArtifactID, PrincipalID: "11111111-1111-4111-8111-111111111111", AttemptGeneration: 1, ClaimToken: "22222222-2222-4222-8222-222222222222", SizeBytes: int64(len(body)), SHA256: digest}
	want := postgres.AttachmentArtifact{ArtifactID: testArtifactID, StoragePath: "ready/" + testArtifactID + ".blob", SizeBytes: int64(len(body)), SHA256: digest, State: postgres.AttachmentReady}
	repository := &fakeRepository{claim: claim, publishResult: want, publishMakesReady: true, beginAllowed: true, beginToken: "33333333-3333-4333-8333-333333333333", candidates: []postgres.AttachmentReconcileCandidate{{ArtifactID: testArtifactID, State: postgres.AttachmentReserved}}}
	service := newTestService(t, repository)
	started := make(chan struct{})
	release := make(chan struct{})
	uploadDone := make(chan error, 1)
	go func() {
		_, uploadErr := service.Upload(context.Background(), claim.PrincipalID, claim.ArtifactID, time.Minute, &gatedReader{body: body, started: started, release: release})
		uploadDone <- uploadErr
	}()
	<-started
	reconcileDone := make(chan error, 1)
	go func() {
		_, reconcileErr := service.ReconcileBatch(context.Background(), postgres.AttachmentReconcileCursor{}, 10)
		reconcileDone <- reconcileErr
	}()
	time.Sleep(20 * time.Millisecond)
	repository.mu.Lock()
	beginCallsBeforePublish := repository.beginCalls
	repository.mu.Unlock()
	if beginCallsBeforePublish != 0 {
		t.Fatal("reaper fenced an in-process publication before its filesystem operation completed")
	}
	close(release)
	if err := <-uploadDone; err != nil {
		t.Fatal(err)
	}
	if err := <-reconcileDone; err != nil {
		t.Fatal(err)
	}
	if err := service.store.Verify(PublishedBlob{StoragePath: want.StoragePath, SizeBytes: want.SizeBytes, SHA256: want.SHA256}); err != nil {
		t.Fatalf("stale reconciliation deleted committed READY bytes: %v", err)
	}
}

func TestServiceMarksMissingReadyBlobCorrupt(t *testing.T) {
	digest := sha256.Sum256([]byte("missing"))
	repository := &fakeRepository{candidates: []postgres.AttachmentReconcileCandidate{{ArtifactID: testArtifactID, State: postgres.AttachmentReady, ExpiresAt: time.Unix(200, 0), StoragePath: "ready/" + testArtifactID + ".blob", SizeBytes: 7, SHA256: digest, CurrentTimeline: true}}}
	service := newTestService(t, repository)
	if _, err := service.ReconcileBatch(context.Background(), postgres.AttachmentReconcileCursor{}, 10); err != nil {
		t.Fatal(err)
	}
	if len(repository.markCorruptCalls) != 1 || repository.markCorruptCalls[0] != testArtifactID {
		t.Fatalf("corrupt calls=%v", repository.markCorruptCalls)
	}
}

func newTestService(t *testing.T, repository Repository) *Service {
	t.Helper()
	store, err := OpenBlobStore(privateBlobRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(repository, store)
	if err != nil {
		t.Fatal(err)
	}
	return service
}
