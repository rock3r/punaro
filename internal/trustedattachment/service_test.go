package trustedattachment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
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
}

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
