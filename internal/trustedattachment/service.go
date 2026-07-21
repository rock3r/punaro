package trustedattachment

import (
	"context"
	"errors"
	"hash/fnv"
	"io"
	"time"

	"github.com/rock3r/punaro/internal/postgres"
)

const (
	maxConcurrentDownloads = 16
	maxDownloadLifetime    = 10 * time.Minute
)

// Repository is the narrow trusted attachment lifecycle and authorization
// surface. Recipient grants themselves are created only by mail append.
type Repository interface {
	ClaimAttachmentUpload(context.Context, string, string, time.Duration) (postgres.AttachmentClaim, error)
	PublishAttachment(context.Context, postgres.AttachmentPublishRequest) (postgres.AttachmentArtifact, error)
	AttachmentReconcileCandidates(context.Context, postgres.AttachmentReconcileCursor, int) ([]postgres.AttachmentReconcileCandidate, postgres.AttachmentReconcileCursor, error)
	MarkAttachmentCorrupt(context.Context, string) (bool, error)
	BeginAttachmentReap(context.Context, string) (string, bool, error)
	ReleaseExpiredAttachment(context.Context, string, string) (bool, error)
	AuthorizeAttachmentDownload(context.Context, postgres.AttachmentDownloadRequest) (postgres.AttachmentDownload, error)
	DeleteAttachment(context.Context, postgres.AttachmentDeleteRequest) (postgres.AttachmentDeletion, error)
	BeginAttachmentPhysicalGC(context.Context) (func() error, bool, error)
	ClaimAttachmentGC(context.Context, string, time.Duration) (postgres.AttachmentGCClaim, bool, error)
	FinalizeAttachmentGC(context.Context, string, int64, string) (postgres.AttachmentDeletion, bool, error)
	AttachmentOrphanGCAllowed(context.Context, string) (bool, error)
}

// DownloadWriter is a destination whose blocked writes can be interrupted.
// HTTP adapters should implement SetWriteDeadline with http.ResponseController;
// raw transports can provide net.Conn directly.
type DownloadWriter interface {
	io.Writer
	SetWriteDeadline(time.Time) error
}

// Download authorizes one current recipient principal under the artifact lock,
// verifies the complete immutable file before output, and emits exactly the
// recorded byte count.
func (service *Service) Download(ctx context.Context, request postgres.AttachmentDownloadRequest, destination DownloadWriter) (postgres.AttachmentDownload, error) {
	return service.DownloadPrepared(ctx, request, destination, nil)
}

// DownloadPrepared invokes prepare with the authorized immutable metadata
// after every authority and shape check but before the first response byte.
// Network adapters use this hook to commit exact integrity headers without
// opening a second authorization race.
func (service *Service) DownloadPrepared(ctx context.Context, request postgres.AttachmentDownloadRequest, destination DownloadWriter, prepare func(postgres.AttachmentDownload) error) (postgres.AttachmentDownload, error) {
	if service == nil || destination == nil || request.Validate() != nil {
		return postgres.AttachmentDownload{}, errors.New("invalid trusted attachment download")
	}
	downloadCtx, cancel := context.WithTimeout(ctx, service.downloadLifetime)
	defer cancel()
	stopWriteDeadline, err := armDownloadWriteDeadline(downloadCtx, destination)
	if err != nil {
		return postgres.AttachmentDownload{}, err
	}
	defer stopWriteDeadline()
	select {
	case service.downloadSlots <- struct{}{}:
		defer func() { <-service.downloadSlots }()
	case <-downloadCtx.Done():
		return postgres.AttachmentDownload{}, downloadCtx.Err()
	}
	unlock, err := service.lockArtifact(downloadCtx, request.ArtifactID)
	if err != nil {
		return postgres.AttachmentDownload{}, err
	}
	defer func() { _ = unlock() }()
	download, err := service.repository.AuthorizeAttachmentDownload(downloadCtx, request)
	if err != nil {
		return postgres.AttachmentDownload{}, err
	}
	if download.ArtifactID != request.ArtifactID || download.StoragePath != "ready/"+download.ArtifactID+".blob" {
		return postgres.AttachmentDownload{}, errors.New("trusted attachment download authority is malformed")
	}
	if prepare != nil {
		if err := prepare(download); err != nil {
			return postgres.AttachmentDownload{}, err
		}
	}
	if err := service.store.StreamVerified(downloadCtx, PublishedBlob{StoragePath: download.StoragePath, SizeBytes: download.SizeBytes, SHA256: download.SHA256}, destination); err != nil {
		if downloadCtx.Err() != nil {
			return postgres.AttachmentDownload{}, downloadCtx.Err()
		}
		return postgres.AttachmentDownload{}, err
	}
	return download, nil
}

// Delete commits the authorization-checked tombstone while holding the same
// artifact lock used by download and publication. It deliberately leaves the
// immutable bytes in place for the backup/restore safety window.
func (service *Service) Delete(ctx context.Context, request postgres.AttachmentDeleteRequest) (postgres.AttachmentDeletion, error) {
	if service == nil || request.Validate() != nil {
		return postgres.AttachmentDeletion{}, errors.New("invalid trusted attachment deletion")
	}
	unlock, err := service.lockArtifact(ctx, request.ArtifactID)
	if err != nil {
		return postgres.AttachmentDeletion{}, err
	}
	defer func() { _ = unlock() }()
	deletion, err := service.repository.DeleteAttachment(ctx, request)
	if err != nil {
		return postgres.AttachmentDeletion{}, err
	}
	if deletion.ArtifactID != request.ArtifactID || deletion.StoragePath != "ready/"+request.ArtifactID+".blob" ||
		(deletion.State != postgres.AttachmentTombstoned && deletion.State != postgres.AttachmentGCClaimed && deletion.State != postgres.AttachmentDeleted) {
		return postgres.AttachmentDeletion{}, errors.New("trusted attachment deletion result is malformed")
	}
	return deletion, nil
}

// GarbageCollect claims one post-cutoff tombstone, durably removes its exact
// final and private stages, then conditionally releases quota. A crash after
// unlink is safe because removal and the token-fenced finalization are both
// idempotent.
func (service *Service) GarbageCollect(ctx context.Context, artifactID string, claimLifetime time.Duration) (postgres.AttachmentDeletion, bool, error) {
	if service == nil {
		return postgres.AttachmentDeletion{}, false, errors.New("trusted attachment service is unavailable")
	}
	unlock, err := service.lockArtifact(ctx, artifactID)
	if err != nil {
		return postgres.AttachmentDeletion{}, false, err
	}
	defer func() { _ = unlock() }()
	return service.garbageCollectLocked(ctx, artifactID, claimLifetime)
}

func (service *Service) garbageCollectLocked(ctx context.Context, artifactID string, claimLifetime time.Duration) (postgres.AttachmentDeletion, bool, error) {
	releaseFence, permitted, err := service.repository.BeginAttachmentPhysicalGC(ctx)
	if err != nil || !permitted {
		return postgres.AttachmentDeletion{}, false, err
	}
	defer func() { _ = releaseFence() }()
	claim, claimed, err := service.repository.ClaimAttachmentGC(ctx, artifactID, claimLifetime)
	if err != nil || !claimed {
		return postgres.AttachmentDeletion{}, false, err
	}
	if claim.ArtifactID != artifactID || claim.State != postgres.AttachmentGCClaimed || claim.GCGeneration < 1 || claim.GCToken == "" ||
		claim.StoragePath != "ready/"+artifactID+".blob" {
		return postgres.AttachmentDeletion{}, false, errors.New("trusted attachment GC claim is malformed")
	}
	if err := service.store.RemoveDeleted(PublishedBlob{StoragePath: claim.StoragePath, SizeBytes: claim.SizeBytes, SHA256: claim.SHA256}); err != nil {
		return postgres.AttachmentDeletion{}, false, err
	}
	deletion, finalized, err := service.repository.FinalizeAttachmentGC(ctx, artifactID, claim.GCGeneration, claim.GCToken)
	if err != nil && ctx.Err() == nil && retryAmbiguousPublication(err) {
		// The exact generation/token retry closes the commit-succeeded/response-
		// lost window without allowing a stale worker to release quota.
		deletion, finalized, err = service.repository.FinalizeAttachmentGC(ctx, artifactID, claim.GCGeneration, claim.GCToken)
	}
	if err != nil || !finalized {
		return postgres.AttachmentDeletion{}, false, err
	}
	if deletion.ArtifactID != artifactID || deletion.State != postgres.AttachmentDeleted || deletion.GCGeneration != claim.GCGeneration || deletion.StoragePath != claim.StoragePath {
		return postgres.AttachmentDeletion{}, false, errors.New("trusted attachment GC result is malformed")
	}
	return deletion, true, nil
}

func armDownloadWriteDeadline(ctx context.Context, destination DownloadWriter) (func(), error) {
	_, found := ctx.Deadline()
	if !found {
		return nil, errors.New("trusted attachment download deadline is unavailable")
	}
	// Prove deadline support up front, then let context cancellation apply the
	// interrupt. Setting the transport to the exact context timestamp can make
	// a write fail just before the context timer records DeadlineExceeded.
	if err := destination.SetWriteDeadline(time.Time{}); err != nil {
		return nil, errors.New("trusted attachment download destination is not interruptible")
	}
	stopped := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		select {
		case <-ctx.Done():
			_ = destination.SetWriteDeadline(time.Now())
		case <-stopped:
		}
	}()
	return func() {
		close(stopped)
		<-finished
		_ = destination.SetWriteDeadline(time.Time{})
	}, nil
}

// Service coordinates database authority with private durable publication.
// A filesystem final remains hidden until PublishAttachment commits READY.
type Service struct {
	repository       Repository
	store            *BlobStore
	locks            [64]chan struct{}
	downloadSlots    chan struct{}
	downloadLifetime time.Duration
}

// NewService binds lifecycle authority to one verified private blob store.
func NewService(repository Repository, store *BlobStore) (*Service, error) {
	if repository == nil || store == nil {
		return nil, errors.New("trusted attachment service dependencies are unavailable")
	}
	service := &Service{repository: repository, store: store, downloadSlots: make(chan struct{}, maxConcurrentDownloads), downloadLifetime: maxDownloadLifetime}
	for index := range service.locks {
		service.locks[index] = make(chan struct{}, 1)
	}
	return service, nil
}

// Upload consumes one bounded stream under a fresh claim, durably publishes
// its exact bytes, then conditionally commits READY under current authority.
func (service *Service) Upload(ctx context.Context, device postgres.AuthenticatedDevice, artifactID string, claimLifetime time.Duration, source io.Reader) (postgres.AttachmentArtifact, error) {
	if service == nil || source == nil {
		return postgres.AttachmentArtifact{}, errors.New("invalid trusted attachment upload")
	}
	unlock, err := service.lockArtifact(ctx, artifactID)
	if err != nil {
		return postgres.AttachmentArtifact{}, err
	}
	defer func() { _ = unlock() }()
	claim, err := service.repository.ClaimAttachmentUpload(ctx, device.PrincipalID, artifactID, claimLifetime)
	if err != nil {
		return postgres.AttachmentArtifact{}, err
	}
	blob, err := service.store.Publish(ctx, UploadClaim{ArtifactID: claim.ArtifactID, AttemptGeneration: claim.AttemptGeneration, SizeBytes: claim.SizeBytes, SHA256: claim.SHA256}, source)
	if err != nil {
		return postgres.AttachmentArtifact{}, err
	}
	request := postgres.AttachmentPublishRequest{
		PrincipalID:          device.PrincipalID,
		CredentialLookupID:   device.LookupID,
		CredentialGeneration: device.Generation,
		ArtifactID:           claim.ArtifactID,
		AttemptGeneration:    claim.AttemptGeneration,
		ClaimToken:           claim.ClaimToken,
		StoragePath:          blob.StoragePath,
		SizeBytes:            blob.SizeBytes,
		SHA256:               blob.SHA256,
	}
	artifact, err := service.repository.PublishAttachment(ctx, request)
	if err != nil && ctx.Err() == nil && retryAmbiguousPublication(err) {
		// One exact retry closes the commit-succeeded/response-lost window. The
		// database function revalidates current authorization on this retry.
		artifact, err = service.repository.PublishAttachment(ctx, request)
	}
	if err != nil {
		return postgres.AttachmentArtifact{}, err
	}
	if artifact.ArtifactID != claim.ArtifactID || artifact.StoragePath != blob.StoragePath || artifact.SizeBytes != blob.SizeBytes || artifact.SHA256 != blob.SHA256 || artifact.State != postgres.AttachmentReady {
		return postgres.AttachmentArtifact{}, errors.New("trusted attachment READY result does not match durable blob")
	}
	if err := service.store.RemoveStages(claim.ArtifactID); err != nil {
		// READY is already committed and durable. Reconciliation retries stage
		// retirement; callers must still receive the authoritative artifact.
		return artifact, nil
	}
	return artifact, nil
}

// ReconcileResult describes one bounded, cursor-addressable recovery pass.
type ReconcileResult struct {
	Scanned int
	Changed int
	Next    postgres.AttachmentReconcileCursor
}

// OrphanReconcileResult describes one bounded deterministic filesystem-only
// skew scan. A changed page restarts from the beginning on the next call.
type OrphanReconcileResult struct {
	Scanned int
	Changed int
	Next    string
}

// ReconcileOrphanBatch removes only UUID namespaces older than grace whose
// authoritative database absence and backup-fence permission are rechecked
// under the cross-process artifact lock.
func (service *Service) ReconcileOrphanBatch(ctx context.Context, after string, limit int, grace time.Duration) (OrphanReconcileResult, error) {
	if service == nil || grace < time.Hour || grace > 30*24*time.Hour {
		return OrphanReconcileResult{}, errors.New("invalid attachment orphan reconciliation")
	}
	candidates, next, err := service.store.OrphanCandidates(after, time.Now().Add(-grace), limit)
	if err != nil {
		return OrphanReconcileResult{}, err
	}
	result := OrphanReconcileResult{Scanned: len(candidates), Next: next}
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return OrphanReconcileResult{}, err
		}
		unlock, err := service.lockArtifact(ctx, candidate.ArtifactID)
		if err != nil {
			return OrphanReconcileResult{}, err
		}
		releaseFence, permitted, authorityErr := service.repository.BeginAttachmentPhysicalGC(ctx)
		if authorityErr == nil && permitted {
			allowed, allowedErr := service.repository.AttachmentOrphanGCAllowed(ctx, candidate.ArtifactID)
			authorityErr = allowedErr
			if authorityErr == nil && allowed {
				authorityErr = service.store.RemoveUnpublished(candidate.ArtifactID)
				if authorityErr == nil {
					result.Changed++
				}
			}
			if releaseErr := releaseFence(); authorityErr == nil {
				authorityErr = releaseErr
			}
		}
		unlockErr := unlock()
		if authorityErr != nil {
			return OrphanReconcileResult{}, authorityErr
		}
		if unlockErr != nil {
			return OrphanReconcileResult{}, unlockErr
		}
	}
	if result.Changed != 0 {
		result.Next = ""
	}
	return result, nil
}

// ReconcileBatch repairs only M-10 publication invariants: READY bytes are
// verified, and expired or restored-timeline RESERVED bytes are removed before
// their quota is released. CORRUPT retention belongs to the later lifecycle.
func (service *Service) ReconcileBatch(ctx context.Context, cursor postgres.AttachmentReconcileCursor, limit int) (ReconcileResult, error) {
	if service == nil {
		return ReconcileResult{}, errors.New("trusted attachment service is unavailable")
	}
	candidates, next, err := service.repository.AttachmentReconcileCandidates(ctx, cursor, limit)
	if err != nil {
		return ReconcileResult{}, err
	}
	result := ReconcileResult{Scanned: len(candidates), Next: next}
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return ReconcileResult{}, err
		}
		changed, candidateErr := service.reconcileCandidate(ctx, candidate)
		if candidateErr != nil {
			return ReconcileResult{}, candidateErr
		}
		if changed {
			result.Changed++
		}
	}
	if result.Changed != 0 {
		// State-changing passes restart from the beginning so an artifact which
		// moved between lifecycle orderings cannot be skipped by a stale cursor.
		result.Next = postgres.AttachmentReconcileCursor{}
	}
	return result, nil
}

func (service *Service) reconcileCandidate(ctx context.Context, candidate postgres.AttachmentReconcileCandidate) (bool, error) {
	unlock, err := service.lockArtifact(ctx, candidate.ArtifactID)
	if err != nil {
		return false, err
	}
	defer func() { _ = unlock() }()
	switch candidate.State {
	case postgres.AttachmentReady:
		if err := service.store.RemoveStages(candidate.ArtifactID); err != nil {
			return false, err
		}
		blob := PublishedBlob{StoragePath: candidate.StoragePath, SizeBytes: candidate.SizeBytes, SHA256: candidate.SHA256}
		if service.store.Verify(blob) == nil {
			return false, nil
		}
		marked, markErr := service.repository.MarkAttachmentCorrupt(ctx, candidate.ArtifactID)
		if markErr != nil {
			return false, markErr
		}
		return marked, nil
	case postgres.AttachmentReserved:
		cleanupToken, fenced, fenceErr := service.repository.BeginAttachmentReap(ctx, candidate.ArtifactID)
		if fenceErr != nil {
			return false, fenceErr
		}
		if !fenced {
			return false, nil
		}
		candidate.CleanupToken = cleanupToken
		fallthrough
	case postgres.AttachmentReaping:
		if err := service.store.RemoveUnpublished(candidate.ArtifactID); err != nil {
			return false, err
		}
		released, releaseErr := service.repository.ReleaseExpiredAttachment(ctx, candidate.ArtifactID, candidate.CleanupToken)
		if releaseErr != nil {
			return false, releaseErr
		}
		return released, nil
	case postgres.AttachmentCorrupt:
		_, finalized, gcErr := service.garbageCollectLocked(ctx, candidate.ArtifactID, time.Minute)
		return finalized, gcErr
	default:
		return false, errors.New("trusted attachment reconciliation state is invalid")
	}
}

func (service *Service) lockArtifact(ctx context.Context, artifactID string) (func() error, error) {
	hasher := fnv.New64a()
	_, _ = hasher.Write([]byte(artifactID))
	lock := service.locks[hasher.Sum64()%uint64(len(service.locks))]
	select {
	case lock <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	fileUnlock, err := service.store.LockArtifact(ctx, artifactID)
	if err != nil {
		<-lock
		return nil, err
	}
	return func() error {
		err := fileUnlock()
		<-lock
		return err
	}, nil
}

func retryAmbiguousPublication(err error) bool {
	return !errors.Is(err, postgres.ErrForbidden) &&
		!errors.Is(err, postgres.ErrIdempotencyConflict) &&
		!errors.Is(err, postgres.ErrAttachmentQuota) &&
		!errors.Is(err, postgres.ErrAttachmentBusy) &&
		!errors.Is(err, postgres.ErrAttachmentStale) &&
		!errors.Is(err, postgres.ErrMaintenance)
}
