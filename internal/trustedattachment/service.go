package trustedattachment

import (
	"context"
	"errors"
	"hash/fnv"
	"io"
	"sync"
	"time"

	"github.com/rock3r/punaro/internal/postgres"
)

// Repository is the narrow schema-v10 lifecycle surface. It deliberately has
// no download, recipient-grant, or sharing operation.
type Repository interface {
	ClaimAttachmentUpload(context.Context, string, string, time.Duration) (postgres.AttachmentClaim, error)
	PublishAttachment(context.Context, postgres.AttachmentPublishRequest) (postgres.AttachmentArtifact, error)
	AttachmentReconcileCandidates(context.Context, postgres.AttachmentReconcileCursor, int) ([]postgres.AttachmentReconcileCandidate, postgres.AttachmentReconcileCursor, error)
	MarkAttachmentCorrupt(context.Context, string) (bool, error)
	BeginAttachmentReap(context.Context, string) (string, bool, error)
	ReleaseExpiredAttachment(context.Context, string, string) (bool, error)
}

// Service coordinates database authority with private durable publication.
// A filesystem final remains hidden until PublishAttachment commits READY.
type Service struct {
	repository Repository
	store      *BlobStore
	locks      [64]sync.Mutex
}

// NewService binds lifecycle authority to one verified private blob store.
func NewService(repository Repository, store *BlobStore) (*Service, error) {
	if repository == nil || store == nil {
		return nil, errors.New("trusted attachment service dependencies are unavailable")
	}
	return &Service{repository: repository, store: store}, nil
}

// Upload consumes one bounded stream under a fresh claim, durably publishes
// its exact bytes, then conditionally commits READY under current authority.
func (service *Service) Upload(ctx context.Context, principalID, artifactID string, claimLifetime time.Duration, source io.Reader) (postgres.AttachmentArtifact, error) {
	if service == nil || source == nil {
		return postgres.AttachmentArtifact{}, errors.New("invalid trusted attachment upload")
	}
	unlock, err := service.lockArtifact(ctx, artifactID)
	if err != nil {
		return postgres.AttachmentArtifact{}, err
	}
	defer func() { _ = unlock() }()
	claim, err := service.repository.ClaimAttachmentUpload(ctx, principalID, artifactID, claimLifetime)
	if err != nil {
		return postgres.AttachmentArtifact{}, err
	}
	blob, err := service.store.Publish(ctx, UploadClaim{ArtifactID: claim.ArtifactID, AttemptGeneration: claim.AttemptGeneration, SizeBytes: claim.SizeBytes, SHA256: claim.SHA256}, source)
	if err != nil {
		return postgres.AttachmentArtifact{}, err
	}
	request := postgres.AttachmentPublishRequest{
		PrincipalID:       principalID,
		ArtifactID:        claim.ArtifactID,
		AttemptGeneration: claim.AttemptGeneration,
		ClaimToken:        claim.ClaimToken,
		StoragePath:       blob.StoragePath,
		SizeBytes:         blob.SizeBytes,
		SHA256:            blob.SHA256,
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
		return postgres.AttachmentArtifact{}, errors.New("trusted attachment READY staging cleanup failed")
	}
	return artifact, nil
}

// ReconcileResult describes one bounded, cursor-addressable recovery pass.
type ReconcileResult struct {
	Scanned int
	Changed int
	Next    postgres.AttachmentReconcileCursor
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
		// M-10 detects and records corruption but exposes no deletion API.
		return false, nil
	default:
		return false, errors.New("trusted attachment reconciliation state is invalid")
	}
}

func (service *Service) lockArtifact(ctx context.Context, artifactID string) (func() error, error) {
	hasher := fnv.New64a()
	_, _ = hasher.Write([]byte(artifactID))
	lock := &service.locks[hasher.Sum64()%uint64(len(service.locks))]
	lock.Lock()
	fileUnlock, err := service.store.LockArtifact(ctx, artifactID)
	if err != nil {
		lock.Unlock()
		return nil, err
	}
	return func() error {
		err := fileUnlock()
		lock.Unlock()
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
