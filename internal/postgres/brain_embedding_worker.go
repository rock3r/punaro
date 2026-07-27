package postgres

import (
	"context"
	"encoding/hex"
	"errors"
	"time"
)

// ErrStaleEmbeddingLease reports that a worker attempted to mutate a lease
// which has expired, been reclaimed, or been superseded by a newer revision.
var ErrStaleEmbeddingLease = errors.New("embedding lease is stale")

// ErrMemoryEmbeddingQuarantined reports that a live lease cannot safely expose
// its canonical content while the item is under an active quarantine.
var ErrMemoryEmbeddingQuarantined = errors.New("memory embedding is quarantined")

// MemoryEmbeddingLease is one exact, content-free worker lease coordinate.
type MemoryEmbeddingLease struct {
	MemoryEmbeddingWork
	// Generation is the immutable model identity observed when this lease was
	// claimed. The executor binds a fenced source to it before provider use.
	Generation      MemoryEmbeddingGeneration
	Attempts        int
	Holder          string
	Token           string
	LeaseGeneration int64
	LeaseUntil      time.Time
}

func (lease MemoryEmbeddingLease) valid() bool {
	return lease.Validate() == nil && lease.Attempts > 0 && lease.Attempts <= 25 &&
		validOpaqueID(lease.Holder) && validOpaqueID(lease.Token) && lease.LeaseGeneration > 0 && !lease.LeaseUntil.IsZero()
}

// MemoryEmbeddingRetry releases a leased coordinate after a bounded delay or
// records a terminal diagnostic when its final attempt has been consumed. The
// quarantined code durably defers work without consuming an attempt.
type MemoryEmbeddingRetry struct {
	Lease     MemoryEmbeddingLease
	ErrorCode string
	Delay     time.Duration
}

func (retry MemoryEmbeddingRetry) valid() bool {
	return retry.Lease.valid() && boundedTokenPattern.MatchString(retry.ErrorCode) && retry.Delay >= 0 && retry.Delay <= time.Hour
}

// ClaimMemoryEmbeddingWork leases content-free, revision-bound work. It has no
// provider interaction and never participates in canonical writes or search.
func (d *Database) ClaimMemoryEmbeddingWork(ctx context.Context, raw MemoryEmbeddingClaimRequest) ([]MemoryEmbeddingLease, error) {
	request, err := raw.normalized()
	if err != nil {
		return nil, err
	}
	tx, err := beginMutation(ctx, d.db)
	if err != nil {
		return nil, mutationStartError(err, "embedding claim transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `SELECT claim.generation_id::text,claim.item_id::text,claim.revision,encode(claim.content_sha256,'hex'),claim.attempts,claim.lease_holder::text,claim.lease_token::text,claim.lease_generation,claim.lease_until,
generation.model,generation.model_revision,generation.dimensions,generation.state
FROM brain.claim_embedding_jobs($1,$2,$3) AS claim
JOIN brain.embedding_generations AS generation ON generation.id=claim.generation_id`, request.WorkerID, request.Limit, request.LeaseDuration.Microseconds())
	if err != nil {
		return nil, errors.New("embedding work could not be claimed")
	}
	defer func() { _ = rows.Close() }()
	leases := make([]MemoryEmbeddingLease, 0, request.Limit)
	for rows.Next() {
		var lease MemoryEmbeddingLease
		var generationState MemoryEmbeddingGenerationState
		if err := rows.Scan(&lease.GenerationID, &lease.ItemID, &lease.Revision, &lease.ContentSHA256, &lease.Attempts, &lease.Holder, &lease.Token, &lease.LeaseGeneration, &lease.LeaseUntil,
			&lease.Generation.Model, &lease.Generation.Revision, &lease.Generation.Dimensions, &generationState); err != nil {
			return nil, errors.New("claimed embedding work is malformed")
		}
		lease.Generation.ID = lease.GenerationID
		lease.Generation.State = generationState
		if !lease.valid() || lease.Generation.Validate() != nil {
			return nil, errors.New("claimed embedding work is malformed")
		}
		leases = append(leases, lease)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("embedding work could not be claimed")
	}
	if err := tx.Commit(); err != nil {
		return nil, errors.New("embedding claim transaction could not commit")
	}
	return leases, nil
}

// RetryMemoryEmbeddingWork conditionally releases a lease for a later attempt.
// The exact revision, hash, token, and generation prevent a stale worker from
// mutating work superseded by a new canonical revision or another claimant.
func (d *Database) RetryMemoryEmbeddingWork(ctx context.Context, retry MemoryEmbeddingRetry) error {
	if !retry.valid() {
		return errors.New("invalid embedding retry")
	}
	digest, _ := hex.DecodeString(retry.Lease.ContentSHA256)
	tx, err := beginMutation(ctx, d.db)
	if err != nil {
		return mutationStartError(err, "embedding retry transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	var changed bool
	err = tx.QueryRowContext(ctx, `SELECT brain.retry_embedding_job($1,$2,$3,$4,$5,$6,$7,$8)`, retry.Lease.GenerationID, retry.Lease.ItemID, retry.Lease.Revision, digest, retry.Lease.Token, retry.Lease.LeaseGeneration, retry.Delay.Microseconds(), retry.ErrorCode).Scan(&changed)
	if err != nil {
		return errors.New("embedding work could not be retried")
	}
	if !changed {
		return ErrStaleEmbeddingLease
	}
	if err := tx.Commit(); err != nil {
		return errors.New("embedding retry transaction could not commit")
	}
	return nil
}
