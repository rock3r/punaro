package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"math"
	"time"
)

const (
	maxMemoryEmbeddingSourceBytes     = 256 << 10
	memoryEmbeddingPublicationReserve = time.Second
)

// MemoryEmbeddingSourceChunk is bounded canonical text supplied to a provider.
type MemoryEmbeddingSourceChunk struct {
	Ordinal                int
	ContentSHA256          string
	StartOffset, EndOffset int
	Text                   string
}

// MemoryEmbeddingProvider generates one vector for each supplied source chunk.
type MemoryEmbeddingProvider interface {
	Embed(context.Context, MemoryEmbeddingGeneration, []MemoryEmbeddingSourceChunk) ([][]float64, error)
}
type memoryEmbeddingExecutorStore interface {
	ClaimMemoryEmbeddingWork(context.Context, MemoryEmbeddingClaimRequest) ([]MemoryEmbeddingLease, error)
	PublishMemoryEmbeddingWork(context.Context, MemoryEmbeddingPublication) error
	RetryMemoryEmbeddingWork(context.Context, MemoryEmbeddingRetry) error
}

// MemoryEmbeddingSource materializes only a live, fenced lease coordinate.
type MemoryEmbeddingSource interface {
	OpenMemoryEmbeddingSource(context.Context, MemoryEmbeddingLease) (MemoryEmbeddingGeneration, []MemoryEmbeddingSourceChunk, func(), error)
}

// MemoryEmbeddingExecutor claims, embeds, and fence-publishes bounded work.
type MemoryEmbeddingExecutor struct {
	store    memoryEmbeddingExecutorStore
	source   MemoryEmbeddingSource
	provider MemoryEmbeddingProvider
}

// MemoryEmbeddingExecutionResult reports one bounded executor pass.
type MemoryEmbeddingExecutionResult struct{ Claimed, Published, Retried int }

// LoadMemoryEmbeddingSource reads only the exact, live lease coordinate. It
// returns one bounded canonical-document chunk; later chunking policies can
// refine this derived boundary without changing the lease fence.
func (d *Database) LoadMemoryEmbeddingSource(ctx context.Context, lease MemoryEmbeddingLease) (MemoryEmbeddingGeneration, []MemoryEmbeddingSourceChunk, error) {
	return d.loadMemoryEmbeddingSource(ctx, d.db, lease)
}

// OpenMemoryEmbeddingSource holds the item fence until its returned release
// function runs, preventing a quarantine transition from racing provider use.
func (d *Database) OpenMemoryEmbeddingSource(ctx context.Context, lease MemoryEmbeddingLease) (MemoryEmbeddingGeneration, []MemoryEmbeddingSourceChunk, func(), error) {
	// The fence must survive cancellation of the worker operation: the provider
	// can still unwind after its context is cancelled, and its source must remain
	// protected until executeLease calls release.
	conn, err := d.embeddingPool().Conn(ctx)
	if err != nil {
		return MemoryEmbeddingGeneration{}, nil, nil, errors.New("memory embedding source is unavailable")
	}
	if _, err := conn.ExecContext(ctx, "BEGIN READ ONLY"); err != nil {
		_ = conn.Close()
		return MemoryEmbeddingGeneration{}, nil, nil, errors.New("memory embedding source is unavailable")
	}
	release := func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), operationTimeout)
		defer cancel()
		_, _ = conn.ExecContext(cleanupCtx, "ROLLBACK")
		_ = conn.Close()
	}
	// Acquisition follows the worker context so a blocked advisory lock does not
	// outlive a cancelled pass. Once acquired, the transaction remains bound to
	// fenceCtx until release so cancellation cannot drop the provider fence.
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text, 801337))`, lease.ItemID); err != nil {
		release()
		return MemoryEmbeddingGeneration{}, nil, nil, errors.New("memory embedding source is unavailable")
	}
	generation, chunks, err := d.loadMemoryEmbeddingSource(ctx, conn, lease)
	if err != nil {
		if errors.Is(err, ErrMemoryEmbeddingQuarantined) {
			return MemoryEmbeddingGeneration{}, nil, release, err
		}
		release()
		return MemoryEmbeddingGeneration{}, nil, nil, err
	}
	return generation, chunks, release, nil
}

func (d *Database) embeddingPool() *sql.DB {
	if d.embeddingDB != nil {
		return d.embeddingDB
	}
	return d.db
}

func (d *Database) loadMemoryEmbeddingSource(ctx context.Context, q queryer, lease MemoryEmbeddingLease) (MemoryEmbeddingGeneration, []MemoryEmbeddingSourceChunk, error) {
	if !lease.valid() {
		return MemoryEmbeddingGeneration{}, nil, errors.New("invalid memory embedding lease")
	}
	digest, _ := hex.DecodeString(lease.ContentSHA256)
	var generation MemoryEmbeddingGeneration
	var document []byte
	var storedHash sql.NullString
	var quarantined bool
	err := q.QueryRowContext(ctx, `SELECT generation.id::text,generation.model,generation.model_revision,generation.dimensions,generation.state,revision.document,encode(revision.content_sha256,'hex'),quarantine.active
FROM brain.embedding_jobs AS job
JOIN brain.embedding_generations AS generation ON generation.id=job.generation_id
JOIN brain.memory_items AS item ON item.id=job.item_id AND item.current_revision=job.revision
CROSS JOIN LATERAL (SELECT EXISTS (SELECT 1 FROM brain.memory_quarantines AS record WHERE record.item_id=job.item_id AND record.released_at IS NULL) AS active) AS quarantine
LEFT JOIN brain.memory_revisions AS revision ON revision.item_id=job.item_id AND revision.revision=job.revision AND NOT quarantine.active
WHERE job.generation_id=$1 AND job.item_id=$2 AND job.revision=$3 AND job.content_sha256=$4
	AND job.state='running' AND job.lease_token=$5 AND job.lease_generation=$6 AND job.lease_until>statement_timestamp()`, lease.GenerationID, lease.ItemID, lease.Revision, digest, lease.Token, lease.LeaseGeneration).Scan(&generation.ID, &generation.Model, &generation.Revision, &generation.Dimensions, &generation.State, &document, &storedHash, &quarantined)
	if errors.Is(err, sql.ErrNoRows) {
		return MemoryEmbeddingGeneration{}, nil, ErrStaleEmbeddingLease
	}
	if err != nil {
		return MemoryEmbeddingGeneration{}, nil, errors.New("memory embedding source is unavailable")
	}
	if quarantined {
		return MemoryEmbeddingGeneration{}, nil, ErrMemoryEmbeddingQuarantined
	}
	documentHash := sha256.Sum256(document)
	if generation.Validate() != nil || len(document) == 0 || len(document) > maxMemoryEmbeddingSourceBytes || !storedHash.Valid || hex.EncodeToString(documentHash[:]) != storedHash.String || storedHash.String != lease.ContentSHA256 {
		return MemoryEmbeddingGeneration{}, nil, errors.New("memory embedding source is invalid")
	}
	chunkHash := sha256.Sum256(document)
	return generation, []MemoryEmbeddingSourceChunk{{Ordinal: 0, ContentSHA256: hex.EncodeToString(chunkHash[:]), StartOffset: 0, EndOffset: len(document), Text: string(document)}}, nil
}

// NewMemoryEmbeddingExecutor constructs a bounded provider-agnostic executor.
func NewMemoryEmbeddingExecutor(store memoryEmbeddingExecutorStore, source MemoryEmbeddingSource, provider MemoryEmbeddingProvider) (*MemoryEmbeddingExecutor, error) {
	if store == nil || source == nil || provider == nil {
		return nil, errors.New("memory embedding executor is invalid")
	}
	return &MemoryEmbeddingExecutor{store: store, source: source, provider: provider}, nil
}

// Execute claims and processes at most the request's bounded lease batch.
func (e *MemoryEmbeddingExecutor) Execute(ctx context.Context, request MemoryEmbeddingClaimRequest) (MemoryEmbeddingExecutionResult, error) {
	var err error
	request, err = request.normalized()
	if err != nil {
		return MemoryEmbeddingExecutionResult{}, err
	}
	result := MemoryEmbeddingExecutionResult{}
	for claimed := 0; claimed < request.Limit; claimed++ {
		one := request
		one.Limit = 1
		leases, err := e.store.ClaimMemoryEmbeddingWork(ctx, one)
		if err != nil {
			return result, err
		}
		if len(leases) == 0 {
			break
		}
		result.Claimed++
		lease := leases[0]
		if err := e.executeLease(ctx, lease, &result); err != nil {
			return result, err
		}
	}
	return result, nil
}

func (e *MemoryEmbeddingExecutor) executeLease(ctx context.Context, lease MemoryEmbeddingLease, result *MemoryEmbeddingExecutionResult) error {
	var generation MemoryEmbeddingGeneration
	var chunks []MemoryEmbeddingSourceChunk
	var release func()
	var loadErr error
	leaseDeadline := lease.LeaseUntil.Add(-memoryEmbeddingPublicationReserve)
	sourceCtx, cancelSource := context.WithDeadline(ctx, leaseDeadline)
	defer cancelSource()
	generation, chunks, release, loadErr = e.source.OpenMemoryEmbeddingSource(sourceCtx, lease)
	if loadErr == nil && release == nil {
		loadErr = errors.New("memory embedding source fence is unavailable")
	}
	if release != nil {
		defer release()
	}
	if loadErr != nil {
		switch {
		case errors.Is(loadErr, ErrMemoryEmbeddingQuarantined):
			if err := e.retry(ctx, lease, "quarantined", result); err != nil {
				return err
			}
		case !time.Now().Before(leaseDeadline):
			// A held advisory fence can outlive this lease while a quarantine
			// writer is still uncommitted. Leave the running lease for safe
			// expiry/reclamation rather than terminally retrying it blind.
			return nil
		case !errors.Is(loadErr, ErrStaleEmbeddingLease):
			if err := e.retry(ctx, lease, "source_unavailable", result); err != nil {
				return err
			}
		}
		return nil
	}
	if !validMemoryEmbeddingSource(lease, generation, chunks) {
		if err := e.retry(ctx, lease, "provider_invalid", result); err != nil {
			return err
		}
		return nil
	}
	providerChunks := append([]MemoryEmbeddingSourceChunk(nil), chunks...)
	vectors, embedErr := e.provider.Embed(sourceCtx, generation, providerChunks)
	if embedErr != nil {
		if err := e.retry(ctx, lease, "provider_unavailable", result); err != nil {
			return err
		}
		return nil
	}
	if len(vectors) != len(chunks) {
		if err := e.retry(ctx, lease, "provider_invalid", result); err != nil {
			return err
		}
		return nil
	}
	publication := MemoryEmbeddingPublication{Lease: lease, Chunks: make([]MemoryEmbeddingChunk, len(chunks))}
	valid := generation.Validate() == nil
	for i, chunk := range chunks {
		publication.Chunks[i] = MemoryEmbeddingChunk{Ordinal: chunk.Ordinal, ContentSHA256: chunk.ContentSHA256, StartOffset: chunk.StartOffset, EndOffset: chunk.EndOffset, Vector: vectors[i]}
		valid = valid && validMemoryEmbeddingVector(vectors[i], generation.Dimensions)
	}
	if !valid || publication.Validate() != nil {
		if err := e.retry(ctx, lease, "provider_invalid", result); err != nil {
			return err
		}
		return nil
	}
	publicationCtx, cancelPublication := context.WithDeadline(ctx, lease.LeaseUntil)
	defer cancelPublication()
	if err := e.store.PublishMemoryEmbeddingWork(publicationCtx, publication); err == nil {
		result.Published++
	} else if !errors.Is(err, ErrStaleEmbeddingLease) {
		if err := e.retry(ctx, lease, "publish_unavailable", result); err != nil {
			return err
		}
	}
	return nil
}

func validMemoryEmbeddingVector(vector []float64, dimensions int) bool {
	if len(vector) != dimensions {
		return false
	}
	normSquared := 0.0
	for _, value := range vector {
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return false
		}
		normSquared += value * value
	}
	return normSquared > 0 && !math.IsInf(normSquared, 0)
}

func validMemoryEmbeddingSource(lease MemoryEmbeddingLease, generation MemoryEmbeddingGeneration, chunks []MemoryEmbeddingSourceChunk) bool {
	if lease.Generation.Validate() != nil || generation != lease.Generation || generation.ID != lease.GenerationID || len(chunks) < 1 || len(chunks) > maxMemoryEmbeddingChunks {
		return false
	}
	end := 0
	document := make([]byte, 0, maxMemoryEmbeddingSourceBytes)
	for ordinal, chunk := range chunks {
		if chunk.Ordinal != ordinal || chunk.StartOffset != end || chunk.EndOffset <= chunk.StartOffset || chunk.EndOffset > maxMemoryEmbeddingSourceBytes || chunk.EndOffset-chunk.StartOffset != len(chunk.Text) {
			return false
		}
		digest := sha256.Sum256([]byte(chunk.Text))
		if chunk.ContentSHA256 != hex.EncodeToString(digest[:]) {
			return false
		}
		end = chunk.EndOffset
		document = append(document, chunk.Text...)
	}
	digest := sha256.Sum256(document)
	return hex.EncodeToString(digest[:]) == lease.ContentSHA256
}

func (e *MemoryEmbeddingExecutor) retry(ctx context.Context, lease MemoryEmbeddingLease, code string, result *MemoryEmbeddingExecutionResult) error {
	retryCtx, cancel := context.WithDeadline(ctx, lease.LeaseUntil)
	defer cancel()
	if err := e.store.RetryMemoryEmbeddingWork(retryCtx, MemoryEmbeddingRetry{Lease: lease, ErrorCode: code, Delay: time.Second}); err != nil {
		if errors.Is(err, ErrStaleEmbeddingLease) {
			return nil
		}
		return err
	}
	result.Retried++
	return nil
}
