package postgres

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"time"
)

const (
	maxMemoryEmbeddingDimensions = 4096
	maxMemoryEmbeddingClaimBatch = 32
	maxMemoryEmbeddingChunks     = 64
	memoryEmbeddingMinLease      = 5 * time.Second
	memoryEmbeddingMaxLease      = 5 * time.Minute
)

var memoryEmbeddingRevisionPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:-]{0,63}$`)

// MemoryEmbeddingGenerationState is the closed state for an immutable derived
// generation. M20A introduces a building generation beside the active one;
// later M20 slices add caught-up validation and atomic activation.
type MemoryEmbeddingGenerationState string

const (
	// MemoryEmbeddingGenerationActive accepts work for one pinned model.
	MemoryEmbeddingGenerationActive MemoryEmbeddingGenerationState = "active"
	// MemoryEmbeddingGenerationBuilding receives rebuild work but does not serve
	// semantic retrieval until a later fenced activation slice validates it.
	MemoryEmbeddingGenerationBuilding MemoryEmbeddingGenerationState = "building"
)

// MemoryEmbeddingGeneration pins the non-secret identity and dimensionality of
// derived embedding work. It never carries provider credentials or documents.
type MemoryEmbeddingGeneration struct {
	ID         string
	Model      string
	Revision   string
	Dimensions int
	State      MemoryEmbeddingGenerationState
}

// Validate rejects malformed or unbounded generation metadata before it can
// influence a database request or an embedding provider.
func (g MemoryEmbeddingGeneration) Validate() error {
	if !validOpaqueID(g.ID) || !validMemoryToken(g.Model) || !memoryEmbeddingRevisionPattern.MatchString(g.Revision) ||
		g.Dimensions < 1 || g.Dimensions > maxMemoryEmbeddingDimensions ||
		g.State != MemoryEmbeddingGenerationActive && g.State != MemoryEmbeddingGenerationBuilding {
		return errors.New("invalid memory embedding generation")
	}
	return nil
}

// MemoryEmbeddingWork is the content-free identity fence for one latest
// revision. Later workers must re-read the canonical revision and match every
// coordinate before they can persist derived data.
type MemoryEmbeddingWork struct {
	GenerationID  string
	ItemID        string
	Revision      int64
	ContentSHA256 string
}

// MemoryEmbeddingChunk is revision-bound derived output for one fragment. Its
// vector is bounded worker output, never canonical content or provider state.
type MemoryEmbeddingChunk struct {
	Ordinal       int       `json:"ordinal"`
	ContentSHA256 string    `json:"content_sha256"`
	StartOffset   int       `json:"start_offset"`
	EndOffset     int       `json:"end_offset"`
	Vector        []float64 `json:"embedding"`
}

func (chunk MemoryEmbeddingChunk) valid() bool {
	if chunk.Ordinal < 0 || chunk.StartOffset < 0 || chunk.EndOffset <= chunk.StartOffset || chunk.EndOffset > 262144 || len(chunk.ContentSHA256) != 64 {
		return false
	}
	if len(chunk.Vector) < 1 || len(chunk.Vector) > maxMemoryEmbeddingDimensions {
		return false
	}
	for _, value := range chunk.Vector {
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return false
		}
	}
	digest, err := hex.DecodeString(chunk.ContentSHA256)
	return err == nil && len(digest) == 32 && hex.EncodeToString(digest) == chunk.ContentSHA256
}

// MemoryEmbeddingPublication atomically stores bounded derived coordinates
// and completes the exact lease that produced them.
type MemoryEmbeddingPublication struct {
	Lease  MemoryEmbeddingLease
	Chunks []MemoryEmbeddingChunk
}

// Validate rejects malformed, unbounded, unordered, or overlapping derived
// chunk coordinates before they reach the owner publication routine.
func (publication MemoryEmbeddingPublication) Validate() error {
	if !publication.Lease.valid() || len(publication.Chunks) < 1 || len(publication.Chunks) > maxMemoryEmbeddingChunks {
		return errors.New("invalid embedding publication")
	}
	end := 0
	for ordinal, chunk := range publication.Chunks {
		if !chunk.valid() || chunk.Ordinal != ordinal || chunk.StartOffset < end {
			return errors.New("invalid embedding publication")
		}
		end = chunk.EndOffset
	}
	return nil
}

// PublishMemoryEmbeddingWork atomically records derived chunk coordinates and
// completes the exact running lease. A stale or superseded lease never alters
// persisted derived metadata.
func (d *Database) PublishMemoryEmbeddingWork(ctx context.Context, publication MemoryEmbeddingPublication) error {
	if err := publication.Validate(); err != nil {
		return err
	}
	chunks, err := json.Marshal(publication.Chunks)
	if err != nil {
		return errors.New("embedding publication cannot be encoded")
	}
	digest, _ := hex.DecodeString(publication.Lease.ContentSHA256)
	tx, err := beginMutation(ctx, d.db)
	if err != nil {
		return mutationStartError(err, "embedding publication transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	var changed bool
	err = tx.QueryRowContext(ctx, `SELECT brain.publish_embedding_job($1,$2,$3,$4,$5,$6,$7::jsonb)`, publication.Lease.GenerationID, publication.Lease.ItemID, publication.Lease.Revision, digest, publication.Lease.Token, publication.Lease.LeaseGeneration, chunks).Scan(&changed)
	if err != nil {
		return errors.New("embedding work could not be published")
	}
	if !changed {
		return ErrStaleEmbeddingLease
	}
	if err := tx.Commit(); err != nil {
		return errors.New("embedding publication transaction could not commit")
	}
	return nil
}

// MemoryEmbeddingClaimRequest is the bounded, provider-free worker claim
// input. Worker identity is an opaque lease holder, never an authorization
// principal or a provider credential.
type MemoryEmbeddingClaimRequest struct {
	WorkerID      string
	Limit         int
	LeaseDuration time.Duration
}

func (r MemoryEmbeddingClaimRequest) normalized() (MemoryEmbeddingClaimRequest, error) {
	if !validOpaqueID(r.WorkerID) || r.Limit < 1 || r.Limit > maxMemoryEmbeddingClaimBatch ||
		r.LeaseDuration < memoryEmbeddingMinLease || r.LeaseDuration > memoryEmbeddingMaxLease {
		return MemoryEmbeddingClaimRequest{}, errors.New("invalid memory embedding claim")
	}
	return r, nil
}

// Validate accepts only opaque IDs, a positive revision, and a canonical
// lowercase SHA-256 coordinate.
func (w MemoryEmbeddingWork) Validate() error {
	if !validOpaqueID(w.GenerationID) || !validOpaqueID(w.ItemID) || w.Revision < 1 ||
		len(w.ContentSHA256) != 64 {
		return errors.New("invalid memory embedding work")
	}
	digest, err := hex.DecodeString(w.ContentSHA256)
	if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != w.ContentSHA256 {
		return errors.New("invalid memory embedding work")
	}
	return nil
}
