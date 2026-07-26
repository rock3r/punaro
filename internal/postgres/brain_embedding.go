package postgres

import (
	"encoding/hex"
	"errors"
	"regexp"
	"time"
)

const (
	maxMemoryEmbeddingDimensions = 4096
	maxMemoryEmbeddingClaimBatch = 32
	memoryEmbeddingMinLease      = 5 * time.Second
	memoryEmbeddingMaxLease      = 5 * time.Minute
)

var memoryEmbeddingRevisionPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:-]{0,63}$`)

// MemoryEmbeddingGenerationState is the closed state for the one M19A
// generation that may receive revision-bound work. M20 extends this with a
// building state and atomic activation; M19A rows are otherwise immutable.
type MemoryEmbeddingGenerationState string

const (
	// MemoryEmbeddingGenerationActive accepts work for one pinned model.
	MemoryEmbeddingGenerationActive MemoryEmbeddingGenerationState = "active"
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
		g.State != MemoryEmbeddingGenerationActive {
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
