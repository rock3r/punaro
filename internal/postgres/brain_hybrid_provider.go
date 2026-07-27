package postgres

import (
	"context"
	"errors"
)

// MemoryHybridQueryEmbedding is a bounded provider result tied to the exact
// generation authorized before the provider received the query.
type MemoryHybridQueryEmbedding struct {
	GenerationID string
	Vector       []float64
}

// MemoryHybridQueryEmbeddingProvider derives one query vector for a prepared
// active generation. Provider credentials and configuration stay outside this
// provider-agnostic package.
type MemoryHybridQueryEmbeddingProvider interface {
	EmbedMemoryQuery(context.Context, MemoryEmbeddingGeneration, string) ([]float64, error)
}

type memoryHybridQueryStore interface {
	PrepareMemoryHybridSearch(context.Context, MemorySearchRequest) (MemoryEmbeddingGeneration, error)
}

// MemoryHybridQueryExecutor authorizes before exposing a normalized query to a
// provider and preserves the resulting generation fence for hybrid retrieval.
type MemoryHybridQueryExecutor struct {
	store    memoryHybridQueryStore
	provider MemoryHybridQueryEmbeddingProvider
}

// NewMemoryHybridQueryExecutor constructs a provider-agnostic, authorization-
// first query embedding executor.
func NewMemoryHybridQueryExecutor(store memoryHybridQueryStore, provider MemoryHybridQueryEmbeddingProvider) (*MemoryHybridQueryExecutor, error) {
	if store == nil || provider == nil {
		return nil, errors.New("memory hybrid query executor is invalid")
	}
	return &MemoryHybridQueryExecutor{store: store, provider: provider}, nil
}

// Embed authorizes the query, derives a bounded vector for the returned active
// generation, and returns that generation ID for fenced hybrid retrieval.
func (e *MemoryHybridQueryExecutor) Embed(ctx context.Context, raw MemorySearchRequest) (MemoryHybridQueryEmbedding, error) {
	request, err := raw.normalized()
	if err != nil {
		return MemoryHybridQueryEmbedding{}, err
	}
	generation, err := e.store.PrepareMemoryHybridSearch(ctx, request)
	if err != nil {
		return MemoryHybridQueryEmbedding{}, err
	}
	if generation.Validate() != nil || generation.State != MemoryEmbeddingGenerationActive {
		return MemoryHybridQueryEmbedding{}, errors.New("memory hybrid generation is unavailable")
	}
	providerCtx, cancel := context.WithTimeout(ctx, memorySearchTimeout)
	defer cancel()
	vector, err := e.provider.EmbedMemoryQuery(providerCtx, generation, request.Query)
	if err != nil {
		return MemoryHybridQueryEmbedding{}, errors.New("memory query embedding is unavailable")
	}
	if !validMemoryEmbeddingVector(vector, generation.Dimensions) {
		return MemoryHybridQueryEmbedding{}, errors.New("memory query embedding is invalid")
	}
	return MemoryHybridQueryEmbedding{GenerationID: generation.ID, Vector: append([]float64(nil), vector...)}, nil
}
