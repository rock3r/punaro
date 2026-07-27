package postgres

import (
	"context"
	"errors"
	"math"
	"testing"
)

func TestMemoryHybridQueryExecutorPreparesBeforeProviderUse(t *testing.T) {
	generation := MemoryEmbeddingGeneration{ID: "11111111-1111-4111-8111-111111111111", Model: "local.e5", Revision: "2026-07-27", Dimensions: 2, State: MemoryEmbeddingGenerationActive}
	store := &fakeMemoryHybridQueryStore{generation: generation}
	provider := &fakeMemoryHybridQueryProvider{vector: []float64{0.25, 0.75}}
	executor, err := NewMemoryHybridQueryExecutor(store, provider)
	if err != nil {
		t.Fatal(err)
	}
	got, err := executor.Embed(context.Background(), MemorySearchRequest{PrincipalID: "22222222-2222-4222-8222-222222222222", ProjectID: "33333333-3333-4333-8333-333333333333", Query: "  release decision  ", Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if store.prepareCalls != 1 || provider.calls != 1 || provider.query != "release decision" || provider.generation != generation || got.GenerationID != generation.ID {
		t.Fatalf("prepared=%d provider=%d query=%q generation=%#v result=%#v", store.prepareCalls, provider.calls, provider.query, provider.generation, got)
	}
}

func TestMemoryHybridQueryExecutorRejectsProviderVectorOutsidePreparedGeneration(t *testing.T) {
	generation := MemoryEmbeddingGeneration{ID: "11111111-1111-4111-8111-111111111111", Model: "local.e5", Revision: "2026-07-27", Dimensions: 2, State: MemoryEmbeddingGenerationActive}
	provider := &fakeMemoryHybridQueryProvider{vector: []float64{1}}
	executor, err := NewMemoryHybridQueryExecutor(&fakeMemoryHybridQueryStore{generation: generation}, provider)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Embed(context.Background(), MemorySearchRequest{PrincipalID: "22222222-2222-4222-8222-222222222222", ProjectID: "33333333-3333-4333-8333-333333333333", Query: "release", Limit: 1}); err == nil {
		t.Fatal("dimension-mismatched provider vector accepted")
	}
}

func TestMemoryHybridQueryExecutorRejectsProviderVectorHybridWouldReject(t *testing.T) {
	generation := MemoryEmbeddingGeneration{ID: "11111111-1111-4111-8111-111111111111", Model: "local.e5", Revision: "2026-07-27", Dimensions: 2, State: MemoryEmbeddingGenerationActive}
	for name, vector := range map[string][]float64{"float32 overflow": {math.MaxFloat64, 1}, "float32 underflow": {math.SmallestNonzeroFloat64, 1}} {
		t.Run(name, func(t *testing.T) {
			executor, err := NewMemoryHybridQueryExecutor(&fakeMemoryHybridQueryStore{generation: generation}, &fakeMemoryHybridQueryProvider{vector: vector})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := executor.Embed(context.Background(), MemorySearchRequest{PrincipalID: "22222222-2222-4222-8222-222222222222", ProjectID: "33333333-3333-4333-8333-333333333333", Query: "release", Limit: 1}); err == nil {
				t.Fatalf("provider vector accepted: %v", vector)
			}
		})
	}
}

func TestMemoryHybridQueryExecutorDoesNotCallProviderWhenPreparationFails(t *testing.T) {
	provider := &fakeMemoryHybridQueryProvider{vector: []float64{1}}
	executor, err := NewMemoryHybridQueryExecutor(&fakeMemoryHybridQueryStore{err: ErrNotFound}, provider)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Embed(context.Background(), MemorySearchRequest{PrincipalID: "22222222-2222-4222-8222-222222222222", ProjectID: "33333333-3333-4333-8333-333333333333", Query: "release", Limit: 1}); !errors.Is(err, ErrNotFound) || provider.calls != 0 {
		t.Fatalf("preparation error=%v provider calls=%d", err, provider.calls)
	}
}

type fakeMemoryHybridQueryStore struct {
	generation   MemoryEmbeddingGeneration
	err          error
	prepareCalls int
}

func (s *fakeMemoryHybridQueryStore) PrepareMemoryHybridSearch(_ context.Context, _ MemorySearchRequest) (MemoryEmbeddingGeneration, error) {
	s.prepareCalls++
	return s.generation, s.err
}

type fakeMemoryHybridQueryProvider struct {
	generation MemoryEmbeddingGeneration
	query      string
	vector     []float64
	err        error
	calls      int
}

func (p *fakeMemoryHybridQueryProvider) EmbedMemoryQuery(_ context.Context, generation MemoryEmbeddingGeneration, query string) ([]float64, error) {
	p.calls++
	p.generation, p.query = generation, query
	return p.vector, p.err
}
