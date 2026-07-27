package postgres

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemoryEmbeddingExecutorPublishesAndRetriesBoundedly(t *testing.T) {
	lease := MemoryEmbeddingLease{MemoryEmbeddingWork: MemoryEmbeddingWork{GenerationID: "11111111-1111-4111-8111-111111111111", ItemID: "22222222-2222-4222-8222-222222222222", Revision: 1, ContentSHA256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}, Generation: MemoryEmbeddingGeneration{ID: "11111111-1111-4111-8111-111111111111", Model: "local.e5", Revision: "2026-07-01", Dimensions: 2, State: MemoryEmbeddingGenerationActive}, Attempts: 1, Holder: "33333333-3333-4333-8333-333333333333", Token: "44444444-4444-4444-8444-444444444444", LeaseGeneration: 1, LeaseUntil: time.Now().Add(time.Minute)}
	store := &fakeEmbeddingExecutorStore{leases: []MemoryEmbeddingLease{lease}}
	source := fakeEmbeddingSource{generation: MemoryEmbeddingGeneration{ID: lease.GenerationID, Model: "local.e5", Revision: "2026-07-01", Dimensions: 2, State: MemoryEmbeddingGenerationActive}, chunks: []MemoryEmbeddingSourceChunk{{Ordinal: 0, ContentSHA256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", StartOffset: 0, EndOffset: 4, Text: "test"}}}
	sourceDeadline := time.Time{}
	source.deadline = &sourceDeadline
	providerDeadline := time.Time{}
	executor, err := NewMemoryEmbeddingExecutor(store, source, fakeEmbeddingProvider{vectors: [][]float64{{0.25, 0.75}}, deadline: &providerDeadline})
	if err != nil {
		t.Fatal(err)
	}
	result, err := executor.Execute(context.Background(), MemoryEmbeddingClaimRequest{WorkerID: lease.Holder, Limit: 1, LeaseDuration: time.Minute})
	if err != nil || result.Published != 1 || len(store.published) != 1 || len(store.retries) != 0 {
		t.Fatalf("result=%#v published=%#v retries=%#v err=%v", result, store.published, store.retries, err)
	}
	if providerDeadline.IsZero() || providerDeadline.After(lease.LeaseUntil.Add(-memoryEmbeddingPublicationReserve)) {
		t.Fatalf("provider deadline=%v lease until=%v", providerDeadline, lease.LeaseUntil)
	}
	if sourceDeadline.IsZero() || sourceDeadline.After(lease.LeaseUntil.Add(-memoryEmbeddingPublicationReserve)) {
		t.Fatalf("source deadline=%v lease until=%v", sourceDeadline, lease.LeaseUntil)
	}
	store.leases = []MemoryEmbeddingLease{lease}
	executor, err = NewMemoryEmbeddingExecutor(store, source, fakeEmbeddingProvider{vectors: [][]float64{{0.25}}})
	if err != nil {
		t.Fatal(err)
	}
	result, err = executor.Execute(context.Background(), MemoryEmbeddingClaimRequest{WorkerID: lease.Holder, Limit: 1, LeaseDuration: time.Minute})
	if err != nil || result.Retried != 1 || len(store.retries) != 1 || store.retries[0].ErrorCode != "provider_invalid" {
		t.Fatalf("result=%#v retries=%#v err=%v", result, store.retries, err)
	}
	store.leases = []MemoryEmbeddingLease{lease}
	store.retryErr = errors.New("retry unavailable")
	executor, err = NewMemoryEmbeddingExecutor(store, source, fakeEmbeddingProvider{err: errors.New("provider unavailable")})
	if err != nil {
		t.Fatal(err)
	}
	result, err = executor.Execute(context.Background(), MemoryEmbeddingClaimRequest{WorkerID: lease.Holder, Limit: 1, LeaseDuration: time.Minute})
	if !errors.Is(err, store.retryErr) || result.Retried != 0 {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	store.leases = []MemoryEmbeddingLease{lease}
	store.retryErr = ErrStaleEmbeddingLease
	result, err = executor.Execute(context.Background(), MemoryEmbeddingClaimRequest{WorkerID: lease.Holder, Limit: 1, LeaseDuration: time.Minute})
	if err != nil || result.Retried != 0 {
		t.Fatalf("stale retry result=%#v err=%v", result, err)
	}
	store.retryErr = nil
	store.leases = []MemoryEmbeddingLease{lease}
	source.err = ErrMemoryEmbeddingQuarantined
	executor, err = NewMemoryEmbeddingExecutor(store, source, fakeEmbeddingProvider{})
	if err != nil {
		t.Fatal(err)
	}
	result, err = executor.Execute(context.Background(), MemoryEmbeddingClaimRequest{WorkerID: lease.Holder, Limit: 1, LeaseDuration: time.Minute})
	if err != nil || result.Retried != 1 || store.retries[len(store.retries)-1].ErrorCode != "quarantined" {
		t.Fatalf("result=%#v retries=%#v err=%v", result, store.retries, err)
	}
	store.leases = []MemoryEmbeddingLease{lease}
	source.err = nil
	source.generation = MemoryEmbeddingGeneration{ID: "55555555-5555-4555-8555-555555555555", Model: "local.e5", Revision: "2026-07-01", Dimensions: 2, State: MemoryEmbeddingGenerationActive}
	calls := 0
	executor, err = NewMemoryEmbeddingExecutor(store, source, fakeEmbeddingProvider{calls: &calls})
	if err != nil {
		t.Fatal(err)
	}
	result, err = executor.Execute(context.Background(), MemoryEmbeddingClaimRequest{WorkerID: lease.Holder, Limit: 1, LeaseDuration: time.Minute})
	if err != nil || calls != 0 || result.Retried != 1 || store.retries[len(store.retries)-1].ErrorCode != "provider_invalid" {
		t.Fatalf("result=%#v calls=%d retries=%#v err=%v", result, calls, store.retries, err)
	}
	store.leases = []MemoryEmbeddingLease{lease}
	source.generation = lease.Generation
	source.generation.Model = "local.other"
	calls = 0
	executor, err = NewMemoryEmbeddingExecutor(store, source, fakeEmbeddingProvider{calls: &calls})
	if err != nil {
		t.Fatal(err)
	}
	result, err = executor.Execute(context.Background(), MemoryEmbeddingClaimRequest{WorkerID: lease.Holder, Limit: 1, LeaseDuration: time.Minute})
	if err != nil || calls != 0 || result.Retried != 1 || store.retries[len(store.retries)-1].ErrorCode != "provider_invalid" {
		t.Fatalf("substituted generation result=%#v calls=%d retries=%#v err=%v", result, calls, store.retries, err)
	}
	store.leases = []MemoryEmbeddingLease{lease}
	if _, err := executor.Execute(context.Background(), MemoryEmbeddingClaimRequest{WorkerID: lease.Holder, Limit: maxMemoryEmbeddingClaimBatch + 1, LeaseDuration: time.Minute}); err == nil || len(store.leases) != 1 {
		t.Fatalf("unbounded executor request err=%v leases=%#v", err, store.leases)
	}
}

func TestMemoryEmbeddingExecutorRetainsSourceFenceThroughQuarantineRetry(t *testing.T) {
	lease := MemoryEmbeddingLease{MemoryEmbeddingWork: MemoryEmbeddingWork{GenerationID: "11111111-1111-4111-8111-111111111111", ItemID: "22222222-2222-4222-8222-222222222222", Revision: 1, ContentSHA256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}, Generation: MemoryEmbeddingGeneration{ID: "11111111-1111-4111-8111-111111111111", Model: "local.e5", Revision: "2026-07-01", Dimensions: 2, State: MemoryEmbeddingGenerationActive}, Attempts: 1, Holder: "33333333-3333-4333-8333-333333333333", Token: "44444444-4444-4444-8444-444444444444", LeaseGeneration: 1, LeaseUntil: time.Now().Add(time.Minute)}
	released := false
	store := &fakeEmbeddingExecutorStore{leases: []MemoryEmbeddingLease{lease}, onRetry: func() error {
		if released {
			return errors.New("quarantine fence released before retry")
		}
		return nil
	}}
	source := fencedEmbeddingSource{err: ErrMemoryEmbeddingQuarantined, release: func() { released = true }}
	executor, err := NewMemoryEmbeddingExecutor(store, source, fakeEmbeddingProvider{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := executor.Execute(context.Background(), MemoryEmbeddingClaimRequest{WorkerID: lease.Holder, Limit: 1, LeaseDuration: time.Minute})
	if err != nil || result.Retried != 1 || !released {
		t.Fatalf("result=%#v released=%t err=%v", result, released, err)
	}
}

type fakeEmbeddingExecutorStore struct {
	leases    []MemoryEmbeddingLease
	published []MemoryEmbeddingPublication
	retries   []MemoryEmbeddingRetry
	retryErr  error
	onRetry   func() error
}

func (s *fakeEmbeddingExecutorStore) ClaimMemoryEmbeddingWork(context.Context, MemoryEmbeddingClaimRequest) ([]MemoryEmbeddingLease, error) {
	result := s.leases
	s.leases = nil
	return result, nil
}
func (s *fakeEmbeddingExecutorStore) PublishMemoryEmbeddingWork(_ context.Context, value MemoryEmbeddingPublication) error {
	s.published = append(s.published, value)
	return nil
}
func (s *fakeEmbeddingExecutorStore) RetryMemoryEmbeddingWork(_ context.Context, value MemoryEmbeddingRetry) error {
	if s.retryErr != nil {
		return s.retryErr
	}
	if s.onRetry != nil {
		if err := s.onRetry(); err != nil {
			return err
		}
	}
	s.retries = append(s.retries, value)
	return nil
}

type fakeEmbeddingSource struct {
	generation MemoryEmbeddingGeneration
	chunks     []MemoryEmbeddingSourceChunk
	err        error
	deadline   *time.Time
}

func (s fakeEmbeddingSource) LoadMemoryEmbeddingSource(context.Context, MemoryEmbeddingLease) (MemoryEmbeddingGeneration, []MemoryEmbeddingSourceChunk, error) {
	return s.generation, s.chunks, s.err
}

func (s fakeEmbeddingSource) OpenMemoryEmbeddingSource(ctx context.Context, _ MemoryEmbeddingLease) (MemoryEmbeddingGeneration, []MemoryEmbeddingSourceChunk, func(), error) {
	if s.deadline != nil {
		*s.deadline, _ = ctx.Deadline()
	}
	return s.generation, s.chunks, func() {}, s.err
}

type fencedEmbeddingSource struct {
	err     error
	release func()
}

func (s fencedEmbeddingSource) LoadMemoryEmbeddingSource(context.Context, MemoryEmbeddingLease) (MemoryEmbeddingGeneration, []MemoryEmbeddingSourceChunk, error) {
	return MemoryEmbeddingGeneration{}, nil, s.err
}

func (s fencedEmbeddingSource) OpenMemoryEmbeddingSource(context.Context, MemoryEmbeddingLease) (MemoryEmbeddingGeneration, []MemoryEmbeddingSourceChunk, func(), error) {
	return MemoryEmbeddingGeneration{}, nil, s.release, s.err
}

type fakeEmbeddingProvider struct {
	vectors  [][]float64
	err      error
	calls    *int
	deadline *time.Time
}

func (p fakeEmbeddingProvider) Embed(ctx context.Context, _ MemoryEmbeddingGeneration, _ []MemoryEmbeddingSourceChunk) ([][]float64, error) {
	if p.calls != nil {
		*p.calls++
	}
	if p.deadline != nil {
		*p.deadline, _ = ctx.Deadline()
	}
	return p.vectors, p.err
}
