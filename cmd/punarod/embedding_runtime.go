package main

import (
	"context"
	"sync"
	"time"

	punaropostgres "github.com/rock3r/punaro/internal/postgres"
)

const (
	embeddingRuntimeBatch       = 1
	embeddingRuntimeLease       = time.Minute
	embeddingRuntimePassTimeout = 30 * time.Second
)

type embeddingExecutor interface {
	Execute(context.Context, punaropostgres.MemoryEmbeddingClaimRequest) (punaropostgres.MemoryEmbeddingExecutionResult, error)
}

// embeddingRuntime runs one bounded, best-effort embedding pass at a time.
// Its failures deliberately do not affect request serving or daemon readiness.
type embeddingRuntime struct {
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
}

func newEmbeddingRuntime(executor embeddingExecutor, workerID string, interval time.Duration) *embeddingRuntime {
	//nolint:gosec // Close owns this cancellation function for the runtime lifetime.
	ctx, cancel := context.WithCancel(context.Background())
	runtime := &embeddingRuntime{cancel: cancel, done: make(chan struct{})}
	go func() {
		defer cancel()
		defer close(runtime.done)
		pass := func() {
			passCtx, passCancel := context.WithTimeout(ctx, embeddingRuntimePassTimeout)
			passCtx = punaropostgres.WithMemoryEmbeddingCleanupContext(passCtx, ctx)
			_, _ = executor.Execute(passCtx, punaropostgres.MemoryEmbeddingClaimRequest{WorkerID: workerID, Limit: embeddingRuntimeBatch, LeaseDuration: embeddingRuntimeLease})
			passCancel()
		}
		pass()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				pass()
			}
		}
	}()
	return runtime
}

func (runtime *embeddingRuntime) Close() {
	if runtime == nil {
		return
	}
	runtime.once.Do(func() { runtime.cancel(); <-runtime.done })
}
