package main

import (
	"context"
	"sync"
	"testing"
	"time"

	punaropostgres "github.com/rock3r/punaro/internal/postgres"
)

type scriptedEmbeddingExecutor struct {
	mu       sync.Mutex
	calls    int
	requests []punaropostgres.MemoryEmbeddingClaimRequest
	started  chan struct{}
}

func (executor *scriptedEmbeddingExecutor) Execute(_ context.Context, request punaropostgres.MemoryEmbeddingClaimRequest) (punaropostgres.MemoryEmbeddingExecutionResult, error) {
	executor.mu.Lock()
	executor.calls++
	executor.requests = append(executor.requests, request)
	executor.mu.Unlock()
	select {
	case executor.started <- struct{}{}:
	default:
	}
	return punaropostgres.MemoryEmbeddingExecutionResult{}, nil
}

func TestEmbeddingRuntimeRunsBoundedPassAndStops(t *testing.T) {
	executor := &scriptedEmbeddingExecutor{started: make(chan struct{}, 1)}
	runtime := newEmbeddingRuntime(executor, "11111111-1111-4111-8111-111111111111", time.Hour)
	select {
	case <-executor.started:
	case <-time.After(time.Second):
		t.Fatal("embedding pass did not start")
	}
	runtime.Close()
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if executor.calls != 1 || len(executor.requests) != 1 || executor.requests[0].Limit != 1 || executor.requests[0].LeaseDuration != time.Minute {
		t.Fatalf("calls=%d requests=%#v", executor.calls, executor.requests)
	}
}
