package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/rock3r/punaro/canopi/protocol"
	"github.com/rock3r/punaro/internal/canopi/simulator"
)

func TestPostBatchSendsAuthenticatedSimulatorEvents(t *testing.T) {
	received := false
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/events:batch" || request.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(response, "bad request", http.StatusBadRequest)
			return
		}
		received = true
		response.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	if err := postBatch(server.Client(), server.URL, "test-token", simulator.Events(time.Now(), 0, "test-run")); err != nil {
		t.Fatalf("postBatch() error = %v", err)
	}
	if !received {
		t.Fatal("collector did not receive simulator batch")
	}
}

func TestRunSimulationRetriesSameBatchBeforeAdvancing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	attempts := make([][]string, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var events []protocol.Event
		if err := json.NewDecoder(request.Body).Decode(&events); err != nil {
			t.Error(err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		ids := make([]string, len(events))
		for index := range events {
			ids[index] = events[index].EventID
		}
		attempts = append(attempts, ids)
		if len(attempts) == 1 {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		response.WriteHeader(http.StatusAccepted)
		cancel()
	}))
	defer server.Close()

	if err := runSimulation(ctx, server.Client(), server.URL, "test-token", "test-run", time.Millisecond, false, io.Discard); err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 2 || !reflect.DeepEqual(attempts[0], attempts[1]) {
		t.Fatalf("attempt event IDs = %#v, want one stable retried batch", attempts)
	}
}
