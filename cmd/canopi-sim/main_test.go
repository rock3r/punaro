package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
	if err := postBatch(server.Client(), server.URL, "test-token", simulator.Events(time.Now(), 0)); err != nil {
		t.Fatalf("postBatch() error = %v", err)
	}
	if !received {
		t.Fatal("collector did not receive simulator batch")
	}
}
