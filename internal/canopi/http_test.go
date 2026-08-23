package canopi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHandlerIngestSnapshotRenderAndConditionalFetch(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	store := NewStore(DefaultConfig())
	handler, err := NewHandler(HandlerConfig{
		Store: store, Token: "test-token", Now: func() time.Time { return now },
		Render: RenderConfig{Width: 800, Height: 480, Grid: GridConfig{Columns: 2, Rows: 6}, RelativeTimeBucket: time.Minute, Title: "CANOPI"},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(event("event-1", "agent", "working", now))
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/events", bytes.NewReader(payload))
	request.Header.Set("Authorization", "Bearer test-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("POST status = %d, body = %s", response.Code, response.Body.String())
	}

	renderRequest := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/render/800x480.png", nil)
	renderRequest.Header.Set("Authorization", "Bearer test-token")
	renderResponse := httptest.NewRecorder()
	handler.ServeHTTP(renderResponse, renderRequest)
	if renderResponse.Code != http.StatusOK || renderResponse.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("render status = %d, content-type = %q", renderResponse.Code, renderResponse.Header().Get("Content-Type"))
	}
	etag := renderResponse.Header().Get("ETag")
	if etag == "" {
		t.Fatal("render response has no ETag")
	}
	conditional := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/render/800x480.png", nil)
	conditional.Header.Set("Authorization", "Bearer test-token")
	conditional.Header.Set("If-None-Match", etag)
	conditionalResponse := httptest.NewRecorder()
	handler.ServeHTTP(conditionalResponse, conditional)
	if conditionalResponse.Code != http.StatusNotModified || conditionalResponse.Body.Len() != 0 {
		t.Fatalf("conditional status = %d, body bytes = %d", conditionalResponse.Code, conditionalResponse.Body.Len())
	}
}

func TestHandlerRequiresBearerAndBatchIsBounded(t *testing.T) {
	handler, err := NewHandler(HandlerConfig{Store: NewStore(DefaultConfig()), Token: "secret", Render: DefaultRenderConfig()})
	if err != nil {
		t.Fatal(err)
	}
	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/snapshot", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", unauthorized.Code)
	}
	batch := make([]json.RawMessage, 101)
	for i := range batch {
		batch[i] = json.RawMessage(`{}`)
	}
	payload, _ := json.Marshal(batch)
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/events:batch", bytes.NewReader(payload))
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized batch status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestHandlerRejectsTrailingBatchJSON(t *testing.T) {
	handler, err := NewHandler(HandlerConfig{Store: NewStore(DefaultConfig()), Token: "secret", Render: DefaultRenderConfig()})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/events:batch", bytes.NewBufferString(`[] {}`))
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("trailing JSON status = %d, body = %s", response.Code, response.Body.String())
	}
}
