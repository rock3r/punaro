package canopi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rock3r/punaro/canopi/protocol"
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

func TestHandlerRejectsFutureActivityAndLiveRecordOverflow(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	config := DefaultConfig()
	config.MaxLiveRecords = 1
	store := NewStore(config)
	store.now = func() time.Time { return now }
	handler, err := NewHandler(HandlerConfig{Store: store, Token: "secret", Now: func() time.Time { return now }, Render: DefaultRenderConfig()})
	if err != nil {
		t.Fatal(err)
	}
	post := func(input protocol.Event) int {
		payload, _ := json.Marshal(input)
		request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/events", bytes.NewReader(payload))
		request.Header.Set("Authorization", "Bearer secret")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response.Code
	}
	if got := post(event("future", "future", protocol.StateWorking, now.Add(6*time.Minute))); got != http.StatusBadRequest {
		t.Fatalf("future activity status = %d, want %d", got, http.StatusBadRequest)
	}
	if got := post(event("first", "first", protocol.StateWorking, now)); got != http.StatusAccepted {
		t.Fatalf("first activity status = %d, want %d", got, http.StatusAccepted)
	}
	if got := post(event("overflow", "overflow", protocol.StateWorking, now)); got != http.StatusTooManyRequests {
		t.Fatalf("overflow status = %d, want %d", got, http.StatusTooManyRequests)
	}
}

func TestHandlerBatchContinuesAfterPermanentEventRejection(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	config := DefaultConfig()
	config.MaxLiveRecords = 1
	store := NewStore(config)
	store.now = func() time.Time { return now }
	_, _ = store.Apply(event("existing", "existing", protocol.StateWorking, now))
	handler, err := NewHandler(HandlerConfig{Store: store, Token: "secret", Now: func() time.Time { return now }, Render: DefaultRenderConfig()})
	if err != nil {
		t.Fatal(err)
	}
	rejected, _ := json.Marshal(event("new-agent", "new-agent", protocol.StateWorking, now))
	suffix, _ := json.Marshal(event("existing-done", "existing", protocol.StateDone, now.Add(time.Second)))
	payload := append(append([]byte{'['}, rejected...), ',')
	payload = append(payload, suffix...)
	payload = append(payload, ']')
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/events:batch", bytes.NewReader(payload))
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusMultiStatus {
		t.Fatalf("batch status = %d, body = %s", response.Code, response.Body.String())
	}
	agents := store.Snapshot(now.Add(time.Second)).Agents
	if len(agents) != 1 || agents[0].State != protocol.StateDone {
		t.Fatalf("batch suffix was not applied: %#v", agents)
	}
}

func TestHandlerUsesRealClockForExpiryOnSnapshotAndRender(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 45, 0, 0, time.UTC)
	for _, path := range []string{"/v1/snapshot", "/v1/render/800x480.png"} {
		t.Run(path, func(t *testing.T) {
			config := DefaultConfig()
			config.WorkingTTL = 30 * time.Minute
			store := NewStore(config)
			store.now = func() time.Time { return now }
			if _, err := store.Apply(event("stale", "agent", protocol.StateWorking, now.Add(-45*time.Minute))); err != nil {
				t.Fatal(err)
			}
			render := DefaultRenderConfig()
			render.RelativeTimeBucket = 24 * time.Hour
			handler, err := NewHandler(HandlerConfig{Store: store, Token: "secret", Now: func() time.Time { return now }, Render: render})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
			request.Header.Set("Authorization", "Bearer secret")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("GET %s status = %d, body = %s", path, response.Code, response.Body.String())
			}
			if got := store.Revision(); got != 2 {
				t.Fatalf("revision after GET %s = %d, want expiry revision 2", path, got)
			}
		})
	}
}
