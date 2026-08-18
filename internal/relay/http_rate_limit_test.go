package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestHTTPAppendRateLimitReturnsBoundedRetryAfterAndContentFreeError(t *testing.T) {
	t.Parallel()
	publicA, privateA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicB, privateB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.SetRateLimitPolicy(RateLimitPolicy{SenderBurst: 1, SenderRefillPerMinute: 30, ConversationBurst: 10, ConversationRefillPerMinute: 60, MaxRetryAfterSeconds: 60}); err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuthenticator(store, []Machine{
		{ID: "machine-a", PublicKey: publicA, EndpointPrefixes: []string{"agent/a/"}},
		{ID: "machine-b", PublicKey: publicB, EndpointPrefixes: []string{"agent/b/"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	metrics := &Metrics{}
	handler := NewHandler(store, auth, HandlerOptions{Now: func() time.Time { return clock }, EndpointLeaseTTL: time.Minute, DeliveryLeaseTTL: time.Minute, Metrics: metrics})
	serveSigned(t, handler, privateA, "machine-a", http.MethodPut, "/v1/machines/me/endpoints", `{"endpoints":["agent/a/session"]}`, "advertise-a", "")
	serveSigned(t, handler, privateB, "machine-b", http.MethodPut, "/v1/machines/me/endpoints", `{"endpoints":["agent/b/session"]}`, "advertise-b", "")
	create := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations", `{"creator_endpoint":"agent/a/session","members":[{"endpoint":"agent/a/session","capabilities":["send","receive","admin"]},{"endpoint":"agent/b/session","capabilities":["receive"]}]}`, "create", "create-1")
	if create.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", create.Code, create.Body.String())
	}
	var conversation struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(create.Body).Decode(&conversation); err != nil {
		t.Fatal(err)
	}
	first := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations/"+conversation.ID+"/messages", `{"from_endpoint":"agent/a/session","body":"one"}`, "send-1", "send-1")
	if first.Code != http.StatusCreated {
		t.Fatalf("first message status=%d body=%s", first.Code, first.Body.String())
	}
	retry := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations/"+conversation.ID+"/messages", `{"from_endpoint":"agent/a/session","body":"one"}`, "send-1-retry", "send-1")
	if retry.Code != http.StatusOK {
		t.Fatalf("committed retry status=%d body=%s", retry.Code, retry.Body.String())
	}
	conflict := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations/"+conversation.ID+"/messages", `{"from_endpoint":"agent/a/session","body":"changed"}`, "send-1-changed", "send-1")
	if conflict.Code != http.StatusConflict {
		t.Fatalf("changed-body status=%d body=%s", conflict.Code, conflict.Body.String())
	}
	limited := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations/"+conversation.ID+"/messages", `{"from_endpoint":"agent/a/session","body":"secret-body"}`, "send-2", "send-2")
	if limited.Code != http.StatusTooManyRequests || limited.Header().Get("Retry-After") != "2" {
		t.Fatalf("rate limit status=%d retry-after=%q body=%s", limited.Code, limited.Header().Get("Retry-After"), limited.Body.String())
	}
	var payload map[string]any
	if err := json.NewDecoder(limited.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if len(payload) != 1 || payload["error"] != "rate limit exceeded" {
		t.Fatalf("rate limit payload=%#v", payload)
	}
	if metrics.RateRejections() != 1 {
		t.Fatalf("rate rejection metric=%d", metrics.RateRejections())
	}
}
