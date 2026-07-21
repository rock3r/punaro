package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestHTTPDurableMessageFlowRequiresSignedMachineRequests(t *testing.T) {
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
	auth, err := NewAuthenticator(store, []Machine{
		{ID: "machine-a", PublicKey: publicA, EndpointPrefixes: []string{"agent/a/"}},
		{ID: "machine-b", PublicKey: publicB, EndpointPrefixes: []string{"agent/b/"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	handler := NewHandler(store, auth, HandlerOptions{Now: func() time.Time { return clock }, EndpointLeaseTTL: time.Minute, DeliveryLeaseTTL: time.Minute})

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
	message := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations/"+conversation.ID+"/messages", `{"from_endpoint":"agent/a/session","body":"review complete"}`, "send", "send-1")
	if message.Code != http.StatusCreated {
		t.Fatalf("message status=%d body=%s", message.Code, message.Body.String())
	}
	lease := serveSigned(t, handler, privateB, "machine-b", http.MethodPost, "/v1/deliveries/lease", `{"endpoint":"agent/b/session","consumer_id":"consumer-b"}`, "lease", "")
	if lease.Code != http.StatusOK {
		t.Fatalf("lease status=%d body=%s", lease.Code, lease.Body.String())
	}
	var leased struct {
		Cursors    map[string]int64 `json:"cursors"`
		Deliveries []struct {
			ID              string `json:"id"`
			LeaseToken      string `json:"lease_token"`
			LeaseGeneration int64  `json:"lease_generation"`
			Message         struct {
				Body string `json:"body"`
			} `json:"message"`
		} `json:"deliveries"`
	}
	if err := json.NewDecoder(lease.Body).Decode(&leased); err != nil {
		t.Fatal(err)
	}
	if len(leased.Deliveries) != 1 || leased.Deliveries[0].Message.Body != "review complete" || leased.Cursors[conversation.ID] != 0 {
		t.Fatalf("leased=%+v", leased)
	}
	ackBody, err := json.Marshal(map[string]any{"endpoint": "agent/b/session", "lease_token": leased.Deliveries[0].LeaseToken, "lease_generation": leased.Deliveries[0].LeaseGeneration})
	if err != nil {
		t.Fatal(err)
	}
	ack := serveSigned(t, handler, privateB, "machine-b", http.MethodPost, "/v1/deliveries/"+leased.Deliveries[0].ID+"/ack", string(ackBody), "ack", "")
	if ack.Code != http.StatusNoContent {
		t.Fatalf("ack status=%d body=%s", ack.Code, ack.Body.String())
	}
	afterAck := serveSigned(t, handler, privateB, "machine-b", http.MethodPost, "/v1/deliveries/lease", `{"endpoint":"agent/b/session","consumer_id":"consumer-b","conversation_id":"`+conversation.ID+`"}`, "lease-after-ack", "")
	var caughtUp struct {
		Cursors map[string]int64 `json:"cursors"`
	}
	if afterAck.Code != http.StatusOK || json.NewDecoder(afterAck.Body).Decode(&caughtUp) != nil || caughtUp.Cursors[conversation.ID] != 1 {
		t.Fatalf("caught-up status=%d body=%s cursors=%v", afterAck.Code, afterAck.Body.String(), caughtUp.Cursors)
	}
}

func TestHTTPSenderValidationAuthorizesWithoutCreatingMessageState(t *testing.T) {
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
	auth, err := NewAuthenticator(store, []Machine{{ID: "machine-a", PublicKey: publicA, EndpointPrefixes: []string{"agent/a/"}}, {ID: "machine-b", PublicKey: publicB, EndpointPrefixes: []string{"agent/b/"}}})
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	handler := NewHandler(store, auth, HandlerOptions{Now: func() time.Time { return clock }, EndpointLeaseTTL: time.Minute})
	serveSigned(t, handler, privateA, "machine-a", http.MethodPut, "/v1/machines/me/endpoints", `{"endpoints":["agent/a/session"]}`, "advertise-a", "")
	serveSigned(t, handler, privateB, "machine-b", http.MethodPut, "/v1/machines/me/endpoints", `{"endpoints":["agent/b/session"]}`, "advertise-b", "")
	created := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations", `{"creator_endpoint":"agent/a/session","members":[{"endpoint":"agent/a/session","capabilities":["send","receive","admin"]},{"endpoint":"agent/b/session","capabilities":["receive"]}]}`, "create", "create-1")
	if created.Code != http.StatusCreated {
		t.Fatalf("create status=%d", created.Code)
	}
	var conversation Conversation
	if err := json.NewDecoder(created.Body).Decode(&conversation); err != nil {
		t.Fatal(err)
	}
	if response := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations/"+conversation.ID+"/sender-validation", `{"from_endpoint":"agent/a/session"}`, "validate-ok", ""); response.Code != http.StatusOK {
		t.Fatalf("authorized validation status=%d body=%s", response.Code, response.Body.String())
	}
	if response := serveSigned(t, handler, privateB, "machine-b", http.MethodPost, "/v1/conversations/"+conversation.ID+"/sender-validation", `{"from_endpoint":"agent/b/session"}`, "validate-no-send", ""); response.Code != http.StatusForbidden {
		t.Fatalf("no-send validation status=%d body=%s", response.Code, response.Body.String())
	}
	if response := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations/"+conversation.ID+"/sender-validation", `{"from_endpoint":"agent/b/session"}`, "validate-wrong-owner", ""); response.Code != http.StatusForbidden {
		t.Fatalf("wrong-owner validation status=%d body=%s", response.Code, response.Body.String())
	}
	for _, table := range []string{"messages", "idempotency"} {
		var count int
		if err := store.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM `+table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("validation mutated %s count=%d err=%v", table, count, err)
		}
	}
}

func TestHTTPCreateConversationDeduplicatesSameMachineIdempotencyKey(t *testing.T) {
	t.Parallel()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	auth, err := NewAuthenticator(store, []Machine{{ID: "machine-a", PublicKey: public, EndpointPrefixes: []string{"agent/a/"}}})
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	handler := NewHandler(store, auth, HandlerOptions{Now: func() time.Time { return clock }, EndpointLeaseTTL: time.Minute})
	serveSigned(t, handler, private, "machine-a", http.MethodPut, "/v1/machines/me/endpoints", `{"endpoints":["agent/a/session"]}`, "advertise", "")
	body := `{"creator_endpoint":"agent/a/session","members":[{"endpoint":"agent/a/session","capabilities":["send","receive","admin"]}]}`
	first := serveSigned(t, handler, private, "machine-a", http.MethodPost, "/v1/conversations", body, "create-first", "create-1")
	second := serveSigned(t, handler, private, "machine-a", http.MethodPost, "/v1/conversations", body, "create-retry", "create-1")
	if first.Code != http.StatusCreated || second.Code != http.StatusCreated {
		t.Fatalf("create statuses first=%d second=%d", first.Code, second.Code)
	}
	var firstConversation, secondConversation Conversation
	if err := json.NewDecoder(first.Body).Decode(&firstConversation); err != nil {
		t.Fatal(err)
	}
	if err := json.NewDecoder(second.Body).Decode(&secondConversation); err != nil {
		t.Fatal(err)
	}
	if firstConversation.ID == "" || secondConversation.ID != firstConversation.ID {
		t.Fatalf("idempotent create first=%#v second=%#v", firstConversation, secondConversation)
	}
	changed := serveSigned(t, handler, private, "machine-a", http.MethodPost, "/v1/conversations", `{"creator_endpoint":"agent/a/session","members":[{"endpoint":"agent/a/session","capabilities":["send","receive","admin"]},{"endpoint":"agent/b/session","capabilities":["receive"]}]}`, "create-conflict", "create-1")
	if changed.Code != http.StatusConflict {
		t.Fatalf("changed create retry status=%d body=%s", changed.Code, changed.Body.String())
	}
}

func TestHTTPRejectsUnsignedEndpointClaimsAndUnknownJSON(t *testing.T) {
	t.Parallel()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	auth, err := NewAuthenticator(store, []Machine{{ID: "machine-a", PublicKey: public, EndpointPrefixes: []string{"agent/a/"}}})
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	handler := NewHandler(store, auth, HandlerOptions{Now: func() time.Time { return clock }})
	unknown := serveSigned(t, handler, private, "machine-a", http.MethodPut, "/v1/machines/me/endpoints", `{"endpoints":["agent/a/reviewer"],"unexpected":true}`, "unknown", "")
	if unknown.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status=%d body=%s", unknown.Code, unknown.Body.String())
	}
	forbidden := serveSigned(t, handler, private, "machine-a", http.MethodPut, "/v1/machines/me/endpoints", `{"endpoints":["agent/other"]}`, "forbidden", "")
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("wrong namespace status=%d body=%s", forbidden.Code, forbidden.Body.String())
	}
	unsigned := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/v1/machines/me/endpoints", bytes.NewBufferString(`{"endpoints":["agent/a/reviewer"]}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, unsigned)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestHTTPRelayReportsMaintenanceDuringAuthentication(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	auth, err := NewAuthenticator(nonceStoreFunc(func(string, string, time.Time, time.Time) error { return ErrMaintenance }), []Machine{{ID: "machine-a", PublicKey: public, EndpointPrefixes: []string{"agent/a/"}}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	handler := NewHandler(store, auth, HandlerOptions{Now: func() time.Time { return now }})
	response := serveSigned(t, handler, private, "machine-a", http.MethodGet, "/v1/conversations", "", "maintenance", "")
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Retry-After") != "5" {
		t.Fatalf("maintenance status=%d retry-after=%q body=%s", response.Code, response.Header().Get("Retry-After"), response.Body.String())
	}
}

func TestHTTPNotificationsAuthenticatesAndEmitsOnlyWakeMetadata(t *testing.T) {
	t.Parallel()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	auth, err := NewAuthenticator(store, []Machine{{ID: "machine-a", PublicKey: public, EndpointPrefixes: []string{"agent/a/"}}})
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	notifier := NewNotifier()
	server := httptest.NewServer(NewHandler(store, auth, HandlerOptions{Now: func() time.Time { return clock }, Notifier: notifier}))
	defer server.Close()
	path := "/v1/notifications"
	signed := signRequest(private, "machine-a", http.MethodGet, path, nil, clock, "notifications")
	headers := http.Header{}
	headers.Set("X-Punaro-Machine", signed.MachineID)
	headers.Set("X-Punaro-Timestamp", signed.Timestamp.Format(time.RFC3339Nano))
	headers.Set("X-Punaro-Nonce", signed.Nonce)
	headers.Set("X-Punaro-Signature", base64.RawURLEncoding.EncodeToString(signed.Signature))
	connection, response, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(server.URL, "http")+path, &websocket.DialOptions{HTTPHeader: headers})
	if response != nil && response.Body != nil {
		defer func() { _ = response.Body.Close() }()
	}
	if err != nil {
		t.Fatalf("dial notifications status=%v err=%v", response, err)
	}
	defer func() { _ = connection.Close(websocket.StatusNormalClosure, "done") }()
	notifier.Publish("machine-a", "conversation-1", 9)
	_, data, err := connection.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"type":"wake","topic_id":"conversation-1","sequence":9}` {
		t.Fatalf("wake payload=%s", data)
	}
}

func TestHTTPNotificationsCloseWithinFenceWhenTransitionAuthorityHangs(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	var current atomic.Int32
	current.Store(1)
	auth, err := NewTransitionAuthenticator(store, []Machine{{ID: "machine-a", PublicKey: public, EndpointPrefixes: []string{"agent/a/"}}}, transitionAuthorityFunc(func(_ context.Context, credential string, legacyKey ed25519.PublicKey) (TransitionAuthorization, error) {
		if credential != testTransitionToken || legacyKey != nil {
			return TransitionAuthorization{}, ErrForbidden
		}
		return TransitionAuthorization{LegacyPublicKey: public, Current: func(ctx context.Context) error {
			switch current.Load() {
			case 1:
				return nil
			case -1:
				<-ctx.Done()
				return ctx.Err()
			default:
				return ErrForbidden
			}
		}}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(NewHandler(store, auth, HandlerOptions{SessionRevalidateInterval: 10 * time.Millisecond}))
	defer server.Close()
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+testTransitionToken)
	connection, response, err := websocket.Dial(t.Context(), "ws"+strings.TrimPrefix(server.URL, "http")+"/v1/notifications", &websocket.DialOptions{HTTPHeader: headers})
	if response != nil && response.Body != nil {
		defer func() { _ = response.Body.Close() }()
	}
	if err != nil {
		t.Fatalf("dial notifications status=%v err=%v", response, err)
	}
	defer func() { _ = connection.Close(websocket.StatusNormalClosure, "done") }()
	current.Store(-1)
	readCtx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, _, err := connection.Read(readCtx); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("revoked transition socket err=%v status=%v", err, websocket.CloseStatus(err))
	}
}

func serveSigned(t *testing.T, handler http.Handler, private ed25519.PrivateKey, machineID, method, path, body, nonce, idempotencyKey string) *httptest.ResponseRecorder {
	t.Helper()
	clock := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	signed := signRequest(private, machineID, method, path, []byte(body), clock, nonce)
	request := httptest.NewRequestWithContext(context.Background(), method, path, bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Punaro-Machine", signed.MachineID)
	request.Header.Set("X-Punaro-Timestamp", signed.Timestamp.Format(time.RFC3339Nano))
	request.Header.Set("X-Punaro-Nonce", signed.Nonce)
	request.Header.Set("X-Punaro-Signature", base64.RawURLEncoding.EncodeToString(signed.Signature))
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
