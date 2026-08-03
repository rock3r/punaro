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
	notifier := NewNotifier()
	targetNotifications := notifier.Register("machine-b")
	t.Cleanup(targetNotifications.Close)
	handler := NewHandler(store, auth, HandlerOptions{Now: func() time.Time { return clock }, EndpointLeaseTTL: time.Minute, DeliveryLeaseTTL: time.Minute, Notifier: notifier})

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

func TestHTTPRoleAddressingRequiresAuthorizedActiveRecipient(t *testing.T) {
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
	serveSigned(t, handler, privateB, "machine-b", http.MethodPut, "/v1/machines/me/endpoints", `{"endpoints":["agent/b/reviewer","agent/b/other"]}`, "advertise-b", "")
	created := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations", `{"creator_endpoint":"agent/a/session","members":[{"endpoint":"agent/a/session","capabilities":["send","receive","admin"],"role":"coordinator"},{"endpoint":"agent/b/reviewer","capabilities":["receive"],"role":"reviewer"},{"endpoint":"agent/b/other","capabilities":["receive"],"role":"implementer"}]}`, "create", "role-create")
	var conversation Conversation
	if created.Code != http.StatusCreated || json.NewDecoder(created.Body).Decode(&conversation) != nil {
		t.Fatalf("create=%d %s", created.Code, created.Body.String())
	}
	unauthorized := serveSigned(t, handler, privateB, "machine-b", http.MethodPut, "/v1/conversations/"+conversation.ID+"/memberships", `{"from_endpoint":"agent/b/reviewer","previous_endpoint":"agent/b/reviewer","member":{"endpoint":"agent/b/reviewer","capabilities":["receive"],"role":"implementer"}}`, "non-admin-change", "")
	if unauthorized.Code != http.StatusForbidden {
		t.Fatalf("non-admin change=%d %s", unauthorized.Code, unauthorized.Body.String())
	}
	message := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations/"+conversation.ID+"/messages", `{"from_endpoint":"agent/a/session","target_role":"reviewer","body":"please review"}`, "role-send", "role-send")
	if message.Code != http.StatusCreated {
		t.Fatalf("role send=%d %s", message.Code, message.Body.String())
	}
	missing := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations/"+conversation.ID+"/messages", `{"from_endpoint":"agent/a/session","target_role":"missing","body":"please review"}`, "missing-send", "missing-send")
	if missing.Code != http.StatusUnprocessableEntity || !strings.Contains(missing.Body.String(), "no eligible recipient") {
		t.Fatalf("missing role=%d %s", missing.Code, missing.Body.String())
	}
	leaseReviewer := serveSigned(t, handler, privateB, "machine-b", http.MethodPost, "/v1/deliveries/lease", `{"endpoint":"agent/b/reviewer","consumer_id":"reviewer-consumer"}`, "lease-reviewer", "")
	leaseOther := serveSigned(t, handler, privateB, "machine-b", http.MethodPost, "/v1/deliveries/lease", `{"endpoint":"agent/b/other","consumer_id":"other-consumer"}`, "lease-other", "")
	if !strings.Contains(leaseReviewer.Body.String(), "please review") || strings.Contains(leaseOther.Body.String(), "please review") {
		t.Fatalf("role leases reviewer=%s other=%s", leaseReviewer.Body.String(), leaseOther.Body.String())
	}
}

type principalEndpointRecordingBackend struct {
	Backend
	plainCalls     int
	principalCalls int
}

func (backend *principalEndpointRecordingBackend) AdvertiseEndpoints(machineID string, endpoints []string, now time.Time, ttl time.Duration) error {
	backend.plainCalls++
	return backend.Backend.AdvertiseEndpoints(machineID, endpoints, now, ttl)
}

func (backend *principalEndpointRecordingBackend) AdvertiseEndpointsForPrincipal(machineID string, _ PrincipalAuthority, endpoints []string, now time.Time, ttl time.Duration) error {
	backend.principalCalls++
	return backend.Backend.AdvertiseEndpoints(machineID, endpoints, now, ttl)
}

func TestHTTPEndpointAdvertisementUsesPrincipalBindingOnlyForDeviceBearer(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	auth, err := NewTransitionAuthenticator(store, []Machine{{ID: "machine-a", PublicKey: public, EndpointPrefixes: []string{"agent/a/"}}}, transitionAuthorityFunc(func(_ context.Context, credential string, legacyKey ed25519.PublicKey) (TransitionAuthorization, error) {
		if credential == "" && bytes.Equal(legacyKey, public) {
			return TransitionAuthorization{PrincipalID: "11111111-1111-4111-8111-111111111111", LegacyPublicKey: public, Current: func(context.Context) error { return nil }}, nil
		}
		if credential == testTransitionToken && legacyKey == nil {
			return TransitionAuthorization{PrincipalID: "11111111-1111-4111-8111-111111111111", CredentialLookupID: "22222222-2222-4222-8222-222222222222", CredentialGeneration: 1, LegacyPublicKey: public, Current: func(context.Context) error { return nil }}, nil
		}
		return TransitionAuthorization{}, ErrForbidden
	}))
	if err != nil {
		t.Fatal(err)
	}
	backend := &principalEndpointRecordingBackend{Backend: store}
	clock := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	handler := NewHandler(backend, auth, HandlerOptions{Now: func() time.Time { return clock }, EndpointLeaseTTL: time.Minute})
	legacy := serveSigned(t, handler, private, "machine-a", http.MethodPut, "/v1/machines/me/endpoints", `{"endpoints":["agent/a/legacy"]}`, "legacy-advertise", "")
	if legacy.Code != http.StatusOK || backend.plainCalls != 1 || backend.principalCalls != 0 {
		t.Fatalf("legacy status=%d plain=%d principal=%d body=%s", legacy.Code, backend.plainCalls, backend.principalCalls, legacy.Body.String())
	}
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/v1/machines/me/endpoints", strings.NewReader(`{"endpoints":["agent/a/device"]}`))
	request.Header.Set("Authorization", "Bearer "+testTransitionToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || backend.plainCalls != 1 || backend.principalCalls != 1 {
		t.Fatalf("device status=%d plain=%d principal=%d body=%s", response.Code, backend.plainCalls, backend.principalCalls, response.Body.String())
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

func TestHTTPInvokeIsAContentFreeOfflineRuntimeHandoff(t *testing.T) {
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
	notifier := NewNotifier()
	targetNotifications := notifier.Register("machine-b")
	t.Cleanup(targetNotifications.Close)
	handler := NewHandler(store, auth, HandlerOptions{Now: func() time.Time { return clock }, EndpointLeaseTTL: time.Minute, DeliveryLeaseTTL: time.Minute, Notifier: notifier})
	serveSigned(t, handler, privateA, "machine-a", http.MethodPut, "/v1/machines/me/endpoints", `{"endpoints":["agent/a/session"]}`, "invoke-advertise-a", "")
	serveSigned(t, handler, privateB, "machine-b", http.MethodPut, "/v1/machines/me/endpoints", `{"endpoints":["agent/b/session"]}`, "invoke-advertise-b", "")
	created := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations", `{"creator_endpoint":"agent/a/session","members":[{"endpoint":"agent/a/session","capabilities":["send","receive","admin","invoke"]},{"endpoint":"agent/b/session","capabilities":["receive"]}]}`, "invoke-create", "invoke-create")
	if created.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	var conversation Conversation
	if err := json.NewDecoder(created.Body).Decode(&conversation); err != nil {
		t.Fatal(err)
	}
	if response := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations/"+conversation.ID+"/messages", `{"from_endpoint":"agent/a/session","body":"opaque work"}`, "invoke-message", "invoke-message"); response.Code != http.StatusCreated {
		t.Fatalf("message status=%d body=%s", response.Code, response.Body.String())
	}
	if response := serveSigned(t, handler, privateB, "machine-b", http.MethodPut, "/v1/machines/me/endpoints", `{"endpoints":[]}`, "invoke-detach-b", ""); response.Code != http.StatusOK {
		t.Fatalf("detach status=%d body=%s", response.Code, response.Body.String())
	}
	requested := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations/"+conversation.ID+"/invocations", `{"from_endpoint":"agent/a/session","target_endpoint":"agent/b/session"}`, "invoke-request", "invoke-request")
	if requested.Code != http.StatusCreated || strings.Contains(requested.Body.String(), "opaque work") {
		t.Fatalf("invoke status=%d body=%s", requested.Code, requested.Body.String())
	}
	select {
	case wake := <-targetNotifications.Events():
		if wake.Type != "wake" || wake.TopicID != conversation.ID || wake.Sequence != 1 {
			t.Fatalf("invoke wake=%#v", wake)
		}
	case <-time.After(time.Second):
		t.Fatal("invoke request did not wake target adapter")
	}
	var invocation Invocation
	if err := json.NewDecoder(requested.Body).Decode(&invocation); err != nil || invocation.ID == "" || invocation.Fence == "" || invocation.TargetMachineID != "machine-b" {
		t.Fatalf("invocation=%#v err=%v", invocation, err)
	}
	lease := serveSigned(t, handler, privateB, "machine-b", http.MethodPost, "/v1/invocations/lease", `{"consumer_id":"adapter-b"}`, "invoke-lease", "")
	if lease.Code != http.StatusOK || strings.Contains(lease.Body.String(), "opaque work") {
		t.Fatalf("lease status=%d body=%s", lease.Code, lease.Body.String())
	}
	var leased struct {
		Invocations []Invocation `json:"invocations"`
	}
	if err := json.NewDecoder(lease.Body).Decode(&leased); err != nil || len(leased.Invocations) != 1 || leased.Invocations[0].ID != invocation.ID {
		t.Fatalf("leased=%#v err=%v", leased, err)
	}
	outcomeBody, err := json.Marshal(map[string]any{"lease_token": leased.Invocations[0].LeaseToken, "lease_generation": leased.Invocations[0].LeaseGeneration, "accepted": true})
	if err != nil {
		t.Fatal(err)
	}
	if response := serveSigned(t, handler, privateB, "machine-b", http.MethodPost, "/v1/invocations/"+invocation.ID+"/outcome", string(outcomeBody), "invoke-outcome", ""); response.Code != http.StatusNoContent {
		t.Fatalf("outcome status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestHTTPInvocationLeaseRejectsOutOfScopeTargetWithoutRetry(t *testing.T) {
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
		{ID: "machine-b", PublicKey: publicB, EndpointPrefixes: []string{"agent/b/allowed/"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	notifier := NewNotifier()
	targetNotifications := notifier.Register("machine-b")
	t.Cleanup(targetNotifications.Close)
	handler := NewHandler(store, auth, HandlerOptions{Now: func() time.Time { return clock }, EndpointLeaseTTL: time.Minute, DeliveryLeaseTTL: time.Minute, Notifier: notifier})
	serveSigned(t, handler, privateA, "machine-a", http.MethodPut, "/v1/machines/me/endpoints", `{"endpoints":["agent/a/session"]}`, "scope-advertise-a", "")
	// Simulate a persisted role whose machine's enrollment was narrowed after it
	// was recorded. The direct store setup deliberately bypasses HTTP's current
	// scope check so the lease route has to contain the old work safely.
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b/out-of-scope"}, clock, time.Hour); err != nil {
		t.Fatal(err)
	}
	created := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations", `{"creator_endpoint":"agent/a/session","members":[{"endpoint":"agent/a/session","capabilities":["send","receive","admin","invoke"]},{"endpoint":"agent/b/out-of-scope","capabilities":["receive"]}]}`, "scope-create", "scope-create")
	if created.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	var conversation Conversation
	if err := json.NewDecoder(created.Body).Decode(&conversation); err != nil {
		t.Fatal(err)
	}
	if response := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations/"+conversation.ID+"/messages", `{"from_endpoint":"agent/a/session","body":"opaque work"}`, "scope-message", "scope-message"); response.Code != http.StatusCreated {
		t.Fatalf("message status=%d body=%s", response.Code, response.Body.String())
	}
	select {
	case <-targetNotifications.Events():
		// The ordinary message notification is expected. The assertion below
		// verifies that the invocation itself adds no out-of-scope wake hint.
	case <-time.After(time.Second):
		t.Fatal("message did not wake target machine")
	}
	if err := store.AdvertiseEndpoints("machine-b", nil, clock, time.Hour); err != nil {
		t.Fatal(err)
	}
	requested := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations/"+conversation.ID+"/invocations", `{"from_endpoint":"agent/a/session","target_endpoint":"agent/b/out-of-scope"}`, "scope-invoke", "scope-invoke")
	if requested.Code != http.StatusCreated {
		t.Fatalf("invoke status=%d body=%s", requested.Code, requested.Body.String())
	}
	var invocation Invocation
	if err := json.NewDecoder(requested.Body).Decode(&invocation); err != nil {
		t.Fatal(err)
	}
	select {
	case wake := <-targetNotifications.Events():
		t.Fatalf("out-of-scope target received wake=%#v", wake)
	case <-time.After(20 * time.Millisecond):
	}
	lease := serveSigned(t, handler, privateB, "machine-b", http.MethodPost, "/v1/invocations/lease", `{"consumer_id":"adapter-b"}`, "scope-lease", "")
	if lease.Code != http.StatusOK || lease.Body.String() != `{"invocations":[]}`+"\n" {
		t.Fatalf("lease status=%d body=%s", lease.Code, lease.Body.String())
	}
	var status InvocationStatus
	var attempts int
	if err := store.db.QueryRowContext(context.Background(), `SELECT status,attempts FROM invocations WHERE id=?`, invocation.ID).Scan(&status, &attempts); err != nil {
		t.Fatal(err)
	}
	if status != InvocationFailed || attempts != 1 {
		t.Fatalf("status=%q attempts=%d", status, attempts)
	}
	if leased, err := store.LeaseInvocations("machine-b", "adapter-b", clock.Add(time.Hour), time.Minute, 1); err != nil || len(leased) != 0 {
		t.Fatalf("terminalized invocation leased=%#v err=%v", leased, err)
	}
	audit, err := store.InvocationAudit(invocation.ID)
	if err != nil || len(audit) != 3 || audit[0].Action != "requested" || audit[1].Action != "leased" || audit[2].Action != "failed" {
		t.Fatalf("audit=%#v err=%v", audit, err)
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
		return TransitionAuthorization{PrincipalID: "11111111-1111-4111-8111-111111111111", CredentialLookupID: "22222222-2222-4222-8222-222222222222", CredentialGeneration: 1, LegacyPublicKey: public, Current: func(ctx context.Context) error {
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
	if _, _, err := connection.Read(readCtx); err == nil {
		t.Fatal("unavailable transition authority left notification socket open")
	} else if readCtx.Err() != nil {
		t.Fatalf("notification socket did not close before the test deadline: %v", err)
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
