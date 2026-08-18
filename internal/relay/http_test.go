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

func TestHTTPTargetRoleRoutesExclusivelyAndBroadcastRemainsCompatible(t *testing.T) {
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
	now := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	handler := NewHandler(store, auth, HandlerOptions{Now: func() time.Time { return now }, EndpointLeaseTTL: time.Minute, DeliveryLeaseTTL: time.Minute})
	serveSigned(t, handler, privateA, "machine-a", http.MethodPut, "/v1/machines/me/endpoints", `{"endpoints":["agent/a/session"]}`, "target-advertise-a", "")
	serveSigned(t, handler, privateB, "machine-b", http.MethodPut, "/v1/machines/me/endpoints", `{"endpoints":["agent/b/session"]}`, "target-advertise-b", "")
	created := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations", `{"creator_endpoint":"agent/a/session","members":[{"endpoint":"agent/a/session","capabilities":["send","receive","admin"]},{"endpoint":"agent/b/session","capabilities":["receive"]},{"role":"role/reviewer","role_machine_id":"machine-b","capabilities":["receive"]},{"role":"role/implementer","role_machine_id":"machine-b","capabilities":["receive"]}]}`, "target-create", "target-create")
	var conversation Conversation
	if created.Code != http.StatusCreated || json.NewDecoder(created.Body).Decode(&conversation) != nil {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	for index, role := range []string{"role/reviewer", "role/implementer"} {
		bound := serveSigned(t, handler, privateB, "machine-b", http.MethodPost, "/v1/roles/bindings", `{"role":"`+role+`","session_endpoint":"agent/b/session"}`, "target-bind-"+string(rune('a'+index)), "")
		if bound.Code != http.StatusNoContent {
			t.Fatalf("bind %s status=%d body=%s", role, bound.Code, bound.Body.String())
		}
	}
	targeted := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations/"+conversation.ID+"/messages", `{"from_endpoint":"agent/a/session","target_role":"role/reviewer","body":"review this"}`, "target-send", "target-send")
	if targeted.Code != http.StatusCreated {
		t.Fatalf("targeted status=%d body=%s", targeted.Code, targeted.Body.String())
	}
	lease := serveSigned(t, handler, privateB, "machine-b", http.MethodPost, "/v1/deliveries/lease", `{"endpoint":"agent/b/session","consumer_id":"target-consumer"}`, "target-lease", "")
	var targetedPage DeliveryLeasePage
	if lease.Code != http.StatusOK || json.NewDecoder(lease.Body).Decode(&targetedPage) != nil || len(targetedPage.Deliveries) != 1 {
		t.Fatalf("targeted lease status=%d page=%#v body=%s", lease.Code, targetedPage, lease.Body.String())
	}
	if targetedPage.Deliveries[0].RecipientRole != "role/reviewer" {
		t.Fatalf("targeted lease recipient role=%q", targetedPage.Deliveries[0].RecipientRole)
	}
	if err := store.AckDelivery("machine-b", "agent/b/session", targetedPage.Deliveries[0].ID, targetedPage.Deliveries[0].LeaseToken, targetedPage.Deliveries[0].LeaseGeneration, now); err != nil {
		t.Fatal(err)
	}
	broadcast := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations/"+conversation.ID+"/messages", `{"from_endpoint":"agent/a/session","body":"broadcast"}`, "broadcast-send", "broadcast-send")
	if broadcast.Code != http.StatusCreated {
		t.Fatalf("broadcast status=%d body=%s", broadcast.Code, broadcast.Body.String())
	}
	broadcastLease := serveSigned(t, handler, privateB, "machine-b", http.MethodPost, "/v1/deliveries/lease", `{"endpoint":"agent/b/session","consumer_id":"target-consumer"}`, "broadcast-lease", "")
	var broadcastPage DeliveryLeasePage
	if broadcastLease.Code != http.StatusOK || json.NewDecoder(broadcastLease.Body).Decode(&broadcastPage) != nil || len(broadcastPage.Deliveries) != 3 {
		t.Fatalf("broadcast lease status=%d page=%#v body=%s", broadcastLease.Code, broadcastPage, broadcastLease.Body.String())
	}
	roles := map[string]int{"": 0, "role/reviewer": 0, "role/implementer": 0}
	for _, delivery := range broadcastPage.Deliveries {
		roles[delivery.RecipientRole]++
	}
	if roles[""] != 1 || roles["role/reviewer"] != 1 || roles["role/implementer"] != 1 || len(roles) != 3 {
		t.Fatalf("broadcast recipient roles=%v", roles)
	}
	missing := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations/"+conversation.ID+"/messages", `{"from_endpoint":"agent/a/session","target_role":"role/missing","body":"nobody"}`, "missing-target", "missing-target")
	if missing.Code != http.StatusForbidden {
		t.Fatalf("missing target status=%d body=%s", missing.Code, missing.Body.String())
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

func TestHTTPControlsRequireAdminAndKeepAuditOutOfMessageBodies(t *testing.T) {
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
	now := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	handler := NewHandler(store, auth, HandlerOptions{Now: func() time.Time { return now }, EndpointLeaseTTL: time.Hour})
	serveSigned(t, handler, privateA, "machine-a", http.MethodPut, "/v1/machines/me/endpoints", `{"endpoints":["agent/a/session"]}`, "advertise-a", "")
	serveSigned(t, handler, privateB, "machine-b", http.MethodPut, "/v1/machines/me/endpoints", `{"endpoints":["agent/b/session"]}`, "advertise-b", "")
	created := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations", `{"creator_endpoint":"agent/a/session","members":[{"endpoint":"agent/a/session","capabilities":["send","receive","admin"]},{"endpoint":"agent/b/session","capabilities":["receive"]}]}`, "create", "create-1")
	var conversation Conversation
	if created.Code != http.StatusCreated || json.NewDecoder(created.Body).Decode(&conversation) != nil {
		t.Fatalf("create=%d %s", created.Code, created.Body.String())
	}
	body := `{"actor_endpoint":"agent/a/session","operation":"upsert_member","member":{"endpoint":"agent/b/session","capabilities":["send","receive"]}}`
	first := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations/"+conversation.ID+"/controls", body, "control-first", "control-1")
	if first.Code != http.StatusCreated {
		t.Fatalf("control=%d %s", first.Code, first.Body.String())
	}
	retry := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations/"+conversation.ID+"/controls", body, "control-retry", "control-1")
	if retry.Code != http.StatusOK {
		t.Fatalf("control retry=%d %s", retry.Code, retry.Body.String())
	}
	denied := serveSigned(t, handler, privateB, "machine-b", http.MethodPost, "/v1/conversations/"+conversation.ID+"/controls", `{"actor_endpoint":"agent/b/session","operation":"remove_member","member":{"endpoint":"agent/a/session"}}`, "control-denied", "control-2")
	if denied.Code != http.StatusForbidden {
		t.Fatalf("non-admin control=%d %s", denied.Code, denied.Body.String())
	}
	audit := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations/"+conversation.ID+"/controls/audit", `{"actor_endpoint":"agent/a/session"}`, "audit", "")
	var response struct {
		Events []ControlEvent `json:"events"`
	}
	if audit.Code != http.StatusOK || json.NewDecoder(audit.Body).Decode(&response) != nil || len(response.Events) != 1 || response.Events[0].Operation != ControlUpsertMember {
		t.Fatalf("audit=%d %s %#v", audit.Code, audit.Body.String(), response)
	}
	var messages int
	if err := store.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM messages").Scan(&messages); err != nil || messages != 0 {
		t.Fatalf("control entered message plane: %d %v", messages, err)
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

func TestHTTPRoleBindingRequiresOwningMachineAndLiveSession(t *testing.T) {
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
	now := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	handler := NewHandler(store, auth, HandlerOptions{Now: func() time.Time { return now }, EndpointLeaseTTL: time.Minute})
	serveSigned(t, handler, privateA, "machine-a", http.MethodPut, "/v1/machines/me/endpoints", `{"endpoints":["agent/a/session"]}`, "advertise-a", "")
	serveSigned(t, handler, privateB, "machine-b", http.MethodPut, "/v1/machines/me/endpoints", `{"endpoints":["agent/b/session"]}`, "advertise-b", "")
	if response := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations", `{"creator_endpoint":"agent/a/session","members":[{"endpoint":"agent/a/session","capabilities":["send","receive","admin"]},{"role":"role/plan-reviewer","role_machine_id":"machine-b","capabilities":["receive","invoke"]}]}`, "create-role-invoke", "create-role-invoke-1"); response.Code != http.StatusBadRequest {
		t.Fatalf("role invoke capability status=%d body=%s", response.Code, response.Body.String())
	}
	create := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations", `{"creator_endpoint":"agent/a/session","members":[{"endpoint":"agent/a/session","capabilities":["send","receive","admin"]},{"role":"role/plan-reviewer","role_machine_id":"machine-b","capabilities":["receive"]}]}`, "create-role", "create-role-1")
	if create.Code != http.StatusCreated {
		t.Fatalf("create role conversation status=%d body=%s", create.Code, create.Body.String())
	}
	if response := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/roles/bindings", `{"role":"role/plan-reviewer","session_endpoint":"agent/a/session"}`, "bind-other-machine", ""); response.Code != http.StatusForbidden {
		t.Fatalf("cross-machine role bind status=%d body=%s", response.Code, response.Body.String())
	}
	if response := serveSigned(t, handler, privateB, "machine-b", http.MethodPost, "/v1/roles/bindings", `{"role":"role/plan-reviewer","session_endpoint":"agent/b/session"}`, "bind-owner", ""); response.Code != http.StatusNoContent {
		t.Fatalf("owner role bind status=%d body=%s", response.Code, response.Body.String())
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

func TestHTTPAppendRateLimitIsRetryableAndContentFree(t *testing.T) {
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
	if err := store.SetRateLimits(tightRateLimits()); err != nil {
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
	serveSigned(t, handler, privateA, "machine-a", http.MethodPut, "/v1/machines/me/endpoints", `{"endpoints":["agent/a/session"]}`, "rate-advertise-a", "")
	serveSigned(t, handler, privateB, "machine-b", http.MethodPut, "/v1/machines/me/endpoints", `{"endpoints":["agent/b/session"]}`, "rate-advertise-b", "")
	create := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations", `{"creator_endpoint":"agent/a/session","members":[{"endpoint":"agent/a/session","capabilities":["send","receive","admin"]},{"endpoint":"agent/b/session","capabilities":["receive"]}]}`, "rate-create", "rate-create")
	var conversation Conversation
	if create.Code != http.StatusCreated || json.NewDecoder(create.Body).Decode(&conversation) != nil {
		t.Fatalf("create status=%d body=%s", create.Code, create.Body.String())
	}
	first := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations/"+conversation.ID+"/messages", `{"from_endpoint":"agent/a/session","body":"one"}`, "rate-send-1", "rate-send-1")
	second := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations/"+conversation.ID+"/messages", `{"from_endpoint":"agent/a/session","body":"two"}`, "rate-send-2", "rate-send-2")
	if first.Code != http.StatusCreated || second.Code != http.StatusCreated {
		t.Fatalf("accepted status first=%d second=%d", first.Code, second.Code)
	}
	replay := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations/"+conversation.ID+"/messages", `{"from_endpoint":"agent/a/session","body":"one"}`, "rate-send-1-retry", "rate-send-1")
	if replay.Code != http.StatusOK {
		t.Fatalf("committed retry status=%d body=%s", replay.Code, replay.Body.String())
	}
	limited := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations/"+conversation.ID+"/messages", `{"from_endpoint":"agent/a/session","body":"three"}`, "rate-send-3", "rate-send-3")
	if limited.Code != http.StatusTooManyRequests {
		t.Fatalf("limited status=%d body=%s", limited.Code, limited.Body.String())
	}
	if limited.Header().Get("Retry-After") != "1" {
		t.Fatalf("Retry-After=%q", limited.Header().Get("Retry-After"))
	}
	body := limited.Body.String()
	if !strings.Contains(body, `"error":"rate limited"`) || strings.Contains(body, conversation.ID) || strings.Contains(body, "three") || strings.Contains(body, "agent/") {
		t.Fatalf("limited body leaked content: %s", body)
	}
	if snapshot := metrics.Snapshot(); snapshot.RelayRateLimitRejections != 1 {
		t.Fatalf("metrics=%#v", snapshot)
	}
}

func TestHTTPAppendCapacityExceededIsRetryableAndContentFree(t *testing.T) {
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
	if err := store.SetQuotaLimits(tightQuota(1, 1024, 8, 4096)); err != nil {
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
	serveSigned(t, handler, privateA, "machine-a", http.MethodPut, "/v1/machines/me/endpoints", `{"endpoints":["agent/a/session"]}`, "quota-advertise-a", "")
	serveSigned(t, handler, privateB, "machine-b", http.MethodPut, "/v1/machines/me/endpoints", `{"endpoints":["agent/b/session"]}`, "quota-advertise-b", "")
	create := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations", `{"creator_endpoint":"agent/a/session","members":[{"endpoint":"agent/a/session","capabilities":["send","receive","admin"]},{"endpoint":"agent/b/session","capabilities":["receive"]}]}`, "quota-create", "quota-create")
	var conversation Conversation
	if create.Code != http.StatusCreated || json.NewDecoder(create.Body).Decode(&conversation) != nil {
		t.Fatalf("create status=%d body=%s", create.Code, create.Body.String())
	}
	first := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations/"+conversation.ID+"/messages", `{"from_endpoint":"agent/a/session","body":"one"}`, "quota-send-1", "quota-send-1")
	if first.Code != http.StatusCreated {
		t.Fatalf("accepted status=%d body=%s", first.Code, first.Body.String())
	}
	replay := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations/"+conversation.ID+"/messages", `{"from_endpoint":"agent/a/session","body":"one"}`, "quota-send-1-retry", "quota-send-1")
	if replay.Code != http.StatusOK {
		t.Fatalf("committed retry status=%d body=%s", replay.Code, replay.Body.String())
	}
	limited := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations/"+conversation.ID+"/messages", `{"from_endpoint":"agent/a/session","body":"two"}`, "quota-send-2", "quota-send-2")
	if limited.Code != http.StatusTooManyRequests {
		t.Fatalf("limited status=%d body=%s", limited.Code, limited.Body.String())
	}
	if limited.Header().Get("Retry-After") != "9" {
		t.Fatalf("Retry-After=%q", limited.Header().Get("Retry-After"))
	}
	body := limited.Body.String()
	if !strings.Contains(body, `"error":"capacity exceeded"`) || strings.Contains(body, "rate limited") || strings.Contains(body, conversation.ID) || strings.Contains(body, "two") || strings.Contains(body, "agent/") {
		t.Fatalf("limited body leaked content: %s", body)
	}
	snapshot := metrics.Snapshot()
	if snapshot.RelayCapacityRejections != 1 || snapshot.RelayPendingDeliveries != 1 || snapshot.RelayPendingBytes != 3 {
		t.Fatalf("metrics=%#v", snapshot)
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

func TestHTTPDoesNotExposeTerminalInventory(t *testing.T) {
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
	handler := NewHandler(store, auth, HandlerOptions{Now: func() time.Time { return clock }, EndpointLeaseTTL: time.Minute, DeliveryLeaseTTL: time.Minute})
	for _, path := range []string{"/v1/terminals", "/v1/deliveries/terminals", "/v1/dead-letters"} {
		nonce := strings.ReplaceAll(path, "/", "-")
		response := serveSigned(t, handler, private, "machine-a", http.MethodGet, path, "", "get"+nonce, "")
		if response.Code != http.StatusNotFound {
			t.Fatalf("path=%s status=%d body=%s", path, response.Code, response.Body.String())
		}
		posted := serveSigned(t, handler, private, "machine-a", http.MethodPost, path, `{}`, "post"+nonce, "")
		if posted.Code != http.StatusNotFound {
			t.Fatalf("post path=%s status=%d body=%s", path, posted.Code, posted.Body.String())
		}
	}
}
