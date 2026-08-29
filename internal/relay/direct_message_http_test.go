package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPDirectMessageCreatesAndRetriesWithoutExposingSession(t *testing.T) {
	handler, privateA, privateB := newRoleRegisterHandler(t)
	if response := serveSigned(t, handler, privateA, "machine-a", http.MethodPut, "/v1/machines/me/endpoints", `{"endpoints":["agent/a/session"]}`, "advertise-a", ""); response.Code != http.StatusOK {
		t.Fatalf("advertise a status=%d body=%s", response.Code, response.Body.String())
	}
	if response := serveSigned(t, handler, privateB, "machine-b", http.MethodPut, "/v1/machines/me/endpoints", `{"endpoints":["agent/b/session"]}`, "advertise-b", ""); response.Code != http.StatusOK {
		t.Fatalf("advertise b status=%d body=%s", response.Code, response.Body.String())
	}
	if response := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/roles/register", `{"role":"role/machine-a/reviewer","direct_addressable":true}`, "reg-a", "reg-a"); response.Code != http.StatusCreated {
		t.Fatalf("register a status=%d body=%s", response.Code, response.Body.String())
	}
	if response := serveSigned(t, handler, privateB, "machine-b", http.MethodPost, "/v1/roles/register", `{"role":"role/machine-b/implementer","direct_addressable":true}`, "reg-b", "reg-b"); response.Code != http.StatusCreated {
		t.Fatalf("register b status=%d body=%s", response.Code, response.Body.String())
	}
	if response := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/roles/bindings", `{"role":"role/machine-a/reviewer","session_endpoint":"agent/a/session"}`, "bind-a", ""); response.Code != http.StatusNoContent {
		t.Fatalf("bind a status=%d body=%s", response.Code, response.Body.String())
	}
	if response := serveSigned(t, handler, privateB, "machine-b", http.MethodPost, "/v1/roles/bindings", `{"role":"role/machine-b/implementer","session_endpoint":"agent/b/session"}`, "bind-b", ""); response.Code != http.StatusNoContent {
		t.Fatalf("bind b status=%d body=%s", response.Code, response.Body.String())
	}

	first := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/direct-messages", `{"from_role":"role/machine-a/reviewer","to_role":"role/machine-b/implementer","body":"please review"}`, "dm-1", "dm-1")
	if first.Code != http.StatusCreated {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	var message Message
	if err := json.NewDecoder(first.Body).Decode(&message); err != nil {
		t.Fatal(err)
	}
	if message.FromRole != "role/machine-a/reviewer" || message.FromEndpoint != "" || message.ConversationID == "" || message.Body != "please review" {
		t.Fatalf("message=%#v", message)
	}
	if encoded, err := json.Marshal(message); err != nil || strings.Contains(string(encoded), "from_endpoint") || strings.Contains(string(encoded), "agent/a") {
		t.Fatalf("response leaked session: %s err=%v", encoded, err)
	}

	retry := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/direct-messages", `{"from_role":"role/machine-a/reviewer","to_role":"role/machine-b/implementer","body":"please review"}`, "dm-retry", "dm-1")
	if retry.Code != http.StatusOK {
		t.Fatalf("retry status=%d body=%s", retry.Code, retry.Body.String())
	}
	var repeated Message
	if err := json.NewDecoder(retry.Body).Decode(&repeated); err != nil || repeated != message {
		t.Fatalf("retry=%#v want=%#v err=%v", repeated, message, err)
	}

	lease := serveSigned(t, handler, privateB, "machine-b", http.MethodPost, "/v1/deliveries/lease", `{"endpoint":"agent/b/session","consumer_id":"consumer-b"}`, "lease-b", "")
	if lease.Code != http.StatusOK {
		t.Fatalf("lease status=%d body=%s", lease.Code, lease.Body.String())
	}
	var page DeliveryLeasePage
	if err := json.NewDecoder(lease.Body).Decode(&page); err != nil || len(page.Deliveries) != 1 {
		t.Fatalf("lease page=%s err=%v", lease.Body.String(), err)
	}
	if page.Deliveries[0].RecipientRole != "role/machine-b/implementer" || page.Deliveries[0].Message.FromRole != "role/machine-a/reviewer" || page.Deliveries[0].Message.FromEndpoint != "" {
		t.Fatalf("leased delivery=%#v", page.Deliveries[0])
	}
}

func TestHTTPDirectMessageRejectsMalformedAndUnauthorizedRequests(t *testing.T) {
	handler, privateA, privateB := newRoleRegisterHandler(t)
	if response := serveSigned(t, handler, privateA, "machine-a", http.MethodPut, "/v1/machines/me/endpoints", `{"endpoints":["agent/a/session"]}`, "advertise-a", ""); response.Code != http.StatusOK {
		t.Fatalf("advertise a status=%d body=%s", response.Code, response.Body.String())
	}
	if response := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/roles/register", `{"role":"role/machine-a/reviewer","direct_addressable":true}`, "reg-a", "reg-a"); response.Code != http.StatusCreated {
		t.Fatalf("register a status=%d body=%s", response.Code, response.Body.String())
	}
	if response := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/roles/bindings", `{"role":"role/machine-a/reviewer","session_endpoint":"agent/a/session"}`, "bind-a", ""); response.Code != http.StatusNoContent {
		t.Fatalf("bind a status=%d body=%s", response.Code, response.Body.String())
	}

	unsigned := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/direct-messages", bytes.NewBufferString(`{"from_role":"role/machine-a/reviewer","to_role":"role/machine-b/implementer","body":"x"}`))
	unsigned.Header.Set("Content-Type", "application/json")
	unsigned.Header.Set("Idempotency-Key", "unsigned")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, unsigned)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned status=%d body=%s", response.Code, response.Body.String())
	}

	tests := []struct {
		name, body, nonce, key string
		want                   int
	}{
		{name: "missing key", body: `{"from_role":"role/machine-a/reviewer","to_role":"role/machine-b/implementer","body":"x"}`, nonce: "missing", key: "", want: http.StatusBadRequest},
		{name: "unknown field", body: `{"from_role":"role/machine-a/reviewer","to_role":"role/machine-b/implementer","body":"x","from_endpoint":"agent/a/session"}`, nonce: "unknown", key: "unknown", want: http.StatusBadRequest},
		{name: "self send", body: `{"from_role":"role/machine-a/reviewer","to_role":"role/machine-a/reviewer","body":"x"}`, nonce: "self", key: "self", want: http.StatusBadRequest},
		{name: "missing target", body: `{"from_role":"role/machine-a/reviewer","to_role":"role/machine-b/missing","body":"x"}`, nonce: "missing-target", key: "missing-target", want: http.StatusForbidden},
		{name: "query string", body: `{"from_role":"role/machine-a/reviewer","to_role":"role/machine-b/implementer","body":"x"}`, nonce: "query", key: "query", want: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "query string" {
				clock := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/direct-messages?limit=1", test.body, test.nonce, test.key)
				if clock.Code != test.want {
					t.Fatalf("status=%d body=%s want=%d", clock.Code, clock.Body.String(), test.want)
				}
				return
			}
			got := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/direct-messages", test.body, test.nonce, test.key)
			if got.Code != test.want {
				t.Fatalf("status=%d body=%s want=%d", got.Code, got.Body.String(), test.want)
			}
		})
	}
	stolen := serveSigned(t, handler, privateB, "machine-b", http.MethodPost, "/v1/direct-messages", `{"from_role":"role/machine-a/reviewer","to_role":"role/machine-b/implementer","body":"x"}`, "stolen", "stolen")
	if stolen.Code != http.StatusBadRequest && stolen.Code != http.StatusForbidden {
		t.Fatalf("stolen status=%d body=%s", stolen.Code, stolen.Body.String())
	}
}

func TestHTTPDirectConversationRejectsGenericAppendAfterOptOut(t *testing.T) {
	handler, privateA, privateB := newRoleRegisterHandler(t)
	if response := serveSigned(t, handler, privateA, "machine-a", http.MethodPut, "/v1/machines/me/endpoints", `{"endpoints":["agent/a/session"]}`, "advertise-a", ""); response.Code != http.StatusOK {
		t.Fatalf("advertise a status=%d body=%s", response.Code, response.Body.String())
	}
	if response := serveSigned(t, handler, privateB, "machine-b", http.MethodPut, "/v1/machines/me/endpoints", `{"endpoints":["agent/b/session"]}`, "advertise-b", ""); response.Code != http.StatusOK {
		t.Fatalf("advertise b status=%d body=%s", response.Code, response.Body.String())
	}
	if response := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/roles/register", `{"role":"role/machine-a/reviewer","direct_addressable":true}`, "reg-a", "reg-a"); response.Code != http.StatusCreated {
		t.Fatalf("register a status=%d body=%s", response.Code, response.Body.String())
	}
	if response := serveSigned(t, handler, privateB, "machine-b", http.MethodPost, "/v1/roles/register", `{"role":"role/machine-b/implementer","direct_addressable":true}`, "reg-b", "reg-b"); response.Code != http.StatusCreated {
		t.Fatalf("register b status=%d body=%s", response.Code, response.Body.String())
	}
	if response := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/roles/bindings", `{"role":"role/machine-a/reviewer","session_endpoint":"agent/a/session"}`, "bind-a", ""); response.Code != http.StatusNoContent {
		t.Fatalf("bind a status=%d body=%s", response.Code, response.Body.String())
	}
	if response := serveSigned(t, handler, privateB, "machine-b", http.MethodPost, "/v1/roles/bindings", `{"role":"role/machine-b/implementer","session_endpoint":"agent/b/session"}`, "bind-b", ""); response.Code != http.StatusNoContent {
		t.Fatalf("bind b status=%d body=%s", response.Code, response.Body.String())
	}
	first := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/direct-messages", `{"from_role":"role/machine-a/reviewer","to_role":"role/machine-b/implementer","body":"please review"}`, "dm-1", "dm-1")
	if first.Code != http.StatusCreated {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	var message Message
	if err := json.NewDecoder(first.Body).Decode(&message); err != nil {
		t.Fatal(err)
	}
	create := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations", `{"creator_endpoint":"agent/a/session","members":[{"endpoint":"agent/a/session","capabilities":["send","receive","admin"]},{"endpoint":"agent/b/session","capabilities":["send","receive"]}]}`, "create-named", "create-named")
	if create.Code != http.StatusCreated {
		t.Fatalf("named create status=%d body=%s", create.Code, create.Body.String())
	}
	var named struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(create.Body).Decode(&named); err != nil {
		t.Fatal(err)
	}
	bypass := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations/"+message.ConversationID+"/messages", `{"from_endpoint":"agent/a/session","body":"bypass"}`, "append-direct", "append-direct")
	if bypass.Code != http.StatusForbidden {
		t.Fatalf("direct append status=%d body=%s", bypass.Code, bypass.Body.String())
	}
	if response := serveSigned(t, handler, privateB, "machine-b", http.MethodPost, "/v1/roles/register", `{"role":"role/machine-b/implementer","direct_addressable":false}`, "opt-out", "opt-out"); response.Code != http.StatusOK && response.Code != http.StatusCreated {
		t.Fatalf("opt-out status=%d body=%s", response.Code, response.Body.String())
	}
	afterOptOut := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations/"+message.ConversationID+"/messages", `{"from_endpoint":"agent/a/session","body":"after opt-out"}`, "append-opt-out", "append-opt-out")
	if afterOptOut.Code != http.StatusForbidden {
		t.Fatalf("opt-out append status=%d body=%s", afterOptOut.Code, afterOptOut.Body.String())
	}
	namedSend := serveSigned(t, handler, privateA, "machine-a", http.MethodPost, "/v1/conversations/"+named.ID+"/messages", `{"from_endpoint":"agent/a/session","body":"named room still works"}`, "append-named", "append-named")
	if namedSend.Code != http.StatusCreated {
		t.Fatalf("named append status=%d body=%s", namedSend.Code, namedSend.Body.String())
	}
}
