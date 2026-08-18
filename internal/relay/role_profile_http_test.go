package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHTTPRoleRegisterValidAndExactRetry(t *testing.T) {
	handler, private, _ := newRoleRegisterHandler(t)
	first := serveSigned(t, handler, private, "machine-a", http.MethodPost, "/v1/roles/register", `{"role":"role/machine-a/reviewer","display_name":"  Reviewer  "}`, "register-1", "register-1")
	if first.Code != http.StatusCreated {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	var profile RoleProfile
	if err := json.NewDecoder(first.Body).Decode(&profile); err != nil {
		t.Fatal(err)
	}
	if profile.Role != "role/machine-a/reviewer" || profile.DisplayName != "Reviewer" || profile.DirectAddressable {
		t.Fatalf("profile=%#v", profile)
	}
	if encoded, err := json.Marshal(profile); err != nil || strings.Contains(string(encoded), "endpoint") || strings.Contains(string(encoded), "binding") || strings.Contains(string(encoded), "conversation") {
		t.Fatalf("response leaked inventory: %s err=%v", encoded, err)
	}
	retry := serveSigned(t, handler, private, "machine-a", http.MethodPost, "/v1/roles/register", `{"role":"role/machine-a/reviewer","display_name":"  Reviewer  "}`, "register-retry", "register-1")
	if retry.Code != http.StatusOK {
		t.Fatalf("retry status=%d body=%s", retry.Code, retry.Body.String())
	}
	var repeated RoleProfile
	if err := json.NewDecoder(retry.Body).Decode(&repeated); err != nil || repeated != profile {
		t.Fatalf("retry=%#v want=%#v err=%v", repeated, profile, err)
	}
}

func TestHTTPRoleRegisterRejectsChangedIdempotencyAndMalformedJSON(t *testing.T) {
	handler, private, _ := newRoleRegisterHandler(t)
	first := serveSigned(t, handler, private, "machine-a", http.MethodPost, "/v1/roles/register", `{"role":"role/machine-a/reviewer"}`, "register-1", "register-1")
	if first.Code != http.StatusCreated {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	tests := []struct {
		name, body, nonce, key string
		want                   int
	}{
		{name: "changed body", body: `{"role":"role/machine-a/reviewer","direct_addressable":true}`, nonce: "changed", key: "register-1", want: http.StatusConflict},
		{name: "unknown field", body: `{"role":"role/machine-a/reviewer","machine":"machine-a"}`, nonce: "unknown", key: "unknown-1", want: http.StatusBadRequest},
		{name: "trailing json", body: `{"role":"role/machine-a/reviewer"}{"extra":true}`, nonce: "trailing", key: "trailing-1", want: http.StatusBadRequest},
		{name: "invalid slug", body: `{"role":"role/machine-a/Reviewer"}`, nonce: "slug", key: "slug-1", want: http.StatusBadRequest},
		{name: "wrong prefix", body: `{"role":"role/machine-b/reviewer"}`, nonce: "prefix", key: "prefix-1", want: http.StatusBadRequest},
		{name: "oversized display name", body: `{"role":"role/machine-a/reviewer","display_name":"` + strings.Repeat("n", 129) + `"}`, nonce: "display", key: "display-1", want: http.StatusBadRequest},
		{name: "missing idempotency key", body: `{"role":"role/machine-a/reviewer"}`, nonce: "missing-key", key: "", want: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := serveSigned(t, handler, private, "machine-a", http.MethodPost, "/v1/roles/register", test.body, test.nonce, test.key)
			if response.Code != test.want {
				t.Fatalf("status=%d body=%s want=%d", response.Code, response.Body.String(), test.want)
			}
		})
	}
}

func TestHTTPRoleRegisterUnsignedAndUniformAuthorizationFailures(t *testing.T) {
	handler, private, privateB := newRoleRegisterHandler(t)
	unsigned := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/roles/register", bytes.NewBufferString(`{"role":"role/machine-a/reviewer"}`))
	unsigned.Header.Set("Content-Type", "application/json")
	unsigned.Header.Set("Idempotency-Key", "unsigned-1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, unsigned)
	if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), `"error":"authentication required"`) {
		t.Fatalf("unsigned status=%d body=%s", response.Code, response.Body.String())
	}
	create := serveSigned(t, handler, private, "machine-a", http.MethodPut, "/v1/machines/me/endpoints", `{"endpoints":["agent/a/session"]}`, "advertise-a", "")
	if create.Code != http.StatusOK {
		t.Fatalf("advertise status=%d body=%s", create.Code, create.Body.String())
	}
	if response := serveSigned(t, handler, private, "machine-a", http.MethodPost, "/v1/conversations", `{"creator_endpoint":"agent/a/session","members":[{"endpoint":"agent/a/session","capabilities":["send","receive","admin"]},{"role":"role/machine-a/reviewer","role_machine_id":"machine-b","capabilities":["receive"]}]}`, "create-owned", "create-owned-1"); response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	takeover := serveSigned(t, handler, private, "machine-a", http.MethodPost, "/v1/roles/register", `{"role":"role/machine-a/reviewer"}`, "takeover", "takeover-1")
	crossMachine := serveSigned(t, handler, privateB, "machine-b", http.MethodPost, "/v1/roles/bindings", `{"role":"role/missing","session_endpoint":"agent/b/session"}`, "bind-missing", "")
	if takeover.Code != http.StatusForbidden || takeover.Body.String() != crossMachine.Body.String() {
		t.Fatalf("authorization bodies diverged takeover=%d %s other=%d %s", takeover.Code, takeover.Body.String(), crossMachine.Code, crossMachine.Body.String())
	}
}

func newRoleRegisterHandler(t *testing.T) (http.Handler, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
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
	return NewHandler(store, auth, HandlerOptions{Now: func() time.Time { return clock }, EndpointLeaseTTL: time.Minute}), privateA, privateB
}
