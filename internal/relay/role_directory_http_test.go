package relay

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestHTTPRoleDirectoryListsAndResolvesWithoutSessionInventory(t *testing.T) {
	handler, private, privateB := newRoleRegisterHandler(t)
	if response := serveSigned(t, handler, private, "machine-a", http.MethodPost, "/v1/roles/register", `{"role":"role/machine-a/alpha","direct_addressable":true}`, "reg-alpha", "reg-alpha"); response.Code != http.StatusCreated {
		t.Fatalf("register alpha status=%d body=%s", response.Code, response.Body.String())
	}
	if response := serveSigned(t, handler, privateB, "machine-b", http.MethodPost, "/v1/roles/register", `{"role":"role/machine-b/alpha","display_name":"Beta","direct_addressable":true}`, "reg-b", "reg-b"); response.Code != http.StatusCreated {
		t.Fatalf("register beta status=%d body=%s", response.Code, response.Body.String())
	}
	if response := serveSigned(t, handler, private, "machine-a", http.MethodPost, "/v1/roles/register", `{"role":"role/machine-a/hidden"}`, "reg-hidden", "reg-hidden"); response.Code != http.StatusCreated {
		t.Fatalf("register hidden status=%d body=%s", response.Code, response.Body.String())
	}
	listed := serveSigned(t, handler, private, "machine-a", http.MethodPost, "/v1/roles/list", `{"cursor":"","limit":50}`, "list-1", "")
	if listed.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", listed.Code, listed.Body.String())
	}
	var page RoleListPage
	if err := json.NewDecoder(listed.Body).Decode(&page); err != nil || len(page.Roles) != 2 || page.Roles[0].Role != "role/machine-a/alpha" {
		t.Fatalf("page=%#v err=%v body leftover", page, err)
	}
	if encoded, err := json.Marshal(page); err != nil || strings.Contains(string(encoded), "agent/") || strings.Contains(string(encoded), "conversation") {
		t.Fatalf("list leaked inventory: %s err=%v", encoded, err)
	}
	exact := serveSigned(t, handler, private, "machine-a", http.MethodPost, "/v1/roles/resolve", `{"name":"role/machine-a/alpha"}`, "resolve-exact", "")
	if exact.Code != http.StatusOK || !strings.Contains(exact.Body.String(), `"status":"resolved"`) {
		t.Fatalf("exact status=%d body=%s", exact.Code, exact.Body.String())
	}
	ambiguous := serveSigned(t, handler, private, "machine-a", http.MethodPost, "/v1/roles/resolve", `{"name":"alpha"}`, "resolve-amb", "")
	if ambiguous.Code != http.StatusConflict || !strings.Contains(ambiguous.Body.String(), `"status":"ambiguous"`) {
		t.Fatalf("ambiguous status=%d body=%s", ambiguous.Code, ambiguous.Body.String())
	}
	hidden := serveSigned(t, handler, private, "machine-a", http.MethodPost, "/v1/roles/resolve", `{"name":"role/machine-a/hidden"}`, "resolve-hidden", "")
	missing := serveSigned(t, handler, private, "machine-a", http.MethodPost, "/v1/roles/resolve", `{"name":"role/plan-reviewer"}`, "resolve-legacy", "")
	if hidden.Code != http.StatusNotFound || hidden.Body.String() != missing.Body.String() {
		t.Fatalf("not-found bodies diverged hidden=%d %s missing=%d %s", hidden.Code, hidden.Body.String(), missing.Code, missing.Body.String())
	}
	if response := serveSigned(t, handler, private, "machine-a", http.MethodPost, "/v1/roles/list", `{"cursor":"","limit":50,"extra":true}`, "list-extra", ""); response.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status=%d body=%s", response.Code, response.Body.String())
	}
}
