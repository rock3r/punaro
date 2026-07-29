package mcphttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProtectedResourceMetadataIsStrictAndChallengesMCPWithoutAcceptingTokens(t *testing.T) {
	handler, err := New("https://mcp.example.test/mcp", []string{"https://auth.example.test"})
	if err != nil {
		t.Fatal(err)
	}

	metadata := httptest.NewRecorder()
	handler.ServeHTTP(metadata, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.well-known/oauth-protected-resource/mcp", nil))
	if metadata.Code != http.StatusOK || metadata.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("metadata response = %d %q", metadata.Code, metadata.Header().Get("Content-Type"))
	}
	if got := metadata.Body.String(); !strings.Contains(got, `"resource":"https://mcp.example.test/mcp"`) || !strings.Contains(got, `"authorization_servers":["https://auth.example.test"]`) {
		t.Fatalf("metadata = %s", got)
	}

	challenge := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", nil)
	request.Header.Set("Authorization", "Bearer deliberately-uninspected")
	handler.ServeHTTP(challenge, request)
	if challenge.Code != http.StatusUnauthorized || challenge.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("challenge response = %d cache-control=%q", challenge.Code, challenge.Header().Get("Cache-Control"))
	}
	wantChallenge := `Bearer realm="punaro-mcp", resource_metadata="https://mcp.example.test/.well-known/oauth-protected-resource/mcp", scope="memory.search memory.read memory.propose"`
	if challenge.Header().Get("WWW-Authenticate") != wantChallenge {
		t.Fatalf("WWW-Authenticate = %q, want %q", challenge.Header().Get("WWW-Authenticate"), wantChallenge)
	}
	if challenge.Body.Len() != 0 {
		t.Fatalf("challenge body = %q", challenge.Body.String())
	}
}

func TestProtectedResourceMetadataRejectsUnsafeConfiguration(t *testing.T) {
	for _, resource := range []string{"http://mcp.example.test/mcp", "https://mcp.example.test/", "https://mcp.example.test/mcp?query=1", "https://mcp.example.test/mcp#fragment", "https://mcp.example.test//mcp"} {
		if _, err := New(resource, []string{"https://auth.example.test"}); err == nil {
			t.Fatalf("unsafe resource accepted: %q", resource)
		}
	}
	for _, authorizationServer := range [][]string{nil, {"http://auth.example.test"}, {"https://auth.example.test/path"}} {
		if _, err := New("https://mcp.example.test/mcp", authorizationServer); err == nil {
			t.Fatalf("unsafe authorization server accepted: %q", authorizationServer)
		}
	}
}
