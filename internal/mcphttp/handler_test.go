package mcphttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rock3r/punaro/internal/mcpoauth"
)

func TestProtectedResourceMetadataIsStrictAndChallengesMCPWithoutAcceptingTokens(t *testing.T) {
	handler, err := New("https://mcp.example.test/mcp", []string{"https://auth.example.test"}, nil, nil, nil)
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

func TestValidatedTokenReachesOnlyTheNoTransportBoundary(t *testing.T) {
	handler, err := New("https://mcp.example.test/mcp", []string{"https://auth.example.test"}, testValidator{}, map[string]string{"operator": "11111111-1111-4111-8111-111111111111"}, activePrincipal)
	if err != nil {
		t.Fatal(err)
	}
	valid := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", nil)
	request.Header.Set("Authorization", "Bearer valid")
	handler.ServeHTTP(valid, request)
	if valid.Code != http.StatusNotImplemented || valid.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("valid token response=%d authenticate=%q", valid.Code, valid.Header().Get("WWW-Authenticate"))
	}
	invalid := httptest.NewRecorder()
	request = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", nil)
	request.Header.Set("Authorization", "Bearer invalid")
	handler.ServeHTTP(invalid, request)
	if invalid.Code != http.StatusUnauthorized || !strings.Contains(invalid.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Fatalf("invalid token response=%d authenticate=%q", invalid.Code, invalid.Header().Get("WWW-Authenticate"))
	}
}

func TestBearerSchemeIsCaseInsensitive(t *testing.T) {
	handler, err := New("https://mcp.example.test/mcp", []string{"https://auth.example.test"}, testValidator{}, map[string]string{"operator": "11111111-1111-4111-8111-111111111111"}, activePrincipal)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", nil)
	request.Header.Set("Authorization", "bearer valid")
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotImplemented {
		t.Fatalf("status=%d", response.Code)
	}
}

func TestVerifiedButUnmappedSubjectIsForbidden(t *testing.T) {
	handler, err := New("https://mcp.example.test/mcp", []string{"https://auth.example.test"}, testValidator{}, nil, activePrincipal)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", nil)
	request.Header.Set("Authorization", "Bearer valid")
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d", response.Code)
	}
}

func TestVerifiedSubjectWithDisabledPrincipalIsForbidden(t *testing.T) {
	handler, err := New("https://mcp.example.test/mcp", []string{"https://auth.example.test"}, testValidator{}, map[string]string{"operator": "11111111-1111-4111-8111-111111111111"}, func(context.Context, string) (bool, error) { return false, nil })
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", nil)
	request.Header.Set("Authorization", "Bearer valid")
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d", response.Code)
	}
}

func TestVerifiedBoundSubjectWithoutDefaultScopeIsForbidden(t *testing.T) {
	handler, err := New("https://mcp.example.test/mcp", []string{"https://auth.example.test"}, unscopedValidator{}, map[string]string{"operator": "11111111-1111-4111-8111-111111111111"}, activePrincipal)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", nil)
	request.Header.Set("Authorization", "Bearer valid")
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Header().Get("WWW-Authenticate"), `error="insufficient_scope"`) || strings.Contains(response.Header().Get("WWW-Authenticate"), `scope=`) {
		t.Fatalf("status=%d authenticate=%q", response.Code, response.Header().Get("WWW-Authenticate"))
	}
}

type testValidator struct{}

type unscopedValidator struct{}

func activePrincipal(context.Context, string) (bool, error) { return true, nil }

func (testValidator) Validate(_ context.Context, raw string, _ time.Time) (mcpoauth.Claims, error) {
	if raw != "valid" {
		return mcpoauth.Claims{}, errors.New("invalid")
	}
	return mcpoauth.Claims{Subject: "operator", Scopes: map[string]struct{}{"memory.read": {}}}, nil
}

func (unscopedValidator) Validate(_ context.Context, raw string, _ time.Time) (mcpoauth.Claims, error) {
	if raw != "valid" {
		return mcpoauth.Claims{}, errors.New("invalid")
	}
	return mcpoauth.Claims{Subject: "operator"}, nil
}

func TestProtectedResourceMetadataRejectsUnsafeConfiguration(t *testing.T) {
	for _, resource := range []string{"http://mcp.example.test/mcp", "https://mcp.example.test/", "https://mcp.example.test/mcp?query=1", "https://mcp.example.test/mcp#fragment", "https://mcp.example.test//mcp"} {
		if _, err := New(resource, []string{"https://auth.example.test"}, nil, nil, nil); err == nil {
			t.Fatalf("unsafe resource accepted: %q", resource)
		}
	}
	for _, authorizationServer := range [][]string{nil, {"http://auth.example.test"}, {"https://auth.example.test/path"}} {
		if _, err := New("https://mcp.example.test/mcp", authorizationServer, nil, nil, nil); err == nil {
			t.Fatalf("unsafe authorization server accepted: %q", authorizationServer)
		}
	}
}
