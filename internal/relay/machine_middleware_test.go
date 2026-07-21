package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestMachineAuthenticationMiddlewareRestoresBoundedAuthenticatedBody(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(t.TempDir() + "/relay.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	auth, err := NewAuthenticator(store, []Machine{{ID: "machine-a", PublicKey: public, EndpointPrefixes: []string{"agent/a/"}}})
	if err != nil {
		t.Fatal(err)
	}
	middleware, err := NewMachineAuthenticationMiddleware(auth, 1024, nil)
	if err != nil {
		t.Fatal(err)
	}
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		machineID, ok := AuthenticatedMachineID(r.Context())
		if !ok || machineID != "machine-a" {
			t.Error("authenticated machine ID missing from request context")
		}
		bytes, _ := io.ReadAll(r.Body)
		if string(bytes) != "payload" {
			t.Errorf("body = %q", bytes)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	now := time.Now().UTC()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "http://example.test/v2/permits", strings.NewReader("payload"))
	signed := signRequest(private, "machine-a", http.MethodPost, "/v2/permits", []byte("payload"), now, "nonce-1")
	request.Header.Set("X-Punaro-Machine", signed.MachineID)
	request.Header.Set("X-Punaro-Timestamp", signed.Timestamp.Format(time.RFC3339Nano))
	request.Header.Set("X-Punaro-Nonce", signed.Nonce)
	request.Header.Set("X-Punaro-Signature", base64.RawURLEncoding.EncodeToString(signed.Signature))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
}

func TestMachineAuthenticationMiddlewarePreservesTransitionPrincipal(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := NewTransitionAuthenticator(nonceStoreFunc(func(string, string, time.Time, time.Time) error { return nil }), []Machine{{ID: "machine-a", PublicKey: public, EndpointPrefixes: []string{"agent/a/"}}}, transitionAuthorityFunc(func(_ context.Context, credential string, legacyKey ed25519.PublicKey) (TransitionAuthorization, error) {
		if credential != testTransitionToken || legacyKey != nil {
			return TransitionAuthorization{}, ErrForbidden
		}
		return TransitionAuthorization{PrincipalID: "11111111-1111-4111-8111-111111111111", CredentialLookupID: "22222222-2222-4222-8222-222222222222", CredentialGeneration: 1, LegacyPublicKey: public, Current: func(context.Context) error { return nil }}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	middleware, err := NewMachineAuthenticationMiddleware(auth, 1024, nil)
	if err != nil {
		t.Fatal(err)
	}
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, ok := AuthenticatedMachineSession(r.Context())
		if !ok || session.MachineID != "machine-a" || session.PrincipalID != "11111111-1111-4111-8111-111111111111" || session.CredentialLookupID != "22222222-2222-4222-8222-222222222222" || session.CredentialGeneration != 1 {
			t.Errorf("authenticated session=%#v present=%t", session, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.test/v1/attachments/22222222-2222-4222-8222-222222222222", nil)
	request.Header.Set("Authorization", "Bearer "+testTransitionToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
}

func TestMachineAuthenticationMiddlewareRejectsUnsignedQueryBeforeNonceUse(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(t.TempDir() + "/relay.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	auth, err := NewAuthenticator(store, []Machine{{ID: "machine-a", PublicKey: public, EndpointPrefixes: []string{"agent/a/"}}})
	if err != nil {
		t.Fatal(err)
	}
	middleware, err := NewMachineAuthenticationMiddleware(auth, 1024, nil)
	if err != nil {
		t.Fatal(err)
	}
	next := middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("next handler reached") }))
	now := time.Now().UTC()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "http://example.test/v2/permits?unsigned=true", nil)
	signed := signRequest(private, "machine-a", http.MethodPost, "/v2/permits", nil, now, "nonce-1")
	request.Header.Set("X-Punaro-Machine", signed.MachineID)
	request.Header.Set("X-Punaro-Timestamp", signed.Timestamp.Format(time.RFC3339Nano))
	request.Header.Set("X-Punaro-Nonce", signed.Nonce)
	request.Header.Set("X-Punaro-Signature", base64.RawURLEncoding.EncodeToString(signed.Signature))
	response := httptest.NewRecorder()
	next.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", response.Code)
	}
	if err := auth.Verify(signed, now); err != nil {
		t.Fatalf("query rejection consumed nonce: %v", err)
	}
}

func TestMachineAuthenticationMiddlewareRejectsNilBody(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(t.TempDir() + "/relay.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	auth, err := NewAuthenticator(store, []Machine{{ID: "machine-a", PublicKey: public, EndpointPrefixes: []string{"agent/a/"}}})
	if err != nil {
		t.Fatal(err)
	}
	middleware, err := NewMachineAuthenticationMiddleware(auth, 1024, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := &http.Request{Method: http.MethodPost, URL: &url.URL{Path: "/v2/permits"}, Header: make(http.Header), ContentLength: 0}
	response := httptest.NewRecorder()
	middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("next handler reached") })).ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", response.Code)
	}
}
