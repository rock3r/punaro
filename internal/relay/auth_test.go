package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

type transitionAuthorityFunc func(context.Context, string, ed25519.PublicKey) (TransitionAuthorization, error)

const testTransitionToken = "not-secret"

func (function transitionAuthorityFunc) AuthorizeTransition(ctx context.Context, credential string, legacyKey ed25519.PublicKey) (TransitionAuthorization, error) {
	return function(ctx, credential, legacyKey)
}

type nonceStoreFunc func(string, string, time.Time, time.Time) error

func (function nonceStoreFunc) ConsumeRequestNonce(machineID, nonce string, now, expiresAt time.Time) error {
	return function(machineID, nonce, now, expiresAt)
}

func TestAuthenticatorPreservesMaintenanceRefusal(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuthenticator(nonceStoreFunc(func(string, string, time.Time, time.Time) error { return ErrMaintenance }), []Machine{{ID: "machine-a", PublicKey: public, EndpointPrefixes: []string{"agent/"}}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.July, 20, 12, 0, 0, 0, time.UTC)
	request := signRequest(private, "machine-a", "GET", "/v1/conversations", nil, now, "nonce")
	if err := auth.Verify(request, now); !errors.Is(err, ErrMaintenance) {
		t.Fatalf("maintenance authentication err=%v", err)
	}
}

func TestAuthenticatorVerifiesRequestAndRejectsReplayAfterRestart(t *testing.T) {
	t.Parallel()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	database := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuthenticator(store, []Machine{{ID: "machine-a", PublicKey: public, EndpointPrefixes: []string{"agent/"}}})
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	signed := signRequest(private, "machine-a", "PUT", "/v1/machines/me/endpoints", []byte(`{"endpoints":["agent/a"]}`), clock, "nonce-one")
	if err := auth.Verify(signed, clock); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	auth, err = NewAuthenticator(store, []Machine{{ID: "machine-a", PublicKey: public, EndpointPrefixes: []string{"agent/"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.Verify(signed, clock.Add(time.Second)); err == nil {
		t.Fatal("replayed signed request was accepted after restart")
	}
}

func TestAuthenticatorRejectsTamperingStaleRequestsAndUnknownMachines(t *testing.T) {
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
	auth, err := NewAuthenticator(store, []Machine{{ID: "machine-a", PublicKey: public, EndpointPrefixes: []string{"agent/"}}})
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	signed := signRequest(private, "machine-a", "POST", "/v1/conversations", []byte(`{"members":[]}`), clock, "nonce-one")
	tampered := signed
	tampered.Body = []byte(`{"members":["agent/a"]}`)
	if err := auth.Verify(tampered, clock); err == nil {
		t.Fatal("tampered body was accepted")
	}
	stale := signRequest(private, "machine-a", "POST", "/v1/conversations", []byte(`{"members":[]}`), clock.Add(-6*time.Minute), "nonce-two")
	if err := auth.Verify(stale, clock); err == nil {
		t.Fatal("stale signed request was accepted")
	}
	unknown := signRequest(private, "machine-z", "POST", "/v1/conversations", []byte(`{"members":[]}`), clock, "nonce-three")
	if err := auth.Verify(unknown, clock); err == nil {
		t.Fatal("unknown machine was accepted")
	}
	if !auth.AllowsEndpoint("machine-a", "agent/reviewer") || auth.AllowsEndpoint("machine-a", "system/reviewer") {
		t.Fatal("endpoint prefix authorization was not enforced")
	}
}

func TestAuthenticatorRejectsOverlappingMachineEndpointNamespaces(t *testing.T) {
	t.Parallel()
	publicA, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicB, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := NewAuthenticator(store, []Machine{{ID: "machine-a", PublicKey: publicA, EndpointPrefixes: []string{"agent/"}}, {ID: "machine-b", PublicKey: publicB, EndpointPrefixes: []string{"agent/a/"}}}); err == nil {
		t.Fatal("overlapping endpoint namespaces were accepted")
	}
}

func TestAuthenticatorRequiresSegmentTerminatedEndpointPrefixes(t *testing.T) {
	t.Parallel()
	public := make([]byte, ed25519.PublicKeySize)
	public[0] = 1
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := NewAuthenticator(store, []Machine{{ID: "machine-a", PublicKey: public, EndpointPrefixes: []string{"agent/a"}}}); err == nil {
		t.Fatal("non-segment-terminated endpoint prefix was accepted")
	}
}

func TestAuthenticatorNamespacePrefixExcludesBareAndAdjacentEndpoints(t *testing.T) {
	t.Parallel()
	public := make([]byte, ed25519.PublicKeySize)
	public[0] = 1
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	auth, err := NewAuthenticator(store, []Machine{{ID: "machine-a", PublicKey: public, EndpointPrefixes: []string{"agent/a/"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !auth.AllowsEndpoint("machine-a", "agent/a/session") {
		t.Fatal("nested endpoint was rejected")
	}
	if auth.AllowsEndpoint("machine-a", "agent/a") || auth.AllowsEndpoint("machine-a", "agent/abuse") {
		t.Fatal("namespace prefix authorized a bare or adjacent endpoint")
	}
}

func TestAuthenticatorAllowsOnlyExplicitExactEndpoint(t *testing.T) {
	t.Parallel()
	public := make([]byte, ed25519.PublicKeySize)
	public[0] = 1
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	auth, err := NewAuthenticator(store, []Machine{{ID: "machine-a", PublicKey: public, EndpointPrefixes: []string{"agent/a/"}, Endpoints: []string{"claude/jbr-skia-reviewer"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !auth.AllowsEndpoint("machine-a", "claude/jbr-skia-reviewer") {
		t.Fatal("exact endpoint was rejected")
	}
	if auth.AllowsEndpoint("machine-a", "claude/jbr-skia-reviewer-extra") {
		t.Fatal("exact endpoint authorization became a prefix")
	}
}

func TestAuthenticatorRejectsExactEndpointOwnedByAnotherMachine(t *testing.T) {
	t.Parallel()
	publicA := make([]byte, ed25519.PublicKeySize)
	publicA[0] = 1
	publicB := make([]byte, ed25519.PublicKeySize)
	publicB[0] = 2
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := NewAuthenticator(store, []Machine{
		{ID: "machine-a", PublicKey: publicA, EndpointPrefixes: []string{"agent/a/"}, Endpoints: []string{"claude/jbr-skia-reviewer"}},
		{ID: "machine-b", PublicKey: publicB, EndpointPrefixes: []string{"claude/"}},
	}); err == nil {
		t.Fatal("exact endpoint overlapping another machine namespace was accepted")
	}
}

func TestTransitionAuthenticatorMakesLegacyGateAuthoritative(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store := nonceStoreFunc(func(string, string, time.Time, time.Time) error { return nil })
	gateOpen := true
	auth, err := NewTransitionAuthenticator(store, []Machine{{ID: "machine-a", PublicKey: public, EndpointPrefixes: []string{"agent/a/"}}}, transitionAuthorityFunc(func(_ context.Context, credential string, legacyKey ed25519.PublicKey) (TransitionAuthorization, error) {
		if credential != "" || !gateOpen || !bytes.Equal(legacyKey, public) {
			return TransitionAuthorization{}, ErrForbidden
		}
		return TransitionAuthorization{PrincipalID: "11111111-1111-4111-8111-111111111111", LegacyPublicKey: legacyKey, Current: func(context.Context) error {
			if !gateOpen {
				return ErrForbidden
			}
			return nil
		}}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.July, 20, 12, 0, 0, 0, time.UTC)
	signed := signRequest(private, "machine-a", http.MethodPost, "/v1/conversations", []byte(`{"members":[]}`), now, "nonce-open")
	request := signedHTTPRequest(t, signed)
	session, err := auth.AuthenticateHTTPSession(request, signed.Body, now)
	if err != nil || session.MachineID != "machine-a" || session.PrincipalID != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("open legacy gate session=%#v err=%v", session, err)
	}
	gateOpen = false
	if err := session.Current(context.Background()); !errors.Is(err, ErrForbidden) {
		t.Fatalf("closed legacy gate retained session err=%v", err)
	}
	signed = signRequest(private, "machine-a", http.MethodPost, "/v1/conversations", []byte(`{"members":[]}`), now, "nonce-closed")
	request = signedHTTPRequest(t, signed)
	if _, err := auth.AuthenticateHTTP(request, signed.Body, now); !errors.Is(err, ErrForbidden) {
		t.Fatalf("closed legacy gate err=%v", err)
	}
}

func TestTransitionAuthenticatorPreservesExactMachineAuthorityForMigratedCredential(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := NewTransitionAuthenticator(nonceStoreFunc(func(string, string, time.Time, time.Time) error { return nil }), []Machine{{ID: "machine-a", PublicKey: public, EndpointPrefixes: []string{"agent/a/"}, Endpoints: []string{"claude/exact"}}}, transitionAuthorityFunc(func(_ context.Context, credential string, legacyKey ed25519.PublicKey) (TransitionAuthorization, error) {
		if credential != testTransitionToken || legacyKey != nil {
			return TransitionAuthorization{}, ErrForbidden
		}
		return TransitionAuthorization{PrincipalID: "11111111-1111-4111-8111-111111111111", CredentialLookupID: "22222222-2222-4222-8222-222222222222", CredentialGeneration: 1, LegacyPublicKey: public, Current: func(context.Context) error { return nil }}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://localhost/v1/conversations", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+testTransitionToken)
	session, err := auth.AuthenticateHTTPSession(request, nil, time.Now().UTC())
	if err != nil || session.MachineID != "machine-a" || session.PrincipalID != "11111111-1111-4111-8111-111111111111" || session.CredentialLookupID != "22222222-2222-4222-8222-222222222222" || session.CredentialGeneration != 1 {
		t.Fatalf("migrated credential session=%#v err=%v", session, err)
	}
	if !auth.AllowsEndpoint(session.MachineID, "agent/a/session") || !auth.AllowsEndpoint(session.MachineID, "claude/exact") || auth.AllowsEndpoint(session.MachineID, "agent/b/session") || auth.AllowsEndpoint(session.MachineID, "claude/exact-more") {
		t.Fatal("migrated credential did not inherit the exact configured machine authority")
	}
}

func TestTransitionAuthenticatorRejectsAmbiguousLegacyPublicKey(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewTransitionAuthenticator(nonceStoreFunc(func(string, string, time.Time, time.Time) error { return nil }), []Machine{
		{ID: "machine-a", PublicKey: public, EndpointPrefixes: []string{"agent/a/"}},
		{ID: "machine-b", PublicKey: public, EndpointPrefixes: []string{"agent/b/"}},
	}, transitionAuthorityFunc(func(context.Context, string, ed25519.PublicKey) (TransitionAuthorization, error) {
		return TransitionAuthorization{PrincipalID: "11111111-1111-4111-8111-111111111111", LegacyPublicKey: public, Current: func(context.Context) error { return nil }}, nil
	}))
	if err == nil {
		t.Fatal("transition authenticator accepted an ambiguous legacy public key")
	}
}

func signedHTTPRequest(t *testing.T, signed SignedRequest) *http.Request {
	t.Helper()
	request, err := http.NewRequestWithContext(context.Background(), signed.Method, "http://localhost"+signed.Path, bytes.NewReader(signed.Body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Punaro-Machine", signed.MachineID)
	request.Header.Set("X-Punaro-Timestamp", signed.Timestamp.Format(time.RFC3339Nano))
	request.Header.Set("X-Punaro-Nonce", signed.Nonce)
	request.Header.Set("X-Punaro-Signature", base64.RawURLEncoding.EncodeToString(signed.Signature))
	return request
}

func signRequest(private ed25519.PrivateKey, machineID, method, path string, body []byte, timestamp time.Time, nonce string) SignedRequest {
	request := SignedRequest{MachineID: machineID, Method: method, Path: path, Body: body, Timestamp: timestamp, Nonce: nonce}
	request.Signature = ed25519.Sign(private, CanonicalRequest(request))
	return request
}
