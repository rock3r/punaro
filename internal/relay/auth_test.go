package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"
)

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

func signRequest(private ed25519.PrivateKey, machineID, method, path string, body []byte, timestamp time.Time, nonce string) SignedRequest {
	request := SignedRequest{MachineID: machineID, Method: method, Path: path, Body: body, Timestamp: timestamp, Nonce: nonce}
	request.Signature = ed25519.Sign(private, CanonicalRequest(request))
	return request
}
