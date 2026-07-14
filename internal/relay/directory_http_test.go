package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type directorySnapshotSourceStub struct {
	raw []byte
	err error
}

func (s directorySnapshotSourceStub) CurrentDirectorySnapshot() ([]byte, error) {
	return append([]byte(nil), s.raw...), s.err
}

func TestDirectoryHTTPHandlerRequiresSignedEnrolledMachine(t *testing.T) {
	t.Parallel()
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
	clock := time.Now().UTC().Truncate(time.Millisecond)
	handler, err := NewDirectoryHandler(auth, directorySnapshotSourceStub{raw: []byte{0xa1, 0x01, 0x02}}, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	unsigned := httptest.NewRequest(http.MethodGet, "/v2/directory", nil)
	unsignedResponse := httptest.NewRecorder()
	handler.ServeHTTP(unsignedResponse, unsigned)
	if unsignedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned status=%d", unsignedResponse.Code)
	}

	request := httptest.NewRequest(http.MethodGet, "/v2/directory", nil)
	signed := signRequest(private, "machine-a", http.MethodGet, "/v2/directory", nil, clock, "directory-nonce")
	request.Header.Set("X-Punaro-Machine", signed.MachineID)
	request.Header.Set("X-Punaro-Timestamp", signed.Timestamp.Format(time.RFC3339Nano))
	request.Header.Set("X-Punaro-Nonce", signed.Nonce)
	request.Header.Set("X-Punaro-Signature", base64.RawURLEncoding.EncodeToString(signed.Signature))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/cbor" || response.Body.String() != string([]byte{0xa1, 0x01, 0x02}) {
		t.Fatalf("status=%d type=%q body=%x", response.Code, response.Header().Get("Content-Type"), response.Body.Bytes())
	}
}

func TestDirectoryHTTPHandlerRejectsQueriesAndSourceFailures(t *testing.T) {
	t.Parallel()
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
	clock := time.Now().UTC().Truncate(time.Millisecond)
	handler, err := NewDirectoryHandler(auth, directorySnapshotSourceStub{err: errDirectoryUnavailable}, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v2/directory?ignored=true", nil)
	signed := signRequest(private, "machine-a", http.MethodGet, "/v2/directory", nil, clock, "query-nonce")
	request.Header.Set("X-Punaro-Machine", signed.MachineID)
	request.Header.Set("X-Punaro-Timestamp", signed.Timestamp.Format(time.RFC3339Nano))
	request.Header.Set("X-Punaro-Nonce", signed.Nonce)
	request.Header.Set("X-Punaro-Signature", base64.RawURLEncoding.EncodeToString(signed.Signature))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("query status=%d", response.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/v2/directory", nil)
	signed = signRequest(private, "machine-a", http.MethodGet, "/v2/directory", nil, clock, "source-failure-nonce")
	request.Header.Set("X-Punaro-Machine", signed.MachineID)
	request.Header.Set("X-Punaro-Timestamp", signed.Timestamp.Format(time.RFC3339Nano))
	request.Header.Set("X-Punaro-Nonce", signed.Nonce)
	request.Header.Set("X-Punaro-Signature", base64.RawURLEncoding.EncodeToString(signed.Signature))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("source failure status=%d", response.Code)
	}
}
