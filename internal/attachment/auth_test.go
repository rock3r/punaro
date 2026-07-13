package attachment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestEd25519AuthenticatorRejectsReplay(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	auth := NewEd25519Authenticator(map[string]ed25519.PublicKey{"device": public}, func() time.Time { return now })
	req := signedRequest(t, private, now, "nonce", []byte("ciphertext"))
	principal, err := auth.Authenticate(req.Context(), req)
	if err != nil || principal.DeviceID != "device" {
		t.Fatalf("Authenticate() = %#v, %v", principal, err)
	}
	replay := signedRequest(t, private, now, "nonce", []byte("ciphertext"))
	if _, err := auth.Authenticate(replay.Context(), replay); err == nil {
		t.Fatal("replayed signature authenticated")
	}
}

func TestEd25519AuthenticatorRejectsReplayAfterRestart(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	store, err := OpenSQLiteOfferStore(t.TempDir() + "/attachments.db")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	first := NewEd25519AuthenticatorWithNonceStore(map[string]ed25519.PublicKey{"device": public}, func() time.Time { return now }, store)
	request := signedRequest(t, private, now, "restart-nonce", []byte("ciphertext"))
	if _, err := first.Authenticate(request.Context(), request); err != nil {
		t.Fatalf("first authentication: %v", err)
	}
	second := NewEd25519AuthenticatorWithNonceStore(map[string]ed25519.PublicKey{"device": public}, func() time.Time { return now }, store)
	replay := signedRequest(t, private, now, "restart-nonce", []byte("ciphertext"))
	if _, err := second.Authenticate(replay.Context(), replay); err == nil {
		t.Fatal("replay authenticated after authenticator restart")
	}
}

func TestEd25519AuthenticatorBindsIdempotencyKey(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	auth := NewEd25519Authenticator(map[string]ed25519.PublicKey{"device": public}, func() time.Time { return now })
	request := signedRequest(t, private, now, "nonce", []byte("ciphertext"))
	request.Header.Set("Idempotency-Key", "tampered-after-signing")
	if _, err := auth.Authenticate(request.Context(), request); err == nil {
		t.Fatal("authentication accepted an idempotency-key header altered after signing")
	}
}

func signedRequest(t *testing.T, private ed25519.PrivateKey, now time.Time, nonce string, body []byte) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/v1/attachment-offers/offer/artifacts/artifact/chunks/0", bytes.NewReader(body))
	timestamp := strconv.FormatInt(now.Unix(), 10)
	digest := sha256.Sum256(body)
	payload := requestSignaturePayload(req.Method, req.URL.EscapedPath(), digest, timestamp, nonce, "")
	req.Header.Set("X-Punaro-Device", "device")
	req.Header.Set("X-Punaro-Timestamp", timestamp)
	req.Header.Set("X-Punaro-Nonce", nonce)
	req.Header.Set("X-Punaro-Signature", base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, payload)))
	return req
}
