package attachment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	authWindow  = 30 * time.Second
	maxAuthBody = 256 << 10
)

// Ed25519Authenticator validates method/path/body-bound device signatures and
// consumes one-time nonces within a bounded replay window.
type Ed25519Authenticator struct {
	keys       map[string]ed25519.PublicKey
	now        func() time.Time
	nonceStore NonceStore
}

// NonceStore atomically records one request nonce until its expiry.
type NonceStore interface {
	ConsumeNonce(device, nonce string, now, expiry time.Time) bool
}

// NewEd25519Authenticator constructs a request authenticator from enrolled
// device public keys. Callers retain ownership of the input map and keys.
func NewEd25519Authenticator(keys map[string]ed25519.PublicKey, now func() time.Time) *Ed25519Authenticator {
	return NewEd25519AuthenticatorWithNonceStore(keys, now, newMemoryNonceStore(now))
}

// NewEd25519AuthenticatorWithNonceStore uses durable replay protection when
// the relay provides one. The store must atomically reject an existing nonce.
func NewEd25519AuthenticatorWithNonceStore(keys map[string]ed25519.PublicKey, now func() time.Time, nonceStore NonceStore) *Ed25519Authenticator {
	copyKeys := make(map[string]ed25519.PublicKey, len(keys))
	for device, key := range keys {
		copyKeys[device] = append(ed25519.PublicKey(nil), key...)
	}
	if now == nil {
		now = time.Now
	}
	if nonceStore == nil {
		nonceStore = newMemoryNonceStore(now)
	}
	return &Ed25519Authenticator{keys: copyKeys, now: now, nonceStore: nonceStore}
}

// Authenticate implements Authenticator. It restores the body after hashing so
// downstream route handling receives the exact signed bytes.
func (a *Ed25519Authenticator) Authenticate(_ context.Context, request *http.Request) (Principal, error) {
	device := request.Header.Get("X-Punaro-Device")
	timestamp := request.Header.Get("X-Punaro-Timestamp")
	nonce := request.Header.Get("X-Punaro-Nonce")
	signatureText := request.Header.Get("X-Punaro-Signature")
	key, known := a.keys[device]
	if !known || len(key) != ed25519.PublicKeySize || nonce == "" || len(nonce) > 128 {
		return Principal{}, ErrUnauthorized
	}
	unix, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || absDuration(a.now().Sub(time.Unix(unix, 0))) > authWindow {
		return Principal{}, ErrUnauthorized
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxAuthBody+1))
	if err != nil || len(body) > maxAuthBody {
		return Principal{}, ErrUnauthorized
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	signature, err := base64.RawStdEncoding.DecodeString(signatureText)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Principal{}, ErrUnauthorized
	}
	digest := sha256.Sum256(body)
	if !ed25519.Verify(key, requestSignaturePayload(request.Method, request.URL.EscapedPath(), digest, timestamp, nonce, request.Header.Get("Idempotency-Key")), signature) {
		return Principal{}, ErrUnauthorized
	}
	now := a.now()
	if !a.nonceStore.ConsumeNonce(device, nonce, now, time.Unix(unix, 0).Add(authWindow)) {
		return Principal{}, ErrUnauthorized
	}
	return Principal{DeviceID: device}, nil
}

type memoryNonceStore struct {
	now    func() time.Time
	mu     sync.Mutex
	nonces map[string]time.Time
}

func newMemoryNonceStore(now func() time.Time) *memoryNonceStore {
	if now == nil {
		now = time.Now
	}
	return &memoryNonceStore{now: now, nonces: make(map[string]time.Time)}
}

func (s *memoryNonceStore) ConsumeNonce(device, nonce string, now, expiry time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, expires := range s.nonces {
		if !expires.After(now) {
			delete(s.nonces, key)
		}
	}
	key := device + "\x00" + nonce
	if _, used := s.nonces[key]; used {
		return false
	}
	s.nonces[key] = expiry
	return true
}

func requestSignaturePayload(method, escapedPath string, digest [sha256.Size]byte, timestamp, nonce, idempotencyKey string) []byte {
	return []byte(strings.Join([]string{"punaro/request/v1", method, escapedPath, base64.RawStdEncoding.EncodeToString(digest[:]), timestamp, nonce, idempotencyKey}, "\x00"))
}

func absDuration(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}

var _ Authenticator = (*Ed25519Authenticator)(nil)
