package access

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestVerifierValidatesCloudflareStyleJWTClaimsAndSignature(t *testing.T) {
	t.Parallel()
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{rsaJWK("key-1", &private.PublicKey)}})
	}))
	defer server.Close()
	now := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	verifier, err := NewVerifier(Config{Issuer: server.URL, Audience: "punaro-audience", JWKSURL: server.URL, CacheTTL: time.Hour}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	token := signedToken(t, private, "key-1", server.URL, "punaro-audience", now.Add(time.Minute))
	if err := verifier.Verify(token, now); err != nil {
		t.Fatal(err)
	}
	wrongAudience := signedToken(t, private, "key-1", server.URL, "other-audience", now.Add(time.Minute))
	if err := verifier.Verify(wrongAudience, now); err == nil {
		t.Fatal("wrong audience accepted")
	}
}

func TestMiddlewareRejectsMissingAccessAssertion(t *testing.T) {
	t.Parallel()
	verifier := &Verifier{}
	handler := verifier.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/deliveries", nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want forbidden", response.Code)
	}
}

func TestVerifierRejectsUnknownKeyAndExpiredToken(t *testing.T) {
	t.Parallel()
	known, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{rsaJWK("known", &known.PublicKey)}})
	}))
	defer server.Close()
	now := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	verifier, err := NewVerifier(Config{Issuer: server.URL, Audience: "punaro-audience", JWKSURL: server.URL}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(signedToken(t, unknown, "unknown", server.URL, "punaro-audience", now.Add(time.Minute)), now); err == nil {
		t.Fatal("unknown signing key accepted")
	}
	if err := verifier.Verify(signedToken(t, known, "known", server.URL, "punaro-audience", now.Add(-time.Minute)), now); err == nil {
		t.Fatal("expired token accepted")
	}
}

func TestNewVerifierRejectsInsecureOrAmbiguousMetadata(t *testing.T) {
	t.Parallel()
	validIssuer := "https://team.cloudflareaccess.example"
	validJWKS := "https://team.cloudflareaccess.example/cdn-cgi/access/certs"
	for name, config := range map[string]Config{
		"http issuer":         {Issuer: "http://team.cloudflareaccess.example", Audience: "audience", JWKSURL: validJWKS},
		"http jwks":           {Issuer: validIssuer, Audience: "audience", JWKSURL: "http://team.cloudflareaccess.example/certs"},
		"issuer userinfo":     {Issuer: "https://user@team.cloudflareaccess.example", Audience: "audience", JWKSURL: validJWKS},
		"jwks query":          {Issuer: validIssuer, Audience: "audience", JWKSURL: validJWKS + "?next=https://elsewhere.example"},
		"issuer fragment":     {Issuer: validIssuer + "#fragment", Audience: "audience", JWKSURL: validJWKS},
		"jwks missing host":   {Issuer: validIssuer, Audience: "audience", JWKSURL: "https:/certs"},
		"issuer missing host": {Issuer: "https:/issuer", Audience: "audience", JWKSURL: validJWKS},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewVerifier(config, nil); err == nil {
				t.Fatal("unsafe Access metadata was accepted")
			}
		})
	}
}

func TestVerifierDoesNotFollowJWKSRedirects(t *testing.T) {
	t.Parallel()
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.Header().Set("Location", "https://untrusted.example/jwks")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	verifier, err := NewVerifier(Config{Issuer: server.URL, Audience: "punaro-audience", JWKSURL: server.URL}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.refreshLocked(context.Background(), time.Now().UTC()); err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("redirect result = %v, want HTTP 302 rejection", err)
	}
	if requests != 1 {
		t.Fatalf("JWKS requests = %d, want 1 (no redirect follow)", requests)
	}
}

func TestVerifierReadsFreshPrivateJWKSSnapshotWithoutNetwork(t *testing.T) {
	t.Parallel()
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(t.TempDir(), "jwks")
	if err := os.Mkdir(parent, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "current.json")
	raw, err := json.Marshal(map[string]any{"keys": []any{rsaJWK("key-1", &private.PublicKey)}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o640); err != nil { // #nosec G306 -- models the root:punaro JWKS cache mode.
		t.Fatal(err)
	}
	client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("network access attempted for local JWKS snapshot")
		return nil, nil
	})}
	now := time.Date(2026, time.July, 14, 12, 0, 0, 0, time.UTC)
	if err := os.Chtimes(path, now, now); err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier(Config{Issuer: "https://team.cloudflareaccess.example", Audience: "punaro-audience", JWKSFile: path}, client)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Warm(context.Background(), now); err != nil {
		t.Fatalf("warm local snapshot: %v", err)
	}
	if err := verifier.Verify(signedToken(t, private, "key-1", "https://team.cloudflareaccess.example", "punaro-audience", now.Add(time.Minute)), now); err != nil {
		t.Fatal(err)
	}
}

func TestVerifierRejectsStaleOrWritableJWKSSnapshot(t *testing.T) {
	t.Parallel()
	parent := filepath.Join(t.TempDir(), "jwks")
	if err := os.Mkdir(parent, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "current.json")
	if err := os.WriteFile(path, []byte(`{"keys":[]}`), 0o640); err != nil { // #nosec G306 -- models the root:punaro JWKS cache mode.
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o660); err != nil { // #nosec G302 -- intentionally models an unsafe writable cache.
		t.Fatal(err)
	}
	if _, err := NewVerifier(Config{Issuer: "https://team.cloudflareaccess.example", Audience: "punaro-audience", JWKSFile: path}, nil); err == nil {
		t.Fatal("group-writable JWKS snapshot was accepted")
	}
	if err := os.Chmod(path, 0o640); err != nil { // #nosec G302 -- restores the root:punaro JWKS cache mode.
		t.Fatal(err)
	}
	verifier, err := NewVerifier(Config{Issuer: "https://team.cloudflareaccess.example", Audience: "punaro-audience", JWKSFile: path, CacheTTL: time.Minute}, nil)
	if err != nil {
		t.Fatal(err)
	}
	stale := time.Now().UTC().Add(-2 * time.Minute)
	if err := os.Chtimes(path, stale, stale); err != nil {
		t.Fatal(err)
	}
	if err := verifier.Warm(context.Background(), time.Now().UTC()); err == nil {
		t.Fatal("stale JWKS snapshot was accepted")
	}
}

func signedToken(t *testing.T, private *rsa.PrivateKey, keyID, issuer, audience string, expires time.Time) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": issuer, "aud": audience, "exp": expires.Unix(), "iat": expires.Add(-time.Hour).Unix()})
	token.Header["kid"] = keyID
	signed, err := token.SignedString(private)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func rsaJWK(keyID string, public *rsa.PublicKey) map[string]string {
	exponent := big.NewInt(int64(public.E)).Bytes()
	return map[string]string{"kty": "RSA", "kid": keyID, "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(public.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(exponent)}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }
