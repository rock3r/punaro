package access

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/deliveries", nil))
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
