package mcpoauth

import (
	"context"
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

func TestVerifierBindsAccessTokenToExactResourceAndIssuer(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{testJWK("key-1", &private.PublicKey)}})
	}))
	defer server.Close()
	now := time.Date(2026, time.July, 29, 12, 0, 0, 0, time.UTC)
	verifier, err := NewVerifier(Config{Issuer: server.URL, Audience: "https://punaro.example/mcp", JWKSURL: server.URL}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	claims, err := verifier.Validate(context.Background(), testToken(t, private, "key-1", server.URL, "https://punaro.example/mcp", now.Add(time.Minute)), now)
	if err != nil || claims.Subject != "operator" {
		t.Fatalf("claims=%#v err=%v", claims, err)
	}
	if _, ok := claims.Scopes["memory.read"]; !ok {
		t.Fatalf("scopes=%#v", claims.Scopes)
	}
	if _, err := verifier.Validate(context.Background(), testToken(t, private, "key-1", server.URL, "https://other.example/mcp", now.Add(time.Minute)), now); err == nil {
		t.Fatal("wrong resource audience accepted")
	}
	if _, err := verifier.Validate(context.Background(), testToken(t, private, "key-1", server.URL, "https://punaro.example/mcp", now.Add(-time.Minute)), now); err == nil {
		t.Fatal("expired token accepted")
	}
}

func TestVerifierRejectsUnknownSigningKey(t *testing.T) {
	known, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{testJWK("known", &known.PublicKey)}})
	}))
	defer server.Close()
	verifier, err := NewVerifier(Config{Issuer: server.URL, Audience: "https://punaro.example/mcp", JWKSURL: server.URL}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	bad := testToken(t, unknown, "unknown", server.URL, "https://punaro.example/mcp", time.Now().UTC().Add(time.Minute))
	if _, err := verifier.Validate(context.Background(), bad, time.Now().UTC()); err == nil {
		t.Fatal("unknown signing key accepted")
	}
	if _, err := verifier.Validate(context.Background(), bad, time.Now().UTC()); err == nil || requests != 1 {
		t.Fatalf("unknown key requests=%d err=%v", requests, err)
	}
}

func testToken(t *testing.T, private *rsa.PrivateKey, kid, issuer, audience string, expiry time.Time) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": issuer, "aud": audience, "sub": "operator", "exp": expiry.Unix(), "scope": "memory.read memory.propose"})
	token.Header["kid"] = kid
	raw, err := token.SignedString(private)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func testJWK(kid string, key *rsa.PublicKey) map[string]string {
	exponent := big.NewInt(int64(key.E)).Bytes()
	return map[string]string{"kty": "RSA", "kid": kid, "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(exponent)}
}
