// Package access validates Cloudflare Access JWTs at the origin boundary.
package access

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const maxJWKSBytes = 256 << 10

// Config contains only Cloudflare Access public metadata. The audience is the
// application AUD tag; no user, device, or service-token secret is stored.
type Config struct {
	Issuer   string
	Audience string
	JWKSURL  string
	CacheTTL time.Duration
}

// Verifier caches public signing keys for a bounded interval and refreshes on
// an unknown key ID to accommodate Access key rotation without trusting stale
// JWTs indefinitely.
type Verifier struct {
	issuer   string
	audience string
	jwksURL  string
	cacheTTL time.Duration
	client   *http.Client

	mu          sync.Mutex
	keys        map[string]*rsa.PublicKey
	cacheExpiry time.Time
}

// NewVerifier validates required origin-verification metadata.
func NewVerifier(config Config, client *http.Client) (*Verifier, error) {
	if strings.TrimSpace(config.Issuer) == "" || strings.TrimSpace(config.Audience) == "" || strings.TrimSpace(config.JWKSURL) == "" {
		return nil, fmt.Errorf("access issuer, audience, and JWKS URL are required")
	}
	issuer, err := url.Parse(config.Issuer)
	if err != nil || issuer.Scheme == "" || issuer.Host == "" {
		return nil, fmt.Errorf("invalid Access issuer")
	}
	jwksURL, err := url.Parse(config.JWKSURL)
	if err != nil || jwksURL.Scheme == "" || jwksURL.Host == "" {
		return nil, fmt.Errorf("invalid Access JWKS URL")
	}
	if config.CacheTTL <= 0 {
		config.CacheTTL = 5 * time.Minute
	}
	if config.CacheTTL > time.Hour {
		return nil, fmt.Errorf("access JWKS cache TTL must not exceed one hour")
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &Verifier{issuer: config.Issuer, audience: config.Audience, jwksURL: config.JWKSURL, cacheTTL: config.CacheTTL, client: client}, nil
}

// Verify accepts only RS256 JWTs with a known cached-or-refreshed signing key,
// matching issuer/audience, and normal JWT time claims.
func (v *Verifier) Verify(rawToken string, now time.Time) error {
	if strings.TrimSpace(rawToken) == "" {
		return fmt.Errorf("access token is required")
	}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}), jwt.WithIssuer(v.issuer), jwt.WithAudience(v.audience), jwt.WithTimeFunc(func() time.Time { return now }))
	_, err := parser.Parse(rawToken, func(token *jwt.Token) (any, error) {
		keyID, _ := token.Header["kid"].(string)
		if keyID == "" {
			return nil, fmt.Errorf("access token key ID is missing")
		}
		return v.key(context.Background(), keyID, now)
	})
	if err != nil {
		return fmt.Errorf("invalid Access token")
	}
	return nil
}

// Middleware admits only requests bearing a valid assertion that Access added
// after its own policy decision. Application machine authentication remains a
// separate required layer inside the wrapped relay handler.
func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := v.Verify(r.Header.Get("Cf-Access-Jwt-Assertion"), time.Now().UTC()); err != nil {
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (v *Verifier) key(ctx context.Context, keyID string, now time.Time) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if now.Before(v.cacheExpiry) {
		if key, found := v.keys[keyID]; found {
			return key, nil
		}
	}
	if err := v.refreshLocked(ctx, now); err != nil {
		return nil, err
	}
	key, found := v.keys[keyID]
	if !found {
		return nil, fmt.Errorf("access token signing key is unknown")
	}
	return key, nil
}

func (v *Verifier) refreshLocked(ctx context.Context, now time.Time) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return err
	}
	response, err := v.client.Do(request)
	if err != nil {
		return fmt.Errorf("fetch Access JWKS: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch Access JWKS: HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxJWKSBytes+1))
	if err != nil || len(body) > maxJWKSBytes {
		return fmt.Errorf("read Access JWKS")
	}
	var document struct {
		Keys []struct {
			KeyType   string `json:"kty"`
			KeyID     string `json:"kid"`
			Algorithm string `json:"alg"`
			Use       string `json:"use"`
			Modulus   string `json:"n"`
			Exponent  string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &document); err != nil || len(document.Keys) == 0 {
		return fmt.Errorf("decode Access JWKS")
	}
	keys := make(map[string]*rsa.PublicKey, len(document.Keys))
	for _, record := range document.Keys {
		if record.KeyType != "RSA" || record.Algorithm != "RS256" || (record.Use != "" && record.Use != "sig") || record.KeyID == "" {
			continue
		}
		key, err := parseRSAKey(record.Modulus, record.Exponent)
		if err != nil {
			continue
		}
		if _, duplicate := keys[record.KeyID]; duplicate {
			return fmt.Errorf("duplicate Access JWKS key ID")
		}
		keys[record.KeyID] = key
	}
	if len(keys) == 0 {
		return fmt.Errorf("access JWKS contains no valid signing key")
	}
	v.keys = keys
	v.cacheExpiry = now.Add(v.cacheTTL)
	return nil
}

func parseRSAKey(modulus, exponent string) (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(modulus)
	if err != nil || len(n) < 256 {
		return nil, fmt.Errorf("invalid RSA modulus")
	}
	e, err := base64.RawURLEncoding.DecodeString(exponent)
	if err != nil || len(e) == 0 || len(e) > 4 {
		return nil, fmt.Errorf("invalid RSA exponent")
	}
	exponentInt := 0
	for _, value := range e {
		exponentInt = exponentInt<<8 | int(value)
	}
	if exponentInt < 3 || exponentInt%2 == 0 {
		return nil, fmt.Errorf("invalid RSA exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exponentInt}, nil
}
