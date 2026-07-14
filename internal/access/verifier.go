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
	"os"
	"path/filepath"
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
	// JWKSFile is an optional local, root-managed JWKS snapshot. Exactly one
	// of JWKSURL and JWKSFile is required.
	JWKSFile string
	CacheTTL time.Duration
}

// Verifier caches public signing keys for a bounded interval and refreshes on
// an unknown key ID to accommodate Access key rotation without trusting stale
// JWTs indefinitely.
type Verifier struct {
	issuer   string
	audience string
	jwksURL  string
	jwksFile string
	cacheTTL time.Duration
	client   *http.Client

	mu          sync.Mutex
	keys        map[string]*rsa.PublicKey
	cacheExpiry time.Time
}

// NewVerifier validates required origin-verification metadata.
func NewVerifier(config Config, client *http.Client) (*Verifier, error) {
	if strings.TrimSpace(config.Issuer) == "" || strings.TrimSpace(config.Audience) == "" {
		return nil, fmt.Errorf("access issuer and audience are required")
	}
	issuer, err := parseSecureAccessURL(config.Issuer)
	if err != nil {
		return nil, fmt.Errorf("invalid Access issuer")
	}
	hasURL := strings.TrimSpace(config.JWKSURL) != ""
	hasFile := strings.TrimSpace(config.JWKSFile) != ""
	if hasURL == hasFile {
		return nil, fmt.Errorf("exactly one Access JWKS source is required")
	}
	var jwksURL *url.URL
	if hasURL {
		jwksURL, err = parseSecureAccessURL(config.JWKSURL)
		if err != nil {
			return nil, fmt.Errorf("invalid Access JWKS URL")
		}
	} else if err := validateJWKSSnapshotPath(config.JWKSFile); err != nil {
		return nil, fmt.Errorf("invalid Access JWKS snapshot")
	}
	if config.CacheTTL <= 0 {
		config.CacheTTL = 5 * time.Minute
	}
	if config.CacheTTL > time.Hour {
		return nil, fmt.Errorf("access JWKS cache TTL must not exceed one hour")
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	} else {
		clone := *client
		client = &clone
	}
	// A JWKS redirect could change the endpoint after configuration validation.
	// Reject it rather than relying on the client to preserve HTTPS and host
	// constraints across redirect hops.
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	verifier := &Verifier{issuer: issuer.String(), audience: config.Audience, cacheTTL: config.CacheTTL, client: client}
	if jwksURL != nil {
		verifier.jwksURL = jwksURL.String()
	} else {
		verifier.jwksFile = config.JWKSFile
	}
	return verifier, nil
}

func parseSecureAccessURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("unsafe Access URL")
	}
	return parsed, nil
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
	body, err := v.readJWKS(ctx, now)
	if err != nil {
		return err
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

func (v *Verifier) readJWKS(ctx context.Context, now time.Time) ([]byte, error) {
	if v.jwksFile != "" {
		return readFreshJWKSSnapshot(v.jwksFile, now, v.cacheTTL)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := v.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch Access JWKS: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch Access JWKS: HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxJWKSBytes+1))
	if err != nil || len(body) == 0 || len(body) > maxJWKSBytes {
		return nil, fmt.Errorf("read Access JWKS")
	}
	return body, nil
}

func validateJWKSSnapshotPath(path string) error {
	if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("snapshot path must be absolute")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("snapshot parent is unsafe")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("snapshot file is unsafe")
	}
	return nil
}

func readFreshJWKSSnapshot(path string, now time.Time, maxAge time.Duration) ([]byte, error) {
	if err := validateJWKSSnapshotPath(path); err != nil {
		return nil, fmt.Errorf("read Access JWKS snapshot")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("read Access JWKS snapshot")
	}
	// #nosec G304,G703 -- a locally configured path is checked before opening;
	// SameFile below detects replacement between Lstat and open.
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read Access JWKS snapshot")
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Mode().Perm()&0o022 != 0 || !os.SameFile(before, opened) || opened.ModTime().After(now.Add(time.Minute)) || now.Sub(opened.ModTime()) > maxAge {
		return nil, fmt.Errorf("read Access JWKS snapshot")
	}
	body, err := io.ReadAll(io.LimitReader(file, maxJWKSBytes+1))
	if err != nil || len(body) == 0 || len(body) > maxJWKSBytes {
		return nil, fmt.Errorf("read Access JWKS snapshot")
	}
	return body, nil
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
