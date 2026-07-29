// Package mcpoauth validates remote MCP OAuth access tokens as an audience-
// bound protected resource. It never forwards a token to another service.
package mcpoauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
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

// Config identifies one OAuth authorization server and this exact resource.
type Config struct {
	Issuer   string
	Audience string
	JWKSURL  string
	CacheTTL time.Duration
}

// Claims are the verified identity and OAuth scopes available to later MCP
// authorization layers.
type Claims struct {
	Subject string
	Scopes  map[string]struct{}
}

// Verifier caches public signing keys and validates only RS256 access tokens.
type Verifier struct {
	issuer, audience, jwksURL string
	cacheTTL                  time.Duration
	client                    *http.Client
	mu                        sync.Mutex
	keys                      map[string]*rsa.PublicKey
	cacheExpiry               time.Time
	nextUnknownKeyRefresh     time.Time
}

// NewVerifier constructs a bounded RS256 verifier for one remote MCP resource.
func NewVerifier(config Config, client *http.Client) (*Verifier, error) {
	if !secureURL(config.Issuer) || !secureURL(config.JWKSURL) || config.Audience == "" {
		return nil, errors.New("invalid remote MCP OAuth verifier configuration")
	}
	if config.CacheTTL <= 0 {
		config.CacheTTL = 5 * time.Minute
	}
	if config.CacheTTL > time.Hour {
		return nil, errors.New("invalid remote MCP OAuth verifier configuration")
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	} else {
		clone := *client
		client = &clone
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return &Verifier{issuer: config.Issuer, audience: config.Audience, jwksURL: config.JWKSURL, cacheTTL: config.CacheTTL, client: client}, nil
}

// Validate verifies one access token and returns only its subject and scopes.
func (v *Verifier) Validate(ctx context.Context, raw string, now time.Time) (Claims, error) {
	if strings.TrimSpace(raw) == "" {
		return Claims{}, errors.New("remote MCP token is invalid")
	}
	registered := jwt.RegisteredClaims{}
	claims := struct {
		Scope string `json:"scope"`
		jwt.RegisteredClaims
	}{RegisteredClaims: registered}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}), jwt.WithIssuer(v.issuer), jwt.WithAudience(v.audience), jwt.WithExpirationRequired(), jwt.WithTimeFunc(now.UTC))
	_, err := parser.ParseWithClaims(raw, &claims, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("remote MCP token is invalid")
		}
		return v.key(ctx, kid, now.UTC())
	})
	if err != nil || claims.Subject == "" {
		return Claims{}, errors.New("remote MCP token is invalid")
	}
	scopes := make(map[string]struct{})
	for _, scope := range strings.Fields(claims.Scope) {
		scopes[scope] = struct{}{}
	}
	return Claims{Subject: claims.Subject, Scopes: scopes}, nil
}

func (v *Verifier) key(ctx context.Context, kid string, now time.Time) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if now.Before(v.cacheExpiry) {
		key := v.keys[kid]
		if key != nil {
			return key, nil
		}
		if now.Before(v.nextUnknownKeyRefresh) {
			return nil, errors.New("remote MCP token is invalid")
		}
		v.nextUnknownKeyRefresh = now.Add(time.Minute)
	}
	if err := v.refreshLocked(ctx, now); err != nil {
		return nil, err
	}
	if key := v.keys[kid]; key != nil {
		return key, nil
	}
	v.nextUnknownKeyRefresh = now.Add(time.Minute)
	return nil, errors.New("remote MCP token is invalid")
}

func (v *Verifier) refreshLocked(ctx context.Context, now time.Time) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return err
	}
	response, err := v.client.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxJWKSBytes+1))
	if err != nil || len(body) == 0 || len(body) > maxJWKSBytes {
		return errors.New("invalid remote MCP JWKS")
	}
	var document struct {
		Keys []struct {
			KTY string `json:"kty"`
			KID string `json:"kid"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if json.Unmarshal(body, &document) != nil || len(document.Keys) == 0 {
		return errors.New("invalid remote MCP JWKS")
	}
	keys := make(map[string]*rsa.PublicKey, len(document.Keys))
	for _, record := range document.Keys {
		if record.KTY != "RSA" || (record.Alg != "" && record.Alg != "RS256") || (record.Use != "" && record.Use != "sig") || record.KID == "" {
			continue
		}
		key, err := rsaKey(record.N, record.E)
		if err != nil {
			continue
		}
		if keys[record.KID] != nil {
			return errors.New("invalid remote MCP JWKS")
		}
		keys[record.KID] = key
	}
	if len(keys) == 0 {
		return errors.New("invalid remote MCP JWKS")
	}
	v.keys, v.cacheExpiry = keys, now.Add(v.cacheTTL)
	v.nextUnknownKeyRefresh = time.Time{}
	return nil
}

func secureURL(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.String() == raw
}

func rsaKey(modulus, exponent string) (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(modulus)
	if err != nil || len(n) < 256 {
		return nil, errors.New("invalid RSA key")
	}
	e, err := base64.RawURLEncoding.DecodeString(exponent)
	if err != nil || len(e) == 0 || len(e) > 8 {
		return nil, errors.New("invalid RSA key")
	}
	value := 0
	for _, b := range e {
		value = value<<8 | int(b)
	}
	if value < 3 || value%2 == 0 {
		return nil, errors.New("invalid RSA key")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: value}, nil
}
