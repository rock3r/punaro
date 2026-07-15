package v3

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type staticPermitIssuanceAuthorityProvider struct{ authority PermitIssuanceAuthority }

func (s staticPermitIssuanceAuthorityProvider) ResolvePermitIssuanceAuthority(context.Context, time.Time) (PermitIssuanceAuthority, error) {
	return s.authority, nil
}

type permitRequestAuthorizerFunc func(context.Context, PermitRequest) error

func (f permitRequestAuthorizerFunc) AuthorizePermitRequest(ctx context.Context, request PermitRequest) error {
	return f(ctx, request)
}

func TestPermitHTTPHandlerMintsCanonicalV3SourceInitPermit(t *testing.T) {
	issuerPublic, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderPublic, holderPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, time.July, 15, 2, 0, 0, 0, time.UTC)
	store, err := openSourceStore(privateDatabase(t), defaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	request := testPermitRequest(clock)
	if err := SignPermitRequest(&request, holderPrivate); err != nil {
		t.Fatal(err)
	}
	raw, err := EncodePermitRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	authority := permitIssuanceAuthorityStub{issuerID: requestIssuerID(), issuer: issuerPublic, holderID: request.HolderDeviceID, holderGen: request.HolderGeneration, holder: holderPublic, binding: DirectoryPermitBinding{Audience: testHash(1), DirectoryHead: testHash(8), RevocationEpoch: 4, ExpiresAt: uint64(clock.Add(20 * time.Second).Unix())}}
	issuer, err := NewPermitIssuer(PermitIssuerOptions{Store: store, IssuerKeyID: requestIssuerID(), PrivateKey: issuerPrivate, MaxLifetime: 30 * time.Second, MaxBytes: 1 << 20, MaxChunks: 4, MaxOperations: 2, MaxActive: 4, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewPermitHTTPHandler(issuer, staticPermitIssuanceAuthorityProvider{authority: authority}, permitRequestAuthorizerFunc(func(context.Context, PermitRequest) error { return nil }), func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	httpRequest := httptest.NewRequest(http.MethodPost, "/v3/permits", bytes.NewReader(raw))
	httpRequest.Header.Set("Content-Type", "application/cbor")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httpRequest)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d", response.Code)
	}
	permit, err := DecodePermit(response.Body.Bytes())
	if err != nil || permit.StagedManifestCommitment != request.StagedManifestCommitment {
		t.Fatalf("permit=%+v err=%v", permit, err)
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cache-control=%q", got)
	}
	// Any content coding invalidates an otherwise signed body; the handler must
	// not rely on Header.Get, which misses duplicate/empty values.
	httpRequest = httptest.NewRequest(http.MethodPost, "/v3/permits", bytes.NewReader(raw))
	httpRequest.Header.Set("Content-Type", "application/cbor")
	httpRequest.Header.Add("Content-Encoding", "")
	httpRequest.Header.Add("Content-Encoding", "gzip")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httpRequest)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("content-encoding status=%d", response.Code)
	}
	httpRequest = httptest.NewRequest(http.MethodPost, "/v3/permits", bytes.NewReader(raw))
	httpRequest.Header.Add("Content-Type", "application/cbor")
	httpRequest.Header.Add("Content-Type", "application/octet-stream")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httpRequest)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("duplicate content-type status=%d", response.Code)
	}
}
