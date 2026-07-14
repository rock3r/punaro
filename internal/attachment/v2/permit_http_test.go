package v2

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type staticPermitIssuanceAuthorityProvider struct{ authority PermitIssuanceAuthority }

func (p staticPermitIssuanceAuthorityProvider) ResolvePermitIssuanceAuthority(context.Context, time.Time) (PermitIssuanceAuthority, error) {
	return p.authority, nil
}

func TestPermitHTTPHandlerMintsOnlyCanonicalHolderSignedRequest(t *testing.T) {
	t.Parallel()
	issuerPublic, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderPublic, holderPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now().UTC().Truncate(time.Second)
	request := samplePermitRequest(t, clock)
	if err := SignPermitRequest(&request, holderPrivate); err != nil {
		t.Fatal(err)
	}
	rawRequest, err := EncodePermitRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	ledger, err := OpenSQLitePermitLedger(filepath.Join(parent, "ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	authority := permitIssuanceAuthorityStub{issuerID: bytes32(3), issuer: issuerPublic, holderID: request.HolderDeviceID, holderGen: request.HolderGeneration, holder: holderPublic, binding: DirectoryPermitBinding{Audience: bytes32(1), DirectoryHead: bytes32(8), RevocationEpoch: 4, ExpiresAt: testUnix(t, clock.Add(20*time.Second))}}
	issuer, err := NewPermitIssuer(PermitIssuerOptions{Ledger: ledger, IssuerKeyID: bytes32(3), PrivateKey: issuerPrivate, MaxLifetime: 30 * time.Second, MaxBytes: 1 << 20, MaxChunks: 4, MaxOperations: 2, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewPermitHTTPHandler(issuer, staticPermitIssuanceAuthorityProvider{authority: authority}, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	httpRequest := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v2/permits", bytes.NewReader(rawRequest))
	httpRequest.Header.Set("Content-Type", "application/cbor")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httpRequest)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/cbor" {
		t.Fatalf("status=%d type=%q", response.Code, response.Header().Get("Content-Type"))
	}
	permit, err := DecodePermit(response.Body.Bytes())
	if err != nil || permit.HolderDeviceID != request.HolderDeviceID {
		t.Fatalf("permit=%+v err=%v", permit, err)
	}
	bad := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v2/permits?x=1", bytes.NewReader(rawRequest))
	bad.Header.Set("Content-Type", "application/cbor")
	badResponse := httptest.NewRecorder()
	handler.ServeHTTP(badResponse, bad)
	if badResponse.Code != http.StatusBadRequest {
		t.Fatalf("bad status=%d", badResponse.Code)
	}
}
