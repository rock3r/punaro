package v3

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

type runtimeAuthorityProvider struct{ authority PermitIssuanceAuthority }

func (p runtimeAuthorityProvider) ResolveAttachmentAuthority(context.Context, time.Time) (AttachmentAuthority, error) {
	authority, ok := p.authority.(AttachmentAuthority)
	if !ok {
		return nil, errors.New("not an attachment authority")
	}
	return authority, nil
}
func (p runtimeAuthorityProvider) ResolvePermitIssuanceAuthority(context.Context, time.Time) (PermitIssuanceAuthority, error) {
	return p.authority, nil
}

func TestAttachmentRuntimeBuildsBothV3HandlersOnlyWithAllAdmissions(t *testing.T) {
	issuerPublic, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, time.July, 15, 3, 0, 0, 0, time.UTC)
	// #nosec G115 -- the test clock is fixed and positive.
	authority := permitIssuanceAuthorityStub{issuerID: requestIssuerID(), issuer: issuerPublic, holderID: testID(4), holderGen: 1, holder: holderPublic, binding: DirectoryPermitBinding{Audience: testHash(1), DirectoryHead: testHash(8), RevocationEpoch: 4, ExpiresAt: uint64(clock.Add(20 * time.Second).Unix())}} // #nosec G115 -- test clock is fixed after the Unix epoch.
	provider := runtimeAuthorityProvider{authority: authority}
	if _, err := NewAttachmentRuntime(AttachmentRuntimeOptions{}); err == nil {
		t.Fatal("runtime accepted missing dependencies")
	}
	runtime, err := NewAttachmentRuntime(AttachmentRuntimeOptions{SourceStorePath: privateDatabase(t), AttachmentAuthority: provider, PermitAuthority: provider, AttachmentAuthorize: panicRequestAuthorizer{}, PermitAuthorize: permitRequestAuthorizerFunc(func(context.Context, PermitRequest) error { return nil }), IssuerKeyID: requestIssuerID(), IssuerPrivateKey: issuerPrivate, MaxLifetime: 30 * time.Second, MaxBytes: 1 << 20, MaxChunks: 4, MaxOperations: 2, MaxActive: 4, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	if runtime.AttachmentHandler() == nil || runtime.PermitHandler() == nil {
		t.Fatal("runtime omitted a v3 handler")
	}
}

func TestAttachmentRuntimeReapsExpiredSourcesInBoundedBatches(t *testing.T) {
	clock := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	issuerPublic, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G115 -- test clock is fixed after the Unix epoch.
	authority := permitIssuanceAuthorityStub{issuerID: requestIssuerID(), issuer: issuerPublic, holderID: testID(4), holderGen: 1, holder: holderPublic, binding: DirectoryPermitBinding{Audience: testHash(1), DirectoryHead: testHash(8), RevocationEpoch: 4, ExpiresAt: uint64(clock.Add(20 * time.Second).Unix())}}
	provider := runtimeAuthorityProvider{authority: authority}
	runtime, err := NewAttachmentRuntime(AttachmentRuntimeOptions{SourceStorePath: privateDatabase(t), AttachmentAuthority: provider, PermitAuthority: provider, AttachmentAuthorize: panicRequestAuthorizer{}, PermitAuthorize: permitRequestAuthorizerFunc(func(context.Context, PermitRequest) error { return nil }), IssuerKeyID: requestIssuerID(), IssuerPrivateKey: issuerPrivate, MaxLifetime: 30 * time.Second, MaxBytes: 1 << 20, MaxChunks: 4, MaxOperations: 2, MaxActive: 4, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	source := verifiedTestSource(t, clock, 1, 1, 1)
	if err := runtime.store.initialize(context.Background(), source, clock); err != nil {
		t.Fatal(err)
	}
	if reaped, err := runtime.ReapExpired(context.Background(), clock.Add(31*time.Second), 1); err != nil || reaped != 1 {
		t.Fatalf("reaped=%d err=%v", reaped, err)
	}
	assertTransferStatus(t, runtime.store, source.TransferID(), transferExpired)
}
