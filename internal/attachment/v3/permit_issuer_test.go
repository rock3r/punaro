package v3

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

type permitIssuanceAuthorityStub struct {
	issuerID  [32]byte
	issuer    ed25519.PublicKey
	holderID  [16]byte
	holderGen uint64
	holder    ed25519.PublicKey
	binding   DirectoryPermitBinding
}

func (s permitIssuanceAuthorityStub) CurrentPermitIssuerKey(keyID [32]byte) (ed25519.PublicKey, error) {
	if keyID != s.issuerID {
		return nil, errors.New("unknown issuer")
	}
	return append(ed25519.PublicKey(nil), s.issuer...), nil
}

func (s permitIssuanceAuthorityStub) CurrentPermitBinding(time.Time) (DirectoryPermitBinding, error) {
	return s.binding, nil
}

func (s permitIssuanceAuthorityStub) CurrentDeviceSigningKey(deviceID [16]byte, generation uint64) (ed25519.PublicKey, error) {
	if deviceID != s.holderID || generation != s.holderGen {
		return nil, errors.New("unknown holder")
	}
	return append(ed25519.PublicKey(nil), s.holder...), nil
}

func (s permitIssuanceAuthorityStub) ValidatePermitAuthority(permit Permit, _ time.Time) (ed25519.PublicKey, error) {
	if permit.IssuerKeyID != s.issuerID || permit.Audience != s.binding.Audience || permit.DirectoryHead != s.binding.DirectoryHead || permit.RevocationEpoch != s.binding.RevocationEpoch || permit.ExpiresAt > s.binding.ExpiresAt {
		return nil, errors.New("invalid permit binding")
	}
	return append(ed25519.PublicKey(nil), s.issuer...), nil
}

func TestPermitIssuerMintsV3PermitAndReturnsExactRetry(t *testing.T) {
	t.Parallel()
	issuerPublic, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderPublic, holderPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, time.July, 15, 1, 0, 0, 0, time.UTC)
	store, err := openSourceStore(privateDatabase(t), defaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	request := testPermitRequest(clock)
	if err := SignPermitRequest(&request, holderPrivate); err != nil {
		t.Fatal(err)
	}
	authority := permitIssuanceAuthorityStub{
		issuerID: requestIssuerID(), issuer: issuerPublic,
		holderID: request.HolderDeviceID, holderGen: request.HolderGeneration, holder: holderPublic,
		binding: DirectoryPermitBinding{Audience: testHash(1), DirectoryHead: testHash(8), RevocationEpoch: 4, ExpiresAt: uint64(clock.Add(20 * time.Second).Unix())},
	}
	issuer, err := NewPermitIssuer(PermitIssuerOptions{Store: store, IssuerKeyID: requestIssuerID(), PrivateKey: issuerPrivate, MaxLifetime: 30 * time.Second, MaxBytes: 1 << 20, MaxChunks: 4, MaxOperations: 2, MaxActive: 4, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	permit, replayed, err := issuer.Issue(context.Background(), request, authority)
	if err != nil || replayed {
		t.Fatalf("Issue() permit=%+v replayed=%v err=%v", permit, replayed, err)
	}
	if permit.StagedManifestCommitment != request.StagedManifestCommitment || permit.IssuerKeyID != authority.issuerID {
		t.Fatalf("permit does not preserve v3 issuance binding: %+v", permit)
	}
	if err := VerifyPermit(permit, authority, clock); err != nil {
		t.Fatal(err)
	}
	retry, replayed, err := issuer.Issue(context.Background(), request, authority)
	if err != nil || !replayed || retry != permit {
		t.Fatalf("retry=%+v replayed=%v err=%v", retry, replayed, err)
	}
	request.MaxBytes++
	if err := SignPermitRequest(&request, holderPrivate); err != nil {
		t.Fatal(err)
	}
	if _, _, err := issuer.Issue(context.Background(), request, authority); err == nil {
		t.Fatal("changed request reused v3 issuance ID")
	}
}

func TestPermitIssuerRetainsRequestIdentityAfterPermitExpiry(t *testing.T) {
	issuerPublic, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderPublic, holderPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, time.July, 15, 1, 30, 0, 0, time.UTC)
	store, err := openSourceStore(privateDatabase(t), defaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	request := testPermitRequest(clock)
	if err := SignPermitRequest(&request, holderPrivate); err != nil {
		t.Fatal(err)
	}
	authority := permitIssuanceAuthorityStub{issuerID: requestIssuerID(), issuer: issuerPublic, holderID: request.HolderDeviceID, holderGen: request.HolderGeneration, holder: holderPublic, binding: DirectoryPermitBinding{Audience: testHash(1), DirectoryHead: testHash(8), RevocationEpoch: 4, ExpiresAt: uint64(clock.Add(5 * time.Minute).Unix())}}
	issuer, err := NewPermitIssuer(PermitIssuerOptions{Store: store, IssuerKeyID: requestIssuerID(), PrivateKey: issuerPrivate, MaxLifetime: 30 * time.Second, MaxBytes: 1 << 20, MaxChunks: 4, MaxOperations: 2, MaxActive: 4, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := issuer.Issue(context.Background(), request, authority); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(30 * time.Second)
	reusedID := request
	reusedID.IssuedAt = uint64(clock.Unix())
	reusedID.ExpiresAt = uint64(clock.Add(20 * time.Second).Unix())
	reusedID.MaxBytes++
	if err := SignPermitRequest(&reusedID, holderPrivate); err != nil {
		t.Fatal(err)
	}
	if _, _, err := issuer.Issue(context.Background(), reusedID, authority); err == nil {
		t.Fatal("expired request ID was reused for changed holder-controlled content")
	}
}

func TestPermitIssuerBoundsRetainedRequestJournal(t *testing.T) {
	issuerPublic, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderPublic, holderPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, time.July, 15, 2, 30, 0, 0, time.UTC)
	store, err := openSourceStore(privateDatabase(t), defaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	request := testPermitRequest(clock)
	if err := SignPermitRequest(&request, holderPrivate); err != nil {
		t.Fatal(err)
	}
	authority := permitIssuanceAuthorityStub{issuerID: requestIssuerID(), issuer: issuerPublic, holderID: request.HolderDeviceID, holderGen: request.HolderGeneration, holder: holderPublic, binding: DirectoryPermitBinding{Audience: testHash(1), DirectoryHead: testHash(8), RevocationEpoch: 4, ExpiresAt: uint64(clock.Add(5 * time.Minute).Unix())}}
	issuer, err := NewPermitIssuer(PermitIssuerOptions{Store: store, IssuerKeyID: requestIssuerID(), PrivateKey: issuerPrivate, MaxLifetime: 30 * time.Second, MaxBytes: 1 << 20, MaxChunks: 4, MaxOperations: 2, MaxActive: 1, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := issuer.Issue(context.Background(), request, authority); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(30 * time.Second)
	second := testPermitRequest(clock)
	second.RequestID = testID(111)
	if err := SignPermitRequest(&second, holderPrivate); err != nil {
		t.Fatal(err)
	}
	if _, _, err := issuer.Issue(context.Background(), second, authority); err == nil {
		t.Fatal("expired permit request bypassed retained journal capacity")
	}
}

func requestIssuerID() [32]byte { return testHash(3) }

func testPermitRequest(now time.Time) PermitRequest {
	return PermitRequest{RequestID: testID(1), HolderDeviceID: testID(4), HolderGeneration: 1, HolderRole: permitHolderSender, TransferID: testID(5), ConversationID: testID(6), SenderDeviceID: testID(4), SenderGeneration: 1, RecipientDeviceID: testID(7), RecipientGeneration: 1, Operation: permitOperationSourceInit, MembershipCommitment: testHash(9), StagedManifestCommitment: testHash(10), IssuedAt: uint64(now.Unix()), ExpiresAt: uint64(now.Add(20 * time.Second).Unix()), MaxBytes: 1024, MaxChunks: 1, MaxOperations: 1}
}
