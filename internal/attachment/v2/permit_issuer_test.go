package v2

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
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

func TestPermitIssuerCreatesOneDurablePermitForSignedRequest(t *testing.T) {
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
	decodedRequest, err := DecodePermitRequest(rawRequest)
	if err != nil || decodedRequest.RequestID != request.RequestID || decodedRequest.Signature != request.Signature {
		t.Fatalf("decoded request=%+v err=%v", decodedRequest, err)
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
	issuer, err := NewPermitIssuer(PermitIssuerOptions{Ledger: ledger, IssuerKeyID: bytes32(3), PrivateKey: issuerPrivate, MaxLifetime: 30 * time.Second, MaxBytes: 1 << 20, MaxChunks: 4, MaxOperations: 2, MaxActive: 4, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	permit, replayed, err := issuer.Issue(context.Background(), request, authority)
	if err != nil || replayed || permit.IssuerKeyID != bytes32(3) || permit.Audience != authority.binding.Audience || permit.DirectoryHead != authority.binding.DirectoryHead || permit.RevocationEpoch != authority.binding.RevocationEpoch {
		t.Fatalf("permit=%+v replayed=%v err=%v", permit, replayed, err)
	}
	if err := VerifyPermit(permit, authority, clock); err != nil {
		t.Fatal(err)
	}
	retry, replayed, err := issuer.Issue(context.Background(), request, authority)
	if err != nil || !replayed || retry.Serial != permit.Serial {
		t.Fatalf("retry=%+v replayed=%v err=%v", retry, replayed, err)
	}
	request.MaxBytes++
	if err := SignPermitRequest(&request, holderPrivate); err != nil {
		t.Fatal(err)
	}
	if _, _, err := issuer.Issue(context.Background(), request, authority); err == nil {
		t.Fatal("changed request reused its issuance ID")
	}
}

func TestPermitIssuerRejectsUnsignedOrOverbroadRequest(t *testing.T) {
	t.Parallel()
	issuerPublic, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now().UTC().Truncate(time.Second)
	request := samplePermitRequest(t, clock)
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
	issuer, err := NewPermitIssuer(PermitIssuerOptions{Ledger: ledger, IssuerKeyID: bytes32(3), PrivateKey: issuerPrivate, MaxLifetime: 30 * time.Second, MaxBytes: 1 << 20, MaxChunks: 4, MaxOperations: 2, MaxActive: 4, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := issuer.Issue(context.Background(), request, authority); err == nil {
		t.Fatal("unsigned request accepted")
	}
}

func TestPermitIssuerRefreshesIdempotentRequestAfterDirectoryHeadAdvance(t *testing.T) {
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
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	ledger, err := OpenSQLitePermitLedger(filepath.Join(parent, "ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	authorityA := permitIssuanceAuthorityStub{issuerID: bytes32(3), issuer: issuerPublic, holderID: request.HolderDeviceID, holderGen: request.HolderGeneration, holder: holderPublic, binding: DirectoryPermitBinding{Audience: bytes32(1), DirectoryHead: bytes32(8), RevocationEpoch: 4, ExpiresAt: testUnix(t, clock.Add(20*time.Second))}}
	issuer, err := NewPermitIssuer(PermitIssuerOptions{Ledger: ledger, IssuerKeyID: bytes32(3), PrivateKey: issuerPrivate, MaxLifetime: 30 * time.Second, MaxBytes: 1 << 20, MaxChunks: 4, MaxOperations: 2, MaxActive: 4, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	first, replayed, err := issuer.Issue(context.Background(), request, authorityA)
	if err != nil || replayed {
		t.Fatalf("first=%+v replayed=%v err=%v", first, replayed, err)
	}
	authorityB := authorityA
	authorityB.binding.DirectoryHead = bytes32(10)
	refreshed, replayed, err := issuer.Issue(context.Background(), request, authorityB)
	if err != nil || replayed || refreshed.Serial == first.Serial || refreshed.DirectoryHead != authorityB.binding.DirectoryHead {
		t.Fatalf("refreshed=%+v replayed=%v err=%v", refreshed, replayed, err)
	}
	if err := VerifyPermit(refreshed, authorityB, clock); err != nil {
		t.Fatalf("refreshed permit is not valid under the new head: %v", err)
	}
}

func TestPermitIssuerBoundsActiveCapabilitiesButPreservesRetriesAndReapsExpiry(t *testing.T) {
	issuerPublic, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderPublic, holderPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now().UTC().Truncate(time.Second)
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	ledger, err := OpenSQLitePermitLedger(filepath.Join(parent, "ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	authority := permitIssuanceAuthorityStub{issuerID: bytes32(3), issuer: issuerPublic, holderID: bytes16(4), holderGen: 1, holder: holderPublic, binding: DirectoryPermitBinding{Audience: bytes32(1), DirectoryHead: bytes32(8), RevocationEpoch: 4, ExpiresAt: testUnix(t, clock.Add(30*time.Second))}}
	issuer, err := NewPermitIssuer(PermitIssuerOptions{Ledger: ledger, IssuerKeyID: bytes32(3), PrivateKey: issuerPrivate, MaxLifetime: 30 * time.Second, MaxBytes: 1 << 20, MaxChunks: 4, MaxOperations: 2, MaxActive: 1, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	firstRequest := samplePermitRequest(t, clock)
	if err := SignPermitRequest(&firstRequest, holderPrivate); err != nil {
		t.Fatal(err)
	}
	first, replayed, err := issuer.Issue(context.Background(), firstRequest, authority)
	if err != nil || replayed {
		t.Fatalf("first=%+v replayed=%v err=%v", first, replayed, err)
	}
	retry, replayed, err := issuer.Issue(context.Background(), firstRequest, authority)
	if err != nil || !replayed || retry.Serial != first.Serial {
		t.Fatalf("retry=%+v replayed=%v err=%v", retry, replayed, err)
	}
	secondRequest := samplePermitRequest(t, clock)
	secondRequest.RequestID = bytes16(91)
	if err := SignPermitRequest(&secondRequest, holderPrivate); err != nil {
		t.Fatal(err)
	}
	if _, _, err := issuer.Issue(context.Background(), secondRequest, authority); err == nil {
		t.Fatal("new permit bypassed active capability quota")
	}
	clock = clock.Add(16 * time.Second)
	authority.binding.ExpiresAt = testUnix(t, clock.Add(14*time.Second))
	secondRequest = samplePermitRequest(t, clock)
	secondRequest.RequestID = bytes16(91)
	if err := SignPermitRequest(&secondRequest, holderPrivate); err != nil {
		t.Fatal(err)
	}
	second, replayed, err := issuer.Issue(context.Background(), secondRequest, authority)
	if err != nil || replayed || second.Serial == first.Serial {
		t.Fatalf("post-expiry issuance=%+v replayed=%v err=%v", second, replayed, err)
	}
	var permits, requests int
	if err := ledger.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM issued_permits").Scan(&permits); err != nil {
		t.Fatal(err)
	}
	if err := ledger.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM issued_permit_requests").Scan(&requests); err != nil {
		t.Fatal(err)
	}
	if permits != 1 || requests != 1 {
		t.Fatalf("expired permit state was retained: permits=%d requests=%d", permits, requests)
	}
}

func samplePermitRequest(t *testing.T, clock time.Time) PermitRequest {
	return PermitRequest{RequestID: bytes16(90), HolderDeviceID: bytes16(4), HolderGeneration: 1, HolderRole: PermitHolderSender, TransferID: bytes16(5), ConversationID: bytes16(6), SenderDeviceID: bytes16(4), SenderGeneration: 1, RecipientDeviceID: bytes16(7), RecipientGeneration: 2, AttemptGeneration: 1, Operation: PermitOperationUpload, MembershipCommitment: bytes32(9), IssuedAt: testUnix(t, clock.Add(-time.Second)), ExpiresAt: testUnix(t, clock.Add(15*time.Second)), MaxBytes: 1024, MaxChunks: 1, MaxOperations: 1}
}
