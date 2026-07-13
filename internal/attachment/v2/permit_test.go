package v2

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestPermitCanonicalSignatureAndFreshIssuerBinding(t *testing.T) {
	t.Parallel()
	issuerPublic, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now().UTC().Truncate(time.Second)
	permit := samplePermit()
	permit.IssuedAt, permit.ExpiresAt = testUnix(t, clock.Add(-time.Second)), testUnix(t, clock.Add(30*time.Second))
	if err := SignPermit(&permit, issuerPrivate); err != nil {
		t.Fatal(err)
	}
	raw, err := EncodePermit(permit)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePermit(raw)
	if err != nil {
		t.Fatal(err)
	}
	resolver := permitIssuerStub{keyID: permit.IssuerKeyID, key: issuerPublic}
	if err := VerifyPermit(decoded, resolver, clock); err != nil {
		t.Fatal(err)
	}
	decoded.Operation = PermitOperationDownload
	if err := VerifyPermit(decoded, resolver, clock); err == nil {
		t.Fatal("mutated permit was accepted")
	}
	if err := VerifyPermit(permit, permitIssuerStub{keyID: permit.IssuerKeyID, key: issuerPublic, reject: true}, clock); err == nil {
		t.Fatal("revoked permit issuer was accepted")
	}
}

type permitIssuerStub struct {
	keyID  [32]byte
	key    ed25519.PublicKey
	reject bool
}

func (s permitIssuerStub) CurrentPermitIssuerKey(keyID [32]byte) (ed25519.PublicKey, error) {
	if s.reject || keyID != s.keyID {
		return nil, errUnknownPermitIssuer
	}
	return s.key, nil
}

func samplePermit() Permit {
	return Permit{
		Audience: bytes32(1), Serial: bytes16(2), IssuerKeyID: bytes32(3),
		HolderDeviceID: bytes16(4), HolderGeneration: 1, HolderRole: PermitHolderSender,
		TransferID: bytes16(5), ConversationID: bytes16(6), RecipientDeviceID: bytes16(7),
		RecipientGeneration: 2, AttemptGeneration: 1, Operation: PermitOperationUpload,
		DirectoryHead: bytes32(8), MembershipCommitment: bytes32(9), RevocationEpoch: 1,
		IssuedAt: 1_700_000_000, ExpiresAt: 1_700_000_030, MaxBytes: 1 << 20,
		MaxChunks: 4, MaxOperations: 1,
	}
}
