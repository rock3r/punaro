package v3

import (
	"crypto/ed25519"
	"crypto/rand"
	"math"
	"testing"
	"time"
)

func TestPermitUsesV3DomainAndBindsStagedManifest(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	permit := testPermit(now)
	if err := SignPermit(&permit, private); err != nil {
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
	if err := VerifyPermit(decoded, permitAuthorityStub{key: public}, now); err != nil {
		t.Fatal(err)
	}
	changed := decoded
	changed.StagedManifestCommitment = testHash(99)
	if err := VerifyPermit(changed, permitAuthorityStub{key: public}, now); err == nil {
		t.Fatal("changed staged commitment accepted")
	}
}

func TestPermitRejectsInvalidHolderOperationAndAttempt(t *testing.T) {
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	for _, operation := range []uint64{permitOperationSourceInit, permitOperationSourceUpload, permitOperationOffer, permitOperationCancel} {
		p := testPermit(now)
		p.Operation = operation
		p.HolderRole, p.HolderDeviceID, p.HolderGeneration = permitHolderRecipient, p.RecipientDeviceID, p.RecipientGeneration
		if _, err := EncodePermit(p); err == nil {
			t.Fatalf("recipient permitted operation %d", operation)
		}
	}
	for _, operation := range []uint64{permitOperationAccept, permitOperationBegin, permitOperationDownload, permitOperationComplete} {
		p := testPermit(now)
		p.Operation = operation
		if _, err := EncodePermit(p); err == nil {
			t.Fatalf("sender permitted operation %d", operation)
		}
		p.HolderRole, p.HolderDeviceID, p.HolderGeneration = permitHolderRecipient, p.RecipientDeviceID, p.RecipientGeneration
		p.AttemptGeneration = 0
		if operation != permitOperationAccept {
			if _, err := EncodePermit(p); err == nil {
				t.Fatalf("zero attempt accepted for operation %d", operation)
			}
		}
	}
	p := testPermit(now)
	p.MaxBytes = maxPermitCiphertextBytes + 1
	if _, err := EncodePermit(p); err == nil {
		t.Fatal("oversized ciphertext quota accepted")
	}
	p = testPermit(now)
	p.IssuedAt, p.ExpiresAt = math.MaxInt64+1, math.MaxInt64+2
	if _, err := EncodePermit(p); err == nil {
		t.Fatal("unrepresentable permit timestamp accepted")
	}
}

func TestUnixSecondsRejectsUnrepresentableProtocolTime(t *testing.T) {
	if _, err := unixSeconds(math.MaxInt64 + 1); err == nil {
		t.Fatal("unrepresentable Unix seconds accepted")
	}
}

func TestPermitExportsOnlyProtocolOperationIdentifiers(t *testing.T) {
	if PermitHolderSender != permitHolderSender || PermitHolderRecipient != permitHolderRecipient || PermitOperationSourceInit != permitOperationSourceInit || PermitOperationSourceUpload != permitOperationSourceUpload || PermitOperationOffer != permitOperationOffer || PermitOperationAccept != permitOperationAccept || PermitOperationBegin != permitOperationBegin || PermitOperationDownload != permitOperationDownload || PermitOperationComplete != permitOperationComplete || PermitOperationCancel != permitOperationCancel {
		t.Fatal("public v3 permit protocol identifiers drifted")
	}
}

func testPermit(now time.Time) Permit {
	return Permit{Audience: testHash(1), Serial: testID(2), IssuerKeyID: testHash(3), HolderDeviceID: testID(4), HolderGeneration: 1, HolderRole: permitHolderSender, TransferID: testID(5), ConversationID: testID(6), SenderDeviceID: testID(4), SenderGeneration: 1, RecipientDeviceID: testID(7), RecipientGeneration: 1, Operation: permitOperationSourceInit, DirectoryHead: testHash(8), MembershipCommitment: testHash(9), RevocationEpoch: 1, IssuedAt: uint64(now.Unix()), ExpiresAt: uint64(now.Add(30 * time.Second).Unix()), MaxBytes: maxPermitCiphertextBytes, MaxChunks: 4096, MaxOperations: 1, StagedManifestCommitment: testHash(10)}
}

type permitAuthorityStub struct{ key ed25519.PublicKey }

func (s permitAuthorityStub) ValidatePermitAuthority(Permit, time.Time) (ed25519.PublicKey, error) {
	return s.key, nil
}
