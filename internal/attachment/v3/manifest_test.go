package v3

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func TestDecodeAndVerifySourceInitDerivesImmutableSource(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	manifest := testManifest(now)
	if err := SignManifest(&manifest, private); err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := DecodeAndVerifySourceInit(raw, manifestAuthorityStub{public: public}, now)
	if err != nil {
		t.Fatal(err)
	}
	if verified.TransferID() != manifest.TransferID || verified.ChunkSize() != manifest.ChunkSize || verified.ChunkCount() != manifest.ChunkCount || verified.PlaintextSize() != manifest.PlaintextSize {
		t.Fatal("verified source did not derive manifest geometry")
	}
	if verified.ManifestCommitment() == [32]byte{} {
		t.Fatal("verified source omitted manifest commitment")
	}
	if _, err := DecodeAndVerifySourceInit(raw, manifestAuthorityStub{err: errors.New("revoked")}, now); err == nil {
		t.Fatal("directory failure accepted")
	}
}

func TestDecodeAndVerifySourceInitRejectsFutureOrUnrepresentableTime(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	manifest := testManifest(now.Add(time.Second))
	if err := SignManifest(&manifest, private); err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAndVerifySourceInit(raw, manifestAuthorityStub{public: public}, now); err == nil {
		t.Fatal("future-issued manifest accepted")
	}
	manifest.IssuedAt = ^uint64(0) - 20
	manifest.ExpiresAt = ^uint64(0) - 10
	if err := SignManifest(&manifest, private); err == nil {
		t.Fatal("unrepresentable manifest timestamp accepted for signing")
	}
}

func testManifest(now time.Time) Manifest {
	return Manifest{
		Audience: testHash(1), TransferID: testID(2), ConversationID: testID(3),
		SenderDeviceID: testID(4), SenderGeneration: 1,
		RecipientDeviceID: testID(5), RecipientGeneration: 1,
		DirectoryHead: testHash(6), MembershipCommitment: testHash(7),
		// #nosec G115 -- callers supply fixed positive test clocks.
		RevocationEpoch: 1, IssuedAt: uint64(now.Unix()), ExpiresAt: uint64(now.Add(30 * time.Second).Unix()),
		ContentSalt: testHash(8), PlaintextCommitment: testHash(9),
		ChunkSize: 4, ChunkCount: 2, PlaintextSize: 5, SignerKeyID: testHash(10),
	}
}

type manifestAuthorityStub struct {
	public ed25519.PublicKey
	err    error
}

func (s manifestAuthorityStub) ValidateManifestAuthority(Manifest, time.Time) (ed25519.PublicKey, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.public, nil
}
