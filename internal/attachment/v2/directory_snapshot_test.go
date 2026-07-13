package v2

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestDirectorySnapshotResolverBindsManifestAndRecipientKeysToFreshMembership(t *testing.T) {
	t.Parallel()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	senderPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipientPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(1_784_000_000, 0).UTC()
	audience, rootID := directoryBytes32(1), directoryBytes32(2)
	entries := []DirectoryEntry{
		{Device: &DirectoryDevice{DeviceID: bytes16(4), Generation: 1, SigningKeyID: directoryBytes32(10), SigningPublicKey: [32]byte(senderPublic), HPKEKeyID: directoryBytes32(11), HPKEPublicKey: [32]byte(senderPublic)}},
		{Device: &DirectoryDevice{DeviceID: bytes16(5), Generation: 2, SigningKeyID: directoryBytes32(12), SigningPublicKey: directoryBytes32(13), HPKEKeyID: directoryBytes32(14), HPKEPublicKey: [32]byte(recipientPrivate.PublicKey().Bytes())}},
		{Membership: &DirectoryMembership{ConversationID: bytes16(3), SenderDeviceID: bytes16(4), SenderGeneration: 1, RecipientDeviceID: bytes16(5), RecipientGeneration: 2, Commitment: directoryBytes32(7)}},
	}
	leaves, err := DirectoryEntryHashes(entries)
	if err != nil {
		t.Fatal(err)
	}
	head := signedDirectoryHead(t, rootPrivate, DirectoryHead{Audience: audience, RootKeyID: rootID, TreeSize: 3, TreeRoot: directoryMerkleRoot(leaves), Sequence: 1, IssuedAt: 1_783_999_999, ExpiresAt: 1_784_000_020, RevocationEpoch: 3})
	raw, err := EncodeDirectoryHead(head)
	if err != nil {
		t.Fatal(err)
	}
	store := &memoryCheckpointStore{checkpoints: make(map[[32]byte]DirectoryCheckpoint)}
	resolver, err := NewDirectorySnapshotResolver(raw, DirectoryTrust{Audience: audience, RootKeyID: rootID, RootPublicKey: rootPublic, Checkpoints: store}, clock, nil, entries)
	if err != nil {
		t.Fatal(err)
	}
	manifest := sampleManifest()
	manifest.Audience, manifest.SenderDeviceID, manifest.SenderGeneration = audience, bytes16(4), 1
	manifest.RecipientDeviceID, manifest.RecipientGeneration = bytes16(5), 2
	manifest.DirectoryHead, err = directoryHeadCommitment(head)
	if err != nil {
		t.Fatal(err)
	}
	manifest.MembershipCommitment, manifest.RevocationEpoch, manifest.SignerKeyID = directoryBytes32(7), 3, directoryBytes32(10)
	manifest.IssuedAt, manifest.ExpiresAt = 1_783_999_999, 1_784_000_020
	resolved, err := resolver.ValidateManifestAuthority(manifest, clock)
	if err != nil || string(resolved) != string(senderPublic) {
		t.Fatalf("signer=%x err=%v", resolved, err)
	}
	keyID, recipient, err := resolver.CurrentRecipientHPKEKey(bytes16(5), 2)
	if err != nil || keyID != directoryBytes32(14) || string(recipient.Bytes()) != string(recipientPrivate.PublicKey().Bytes()) {
		t.Fatalf("recipient key=%v id=%x err=%v", recipient, keyID, err)
	}
	manifest.RevocationEpoch = 2
	if _, err := resolver.ValidateManifestAuthority(manifest, clock); err == nil {
		t.Fatal("manifest with stale revocation epoch was accepted")
	}
}

func TestDirectorySnapshotResolverRejectsRevokedAndReboundDeviceGenerations(t *testing.T) {
	t.Parallel()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(1_784_000_000, 0).UTC()
	audience, rootID := directoryBytes32(1), directoryBytes32(2)
	device := DirectoryDevice{DeviceID: bytes16(4), Generation: 1, SigningKeyID: directoryBytes32(10), SigningPublicKey: directoryBytes32(11), HPKEKeyID: directoryBytes32(12), HPKEPublicKey: directoryBytes32(13)}
	trust := DirectoryTrust{Audience: audience, RootKeyID: rootID, RootPublicKey: rootPublic, Checkpoints: &memoryCheckpointStore{checkpoints: make(map[[32]byte]DirectoryCheckpoint)}}

	revoked := device
	revoked.Revoked = true
	revokedEntries := []DirectoryEntry{{Device: &revoked}}
	revokedLeaves, err := DirectoryEntryHashes(revokedEntries)
	if err != nil {
		t.Fatal(err)
	}
	revokedHead := signedDirectoryHead(t, rootPrivate, DirectoryHead{Audience: audience, RootKeyID: rootID, TreeSize: 1, TreeRoot: directoryMerkleRoot(revokedLeaves), Sequence: 1, IssuedAt: 1_783_999_999, ExpiresAt: 1_784_000_020, RevocationEpoch: 3})
	revokedRaw, err := EncodeDirectoryHead(revokedHead)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewDirectorySnapshotResolver(revokedRaw, trust, clock, nil, revokedEntries); err == nil {
		t.Fatal("snapshot with an initially revoked device was accepted")
	}
	if _, found, err := trust.Checkpoints.LoadCheckpoint(audience); err != nil || found {
		t.Fatalf("invalid snapshot changed checkpoint: found=%v err=%v", found, err)
	}

	rebound := device
	rebound.SigningPublicKey = directoryBytes32(99)
	reboundEntries := []DirectoryEntry{{Device: &device}, {Device: &rebound}}
	reboundLeaves, err := DirectoryEntryHashes(reboundEntries)
	if err != nil {
		t.Fatal(err)
	}
	reboundHead := signedDirectoryHead(t, rootPrivate, DirectoryHead{Audience: audience, RootKeyID: rootID, TreeSize: 2, TreeRoot: directoryMerkleRoot(reboundLeaves), Sequence: 2, IssuedAt: 1_783_999_999, ExpiresAt: 1_784_000_020, RevocationEpoch: 3})
	reboundRaw, err := EncodeDirectoryHead(reboundHead)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewDirectorySnapshotResolver(reboundRaw, trust, clock, &FullConsistencyProof{LeafHashes: reboundLeaves}, reboundEntries); err == nil {
		t.Fatal("snapshot that rebounded a device generation was accepted")
	}
}
