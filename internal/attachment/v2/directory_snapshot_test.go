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
	clock := time.Now().UTC().Truncate(time.Second)
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
	head := signedDirectoryHead(t, rootPrivate, DirectoryHead{Audience: audience, RootKeyID: rootID, TreeSize: 3, TreeRoot: directoryMerkleRoot(leaves), Sequence: 1, IssuedAt: testUnix(t, clock.Add(-time.Second)), ExpiresAt: testUnix(t, clock.Add(20*time.Second)), RevocationEpoch: 3})
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
	manifest.IssuedAt, manifest.ExpiresAt = testUnix(t, clock.Add(-time.Second)), testUnix(t, clock.Add(20*time.Second))
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

func TestDirectorySnapshotResolverCopiesInputAndRejectsSupersededOrStaleAuthority(t *testing.T) {
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
	clock := time.Now().UTC().Truncate(time.Second)
	audience, rootID := directoryBytes32(1), directoryBytes32(2)
	sender := DirectoryDevice{DeviceID: bytes16(4), Generation: 1, SigningKeyID: directoryBytes32(10), SigningPublicKey: [32]byte(senderPublic), HPKEKeyID: directoryBytes32(11), HPKEPublicKey: directoryBytes32(12)}
	recipient := DirectoryDevice{DeviceID: bytes16(5), Generation: 1, SigningKeyID: directoryBytes32(13), SigningPublicKey: directoryBytes32(14), HPKEKeyID: directoryBytes32(15), HPKEPublicKey: [32]byte(recipientPrivate.PublicKey().Bytes())}
	membership := DirectoryMembership{ConversationID: bytes16(3), SenderDeviceID: sender.DeviceID, SenderGeneration: 1, RecipientDeviceID: recipient.DeviceID, RecipientGeneration: 1, Commitment: directoryBytes32(7)}
	entries := []DirectoryEntry{{Device: &sender}, {Device: &recipient}, {Membership: &membership}}
	leaves, err := DirectoryEntryHashes(entries)
	if err != nil {
		t.Fatal(err)
	}
	head := signedDirectoryHead(t, rootPrivate, DirectoryHead{Audience: audience, RootKeyID: rootID, TreeSize: uint64(len(entries)), TreeRoot: directoryMerkleRoot(leaves), Sequence: 1, IssuedAt: testUnix(t, clock.Add(-time.Second)), ExpiresAt: testUnix(t, clock.Add(20*time.Second)), RevocationEpoch: 1})
	raw, err := EncodeDirectoryHead(head)
	if err != nil {
		t.Fatal(err)
	}
	store := &memoryCheckpointStore{checkpoints: make(map[[32]byte]DirectoryCheckpoint)}
	resolver, err := NewDirectorySnapshotResolver(raw, DirectoryTrust{Audience: audience, RootKeyID: rootID, RootPublicKey: rootPublic, Checkpoints: store}, clock, nil, entries)
	if err != nil {
		t.Fatal(err)
	}
	sender.SigningPublicKey = directoryBytes32(99)
	membership.Commitment = directoryBytes32(98)
	manifest := sampleManifest()
	manifest.Audience, manifest.ConversationID = audience, bytes16(3)
	manifest.SenderDeviceID, manifest.SenderGeneration = sender.DeviceID, 1
	manifest.RecipientDeviceID, manifest.RecipientGeneration = recipient.DeviceID, 1
	manifest.SignerKeyID, manifest.MembershipCommitment = directoryBytes32(10), directoryBytes32(7)
	manifest.RevocationEpoch, manifest.IssuedAt, manifest.ExpiresAt = 1, testUnix(t, clock.Add(-time.Second)), testUnix(t, clock.Add(20*time.Second))
	manifest.DirectoryHead, err = directoryHeadCommitment(head)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolver.ValidateManifestAuthority(manifest, clock)
	if err != nil || string(resolved) != string(senderPublic) {
		t.Fatalf("mutated input affected resolved signer: %x err=%v", resolved, err)
	}
	resolver.now = func() time.Time { return clock.Add(21 * time.Second) }
	if _, _, err := resolver.CurrentRecipientHPKEKey(recipient.DeviceID, 1); err == nil {
		t.Fatal("expired directory resolver returned a recipient key")
	}
	store.checkpoints[audience] = DirectoryCheckpoint{Sequence: 2, TreeSize: head.TreeSize, TreeRoot: head.TreeRoot, RevocationEpoch: 2}
	if _, err := resolver.ValidateManifestAuthority(manifest, clock); err == nil {
		t.Fatal("superseded directory resolver authorized a manifest")
	}
}

func testUnix(t *testing.T, value time.Time) uint64 {
	t.Helper()
	seconds := value.Unix()
	if seconds < 0 {
		t.Fatal("test time precedes Unix epoch")
	}
	return uint64(seconds) // #nosec G115 -- the negative Unix-time case returns above.
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

func TestDirectoryEntryHistoryMakesMembershipTombstonesAndOlderGenerationsInactive(t *testing.T) {
	t.Parallel()
	deviceV1 := DirectoryDevice{DeviceID: bytes16(4), Generation: 1, SigningKeyID: directoryBytes32(10), SigningPublicKey: directoryBytes32(11), HPKEKeyID: directoryBytes32(12), HPKEPublicKey: directoryBytes32(13)}
	deviceV2 := deviceV1
	deviceV2.Generation = 2
	deviceV2.SigningKeyID = directoryBytes32(14)
	deviceV2.SigningPublicKey = directoryBytes32(15)
	deviceV2.HPKEKeyID = directoryBytes32(16)
	deviceV2.HPKEPublicKey = directoryBytes32(17)
	membership := DirectoryMembership{ConversationID: bytes16(3), SenderDeviceID: bytes16(4), SenderGeneration: 1, RecipientDeviceID: bytes16(5), RecipientGeneration: 1, Commitment: directoryBytes32(7)}
	tombstone := membership
	tombstone.Revoked = true
	devices, latest, memberships, _, err := validateDirectoryEntryHistory([]DirectoryEntry{{Device: &deviceV1}, {Membership: &membership}, {Membership: &tombstone}, {Device: &deviceV2}})
	if err != nil {
		t.Fatal(err)
	}
	if latest[deviceV1.DeviceID] != 2 || devices[directoryDeviceKey{id: deviceV1.DeviceID, generation: 1}].Revoked || !memberships[directoryMembershipKey{conversation: membership.ConversationID, sender: membership.SenderDeviceID, senderGen: membership.SenderGeneration, recipient: membership.RecipientDeviceID, recipientGen: membership.RecipientGeneration, commitment: membership.Commitment}].Revoked {
		t.Fatal("historic device generation or membership remained active")
	}
}

func TestDirectorySnapshotResolverResolvesOnlyFreshActivePermitIssuers(t *testing.T) {
	t.Parallel()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now().UTC().Truncate(time.Second)
	audience, rootID, issuerID := directoryBytes32(1), directoryBytes32(2), directoryBytes32(3)
	entries := []DirectoryEntry{{Issuer: &DirectoryPermitIssuer{KeyID: issuerID, PublicKey: [32]byte(issuerPublic)}}}
	leaves, err := DirectoryEntryHashes(entries)
	if err != nil {
		t.Fatal(err)
	}
	head := signedDirectoryHead(t, rootPrivate, DirectoryHead{Audience: audience, RootKeyID: rootID, TreeSize: 1, TreeRoot: directoryMerkleRoot(leaves), Sequence: 1, IssuedAt: testUnix(t, clock.Add(-time.Second)), ExpiresAt: testUnix(t, clock.Add(20*time.Second))})
	raw, err := EncodeDirectoryHead(head)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewDirectorySnapshotResolver(raw, DirectoryTrust{Audience: audience, RootKeyID: rootID, RootPublicKey: rootPublic, Checkpoints: &memoryCheckpointStore{checkpoints: make(map[[32]byte]DirectoryCheckpoint)}}, clock, nil, entries)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolver.CurrentPermitIssuerKey(issuerID)
	if err != nil || string(resolved) != string(issuerPublic) {
		t.Fatalf("issuer=%x err=%v", resolved, err)
	}
	resolver.now = func() time.Time { return clock.Add(21 * time.Second) }
	if _, err := resolver.CurrentPermitIssuerKey(issuerID); err == nil {
		t.Fatal("stale permit issuer was accepted")
	}
}
