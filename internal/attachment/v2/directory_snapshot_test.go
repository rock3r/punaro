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
	manifest.RevocationEpoch = 3
	manifest.ExpiresAt = testUnix(t, clock.Add(10*time.Minute))
	if _, err := resolver.ValidateManifestAuthority(manifest, clock); err == nil {
		t.Fatal("v2 strict manifest validation accepted a manifest beyond its directory head")
	}
	if _, err := resolver.ValidateV3ManifestAdmissionAuthority(manifest, clock); err != nil {
		t.Fatalf("v3 strict admission rejected exact ten-minute manifest: %v", err)
	}
	manifest.IssuedAt = testUnix(t, clock.Add(60*time.Second))
	if _, err := resolver.ValidateV3ManifestAdmissionAuthority(manifest, clock); err != nil {
		t.Fatalf("v3 admission rejected bounded future clock skew: %v", err)
	}
	manifest.IssuedAt = testUnix(t, clock.Add(61*time.Second))
	if _, err := resolver.ValidateV3ManifestAdmissionAuthority(manifest, clock); err == nil {
		t.Fatal("v3 admission accepted excessive future clock skew")
	}
	manifest.IssuedAt = testUnix(t, clock.Add(-time.Second))
	admissionHead := manifest.DirectoryHead
	manifest.DirectoryHead = directoryBytes32(99)
	if _, err := resolver.ValidateV3ManifestAdmissionAuthority(manifest, clock); err == nil {
		t.Fatal("v3 strict admission accepted a different directory head")
	}
	manifest.DirectoryHead, manifest.RevocationEpoch = admissionHead, 2
	if _, err := resolver.ValidateV3ManifestAdmissionAuthority(manifest, clock); err == nil {
		t.Fatal("v3 strict admission accepted a different revocation epoch")
	}

	futureHead := head
	futureHead.IssuedAt = testUnix(t, clock.Add(60*time.Second))
	futureHead.ExpiresAt = testUnix(t, clock.Add(5*time.Minute))
	futureHead = signedDirectoryHead(t, rootPrivate, futureHead)
	futureRaw, err := EncodeDirectoryHead(futureHead)
	if err != nil {
		t.Fatal(err)
	}
	futureResolver, err := NewDirectorySnapshotResolver(futureRaw, DirectoryTrust{Audience: audience, RootKeyID: rootID, RootPublicKey: rootPublic, Checkpoints: &memoryCheckpointStore{checkpoints: make(map[[32]byte]DirectoryCheckpoint)}}, clock, nil, entries)
	if err != nil {
		t.Fatalf("future-skew directory resolver: %v", err)
	}
	if _, _, err := futureResolver.CurrentRecipientHPKEKey(bytes16(5), 2); err != nil {
		t.Fatalf("bounded future-skew directory head was not usable: %v", err)
	}
}

func TestDirectorySnapshotResolverResolvesOnlyExactCurrentTransferBinding(t *testing.T) {
	t.Parallel()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now().UTC().Truncate(time.Second)
	audience, rootID := directoryBytes32(31), directoryBytes32(32)
	sender := DirectoryDevice{DeviceID: bytes16(33), Generation: 1, SigningKeyID: directoryBytes32(34), SigningPublicKey: directoryBytes32(35), HPKEKeyID: directoryBytes32(36), HPKEPublicKey: directoryBytes32(37)}
	recipient := DirectoryDevice{DeviceID: bytes16(38), Generation: 1, SigningKeyID: directoryBytes32(39), SigningPublicKey: directoryBytes32(40), HPKEKeyID: directoryBytes32(41), HPKEPublicKey: directoryBytes32(42)}
	membership := DirectoryMembership{ConversationID: bytes16(43), SenderDeviceID: sender.DeviceID, SenderGeneration: sender.Generation, RecipientDeviceID: recipient.DeviceID, RecipientGeneration: recipient.Generation, Commitment: directoryBytes32(44)}
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
	resolver, err := NewDirectorySnapshotResolver(raw, DirectoryTrust{Audience: audience, RootKeyID: rootID, RootPublicKey: rootPublic, Checkpoints: &memoryCheckpointStore{checkpoints: make(map[[32]byte]DirectoryCheckpoint)}}, clock, nil, entries)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := resolver.ResolveTransferBinding(membership.ConversationID, sender.DeviceID, sender.Generation, recipient.DeviceID, recipient.Generation, membership.Commitment, clock)
	if err != nil || binding.Sender != sender || binding.Recipient != recipient || binding.Membership != membership || binding.Permit.Audience != audience || binding.Permit.RevocationEpoch != 1 {
		t.Fatalf("binding=%+v err=%v", binding, err)
	}
	if _, err := resolver.ResolveTransferBinding(membership.ConversationID, sender.DeviceID, sender.Generation, recipient.DeviceID, recipient.Generation, directoryBytes32(45), clock); err == nil {
		t.Fatal("transfer binding accepted a mismatched membership commitment")
	}
	resolver.now = func() time.Time { return clock.Add(21 * time.Second) }
	if _, err := resolver.ResolveTransferBinding(membership.ConversationID, sender.DeviceID, sender.Generation, recipient.DeviceID, recipient.Generation, membership.Commitment, clock.Add(21*time.Second)); err == nil {
		t.Fatal("transfer binding accepted a stale directory")
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
	binding, err := resolver.CurrentPermitBinding(clock)
	if err != nil || binding.Audience != audience || binding.RevocationEpoch != head.RevocationEpoch || binding.ExpiresAt != head.ExpiresAt || isZero32(binding.DirectoryHead) {
		t.Fatalf("binding=%+v err=%v", binding, err)
	}
	resolver.now = func() time.Time { return clock.Add(21 * time.Second) }
	if _, err := resolver.CurrentPermitIssuerKey(issuerID); err == nil {
		t.Fatal("stale permit issuer was accepted")
	}
}

func TestDirectorySnapshotResolverRequiresExactActivePermitMembership(t *testing.T) {
	t.Parallel()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerPublic, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	senderPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipientPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now().UTC().Truncate(time.Second)
	audience, rootID, issuerID := directoryBytes32(1), directoryBytes32(2), directoryBytes32(3)
	sender := DirectoryDevice{DeviceID: bytes16(4), Generation: 1, SigningKeyID: directoryBytes32(10), SigningPublicKey: [32]byte(senderPublic), HPKEKeyID: directoryBytes32(11), HPKEPublicKey: directoryBytes32(12)}
	recipient := DirectoryDevice{DeviceID: bytes16(5), Generation: 2, SigningKeyID: directoryBytes32(13), SigningPublicKey: [32]byte(recipientPublic), HPKEKeyID: directoryBytes32(14), HPKEPublicKey: directoryBytes32(15)}
	membership := DirectoryMembership{ConversationID: bytes16(6), SenderDeviceID: sender.DeviceID, SenderGeneration: sender.Generation, RecipientDeviceID: recipient.DeviceID, RecipientGeneration: recipient.Generation, Commitment: directoryBytes32(7)}
	entries := []DirectoryEntry{{Device: &sender}, {Device: &recipient}, {Membership: &membership}, {Issuer: &DirectoryPermitIssuer{KeyID: issuerID, PublicKey: [32]byte(issuerPublic)}}}
	leaves, err := DirectoryEntryHashes(entries)
	if err != nil {
		t.Fatal(err)
	}
	head := signedDirectoryHead(t, rootPrivate, DirectoryHead{Audience: audience, RootKeyID: rootID, TreeSize: uint64(len(entries)), TreeRoot: directoryMerkleRoot(leaves), Sequence: 1, IssuedAt: testUnix(t, clock.Add(-time.Second)), ExpiresAt: testUnix(t, clock.Add(20*time.Second)), RevocationEpoch: 3})
	raw, err := EncodeDirectoryHead(head)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewDirectorySnapshotResolver(raw, DirectoryTrust{Audience: audience, RootKeyID: rootID, RootPublicKey: rootPublic, Checkpoints: &memoryCheckpointStore{checkpoints: make(map[[32]byte]DirectoryCheckpoint)}}, clock, nil, entries)
	if err != nil {
		t.Fatal(err)
	}
	headCommitment, err := directoryHeadCommitment(head)
	if err != nil {
		t.Fatal(err)
	}
	permit := samplePermit()
	permit.Audience, permit.IssuerKeyID = audience, issuerID
	permit.HolderDeviceID, permit.HolderGeneration, permit.HolderRole = sender.DeviceID, sender.Generation, PermitHolderSender
	permit.ConversationID, permit.SenderDeviceID, permit.SenderGeneration = membership.ConversationID, sender.DeviceID, sender.Generation
	permit.RecipientDeviceID, permit.RecipientGeneration = recipient.DeviceID, recipient.Generation
	permit.DirectoryHead, permit.MembershipCommitment, permit.RevocationEpoch = headCommitment, membership.Commitment, head.RevocationEpoch
	permit.IssuedAt, permit.ExpiresAt = testUnix(t, clock.Add(-time.Second)), testUnix(t, clock.Add(10*time.Second))
	if err := SignPermit(&permit, issuerPrivate); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPermit(permit, resolver, clock); err != nil {
		t.Fatal(err)
	}
	unknownRole := PermitDirectoryBinding{Audience: permit.Audience, IssuerKeyID: permit.IssuerKeyID, HolderDeviceID: permit.HolderDeviceID, HolderGeneration: permit.HolderGeneration, HolderRole: 99, ConversationID: permit.ConversationID, SenderDeviceID: permit.SenderDeviceID, SenderGeneration: permit.SenderGeneration, RecipientDeviceID: permit.RecipientDeviceID, RecipientGeneration: permit.RecipientGeneration, DirectoryHead: permit.DirectoryHead, MembershipCommitment: permit.MembershipCommitment, RevocationEpoch: permit.RevocationEpoch, ExpiresAt: permit.ExpiresAt}
	if _, err := resolver.ValidatePermitDirectoryBinding(unknownRole, clock); err == nil {
		t.Fatal("unknown version-neutral permit holder role was accepted")
	}
	mismatch := permit
	mismatch.MembershipCommitment = directoryBytes32(99)
	if err := SignPermit(&mismatch, issuerPrivate); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPermit(mismatch, resolver, clock); err == nil {
		t.Fatal("permit with mismatched membership was accepted")
	}
	tooLong := permit
	tooLong.ExpiresAt = testUnix(t, clock.Add(21*time.Second))
	if err := SignPermit(&tooLong, issuerPrivate); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPermit(tooLong, resolver, clock); err == nil {
		t.Fatal("permit exceeding its directory head lifetime was accepted")
	}
}
