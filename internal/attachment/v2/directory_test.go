package v2

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"
)

type memoryCheckpointStore struct {
	checkpoints map[[32]byte]DirectoryCheckpoint
	frozen      map[[32]byte]bool
}

func TestSQLiteCheckpointStoreSurvivesRestartAndFreezesEquivocation(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "directory.db")
	store, err := OpenSQLiteCheckpointStore(path)
	if err != nil {
		t.Fatal(err)
	}
	audience := directoryBytes32(1)
	want := DirectoryCheckpoint{Sequence: 7, TreeSize: 3, TreeRoot: directoryBytes32(2), RevocationEpoch: 4}
	if err := store.SaveCheckpoint(audience, want); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenSQLiteCheckpointStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	got, found, err := store.LoadCheckpoint(audience)
	if err != nil || !found || got != want {
		t.Fatalf("checkpoint=%#v found=%v err=%v", got, found, err)
	}
	if err := store.FreezeAudience(audience, []byte("evidence")); err != nil {
		t.Fatal(err)
	}
	frozen, err := store.AudienceFrozen(audience)
	if err != nil || !frozen {
		t.Fatalf("frozen=%v err=%v", frozen, err)
	}
}

func (s *memoryCheckpointStore) LoadCheckpoint(audience [32]byte) (DirectoryCheckpoint, bool, error) {
	checkpoint, found := s.checkpoints[audience]
	return checkpoint, found, nil
}

func (s *memoryCheckpointStore) SaveCheckpoint(audience [32]byte, checkpoint DirectoryCheckpoint) error {
	s.checkpoints[audience] = checkpoint
	return nil
}

func (s *memoryCheckpointStore) FreezeAudience(audience [32]byte, _ []byte) error {
	if s.frozen == nil {
		s.frozen = make(map[[32]byte]bool)
	}
	s.frozen[audience] = true
	return nil
}

func (s *memoryCheckpointStore) AudienceFrozen(audience [32]byte) (bool, error) {
	return s.frozen[audience], nil
}

func TestVerifyAndAdvanceDirectoryHeadRequiresFreshSignedConsistentAdvance(t *testing.T) {
	t.Parallel()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(1_784_000_000, 0).UTC()
	audience := directoryBytes32(1)
	rootID := directoryBytes32(2)
	store := &memoryCheckpointStore{checkpoints: make(map[[32]byte]DirectoryCheckpoint)}
	firstLeaves := [][32]byte{directoryBytes32(3)}
	first := signedDirectoryHead(t, rootPrivate, DirectoryHead{Audience: audience, RootKeyID: rootID, TreeSize: 1, TreeRoot: directoryMerkleRoot(firstLeaves), Sequence: 1, IssuedAt: 1_783_999_999, ExpiresAt: 1_784_000_020, RevocationEpoch: 4})
	firstRaw, err := EncodeDirectoryHead(first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAndAdvanceDirectoryHead(firstRaw, DirectoryTrust{Audience: audience, RootKeyID: rootID, RootPublicKey: rootPublic, Checkpoints: store}, clock, nil); err != nil {
		t.Fatal(err)
	}
	secondLeaves := append(append([][32]byte(nil), firstLeaves...), directoryBytes32(4))
	second := signedDirectoryHead(t, rootPrivate, DirectoryHead{Audience: audience, RootKeyID: rootID, TreeSize: 2, TreeRoot: directoryMerkleRoot(secondLeaves), Sequence: 2, IssuedAt: 1_784_000_000, ExpiresAt: 1_784_000_020, RevocationEpoch: 5})
	secondRaw, err := EncodeDirectoryHead(second)
	if err != nil {
		t.Fatal(err)
	}
	proof := &FullConsistencyProof{LeafHashes: secondLeaves}
	if _, err := VerifyAndAdvanceDirectoryHead(secondRaw, DirectoryTrust{Audience: audience, RootKeyID: rootID, RootPublicKey: rootPublic, Checkpoints: store}, clock, proof); err != nil {
		t.Fatal(err)
	}
	checkpoint, found, err := store.LoadCheckpoint(audience)
	if err != nil || !found || checkpoint.Sequence != 2 || checkpoint.TreeRoot != second.TreeRoot || checkpoint.RevocationEpoch != 5 {
		t.Fatalf("checkpoint=%#v found=%v err=%v", checkpoint, found, err)
	}
}

func TestVerifyAndAdvanceDirectoryHeadRejectsEquivocationAndMissingProof(t *testing.T) {
	t.Parallel()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(1_784_000_000, 0).UTC()
	audience := directoryBytes32(1)
	rootID := directoryBytes32(2)
	store := &memoryCheckpointStore{checkpoints: map[[32]byte]DirectoryCheckpoint{audience: {Sequence: 4, TreeSize: 1, TreeRoot: directoryMerkleRoot([][32]byte{directoryBytes32(3)}), RevocationEpoch: 7}}}
	trust := DirectoryTrust{Audience: audience, RootKeyID: rootID, RootPublicKey: rootPublic, Checkpoints: store}
	head := signedDirectoryHead(t, rootPrivate, DirectoryHead{Audience: audience, RootKeyID: rootID, TreeSize: 2, TreeRoot: directoryMerkleRoot([][32]byte{directoryBytes32(3), directoryBytes32(4)}), Sequence: 5, IssuedAt: 1_784_000_000, ExpiresAt: 1_784_000_020, RevocationEpoch: 7})
	raw, err := EncodeDirectoryHead(head)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAndAdvanceDirectoryHead(raw, trust, clock, nil); err == nil {
		t.Fatal("newer head without a consistency proof was accepted")
	}
	equivocating := signedDirectoryHead(t, rootPrivate, DirectoryHead{Audience: audience, RootKeyID: rootID, TreeSize: 1, TreeRoot: directoryBytes32(9), Sequence: 4, IssuedAt: 1_784_000_000, ExpiresAt: 1_784_000_020, RevocationEpoch: 7})
	raw, err = EncodeDirectoryHead(equivocating)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAndAdvanceDirectoryHead(raw, trust, clock, nil); err == nil {
		t.Fatal("same-sequence equivocation was accepted")
	}
}

func signedDirectoryHead(t *testing.T, private ed25519.PrivateKey, head DirectoryHead) DirectoryHead {
	t.Helper()
	if err := SignDirectoryHead(&head, private); err != nil {
		t.Fatal(err)
	}
	return head
}

func directoryBytes32(value byte) [32]byte {
	var result [32]byte
	result[0] = value
	return result
}
