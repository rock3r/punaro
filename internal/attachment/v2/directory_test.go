package v2

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type memoryCheckpointStore struct {
	mu          sync.Mutex
	checkpoints map[[32]byte]DirectoryCheckpoint
	frozen      map[[32]byte]bool
}

func TestSQLiteCheckpointStoreSurvivesRestartAndFreezesEquivocation(t *testing.T) {
	t.Parallel()
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "directory.db")
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

func TestSQLiteCheckpointStoreRejectsInsecureParentAndCreatesPrivateDatabase(t *testing.T) {
	t.Parallel()
	insecure := filepath.Join(t.TempDir(), "insecure")
	if err := os.Mkdir(insecure, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(insecure, 0o755); err != nil { // #nosec G302 -- this test intentionally creates an insecure parent.
		t.Fatal(err)
	}
	if _, err := OpenSQLiteCheckpointStore(filepath.Join(insecure, "directory.db")); err == nil {
		t.Fatal("insecure checkpoint parent was accepted")
	}
	private := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(private, "directory.db")
	store, err := OpenSQLiteCheckpointStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("database mode=%#o err=%v", info.Mode().Perm(), err)
	}
}

func (s *memoryCheckpointStore) LoadCheckpoint(audience [32]byte) (DirectoryCheckpoint, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	checkpoint, found := s.checkpoints[audience]
	return checkpoint, found, nil
}

func (s *memoryCheckpointStore) SaveCheckpoint(audience [32]byte, checkpoint DirectoryCheckpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checkpoints[audience] = checkpoint
	return nil
}

func (s *memoryCheckpointStore) FreezeAudience(audience [32]byte, _ []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.frozen == nil {
		s.frozen = make(map[[32]byte]bool)
	}
	s.frozen[audience] = true
	return nil
}

func (s *memoryCheckpointStore) AudienceFrozen(audience [32]byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.frozen[audience], nil
}

func (s *memoryCheckpointStore) Advance(audience [32]byte, next DirectoryCheckpoint, _ []byte, proof *FullConsistencyProof) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, found := s.checkpoints[audience]
	save, freeze, result := advanceCheckpoint(previous, found, s.frozen[audience], next, proof)
	if freeze {
		if s.frozen == nil {
			s.frozen = make(map[[32]byte]bool)
		}
		s.frozen[audience] = true
	}
	if save {
		s.checkpoints[audience] = next
	}
	return result
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
	if _, err := verifyAndAdvanceDirectoryHead(firstRaw, DirectoryTrust{Audience: audience, RootKeyID: rootID, RootPublicKey: rootPublic, Checkpoints: store}, clock, nil); err != nil {
		t.Fatal(err)
	}
	secondLeaves := append(append([][32]byte(nil), firstLeaves...), directoryBytes32(4))
	second := signedDirectoryHead(t, rootPrivate, DirectoryHead{Audience: audience, RootKeyID: rootID, TreeSize: 2, TreeRoot: directoryMerkleRoot(secondLeaves), Sequence: 2, IssuedAt: 1_784_000_000, ExpiresAt: 1_784_000_020, RevocationEpoch: 5})
	secondRaw, err := EncodeDirectoryHead(second)
	if err != nil {
		t.Fatal(err)
	}
	proof := &FullConsistencyProof{LeafHashes: secondLeaves}
	if _, err := verifyAndAdvanceDirectoryHead(secondRaw, DirectoryTrust{Audience: audience, RootKeyID: rootID, RootPublicKey: rootPublic, Checkpoints: store}, clock, proof); err != nil {
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
	if _, err := verifyAndAdvanceDirectoryHead(raw, trust, clock, nil); err == nil {
		t.Fatal("newer head without a consistency proof was accepted")
	}
	equivocating := signedDirectoryHead(t, rootPrivate, DirectoryHead{Audience: audience, RootKeyID: rootID, TreeSize: 1, TreeRoot: directoryBytes32(9), Sequence: 4, IssuedAt: 1_784_000_000, ExpiresAt: 1_784_000_020, RevocationEpoch: 7})
	raw, err = EncodeDirectoryHead(equivocating)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyAndAdvanceDirectoryHead(raw, trust, clock, nil); err == nil {
		t.Fatal("same-sequence equivocation was accepted")
	}
	frozen, err := store.AudienceFrozen(audience)
	if err != nil || !frozen {
		t.Fatalf("equivocation did not durably freeze audience: frozen=%v err=%v", frozen, err)
	}
}

func TestVerifyDirectoryHeadAllowsBoundedClockSkewAndPracticalLifetime(t *testing.T) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.July, 17, 12, 0, 0, 0, time.UTC)
	trust := DirectoryTrust{Audience: directoryBytes32(1), RootKeyID: directoryBytes32(2), RootPublicKey: rootPublic, Checkpoints: &memoryCheckpointStore{checkpoints: make(map[[32]byte]DirectoryCheckpoint)}}

	accepted := signedDirectoryHead(t, rootPrivate, DirectoryHead{
		Audience: trust.Audience, RootKeyID: trust.RootKeyID, TreeSize: 1, TreeRoot: directoryBytes32(3), Sequence: 1,
		IssuedAt: testUnix(t, now.Add(60*time.Second)), ExpiresAt: testUnix(t, now.Add(5*time.Minute)),
	})
	raw, err := EncodeDirectoryHead(accepted)
	if err != nil {
		t.Fatalf("encode bounded-skew head: %v", err)
	}
	if _, err := verifyDirectoryHead(raw, trust, now); err != nil {
		t.Fatalf("bounded future clock skew rejected: %v", err)
	}

	rejected := accepted
	rejected.IssuedAt = testUnix(t, now.Add(61*time.Second))
	rejected.ExpiresAt = testUnix(t, now.Add(5*time.Minute+time.Second))
	if err := SignDirectoryHead(&rejected, rootPrivate); err != nil {
		t.Fatal(err)
	}
	raw, err = EncodeDirectoryHead(rejected)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyDirectoryHead(raw, trust, now); err == nil {
		t.Fatal("directory head beyond bounded future clock skew accepted")
	}
}

func TestSQLiteCheckpointStoreConcurrentAdvancesCannotDowngradeCheckpoint(t *testing.T) {
	t.Parallel()
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "directory.db")
	first, err := OpenSQLiteCheckpointStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	second, err := OpenSQLiteCheckpointStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	audience := directoryBytes32(1)
	leaves := [][32]byte{directoryBytes32(3), directoryBytes32(4), directoryBytes32(5)}
	base := DirectoryCheckpoint{Sequence: 1, TreeSize: 1, TreeRoot: directoryMerkleRoot(leaves[:1]), RevocationEpoch: 1}
	if err := first.Advance(audience, base, []byte("head-1"), nil); err != nil {
		t.Fatal(err)
	}
	sequenceTwo := DirectoryCheckpoint{Sequence: 2, TreeSize: 2, TreeRoot: directoryMerkleRoot(leaves[:2]), RevocationEpoch: 1}
	sequenceThree := DirectoryCheckpoint{Sequence: 3, TreeSize: 3, TreeRoot: directoryMerkleRoot(leaves), RevocationEpoch: 1}
	ready := make(chan struct{})
	errs := make(chan error, 2)
	go func() {
		<-ready
		errs <- first.Advance(audience, sequenceTwo, []byte("head-2"), &FullConsistencyProof{LeafHashes: leaves[:2]})
	}()
	go func() {
		<-ready
		errs <- second.Advance(audience, sequenceThree, []byte("head-3"), &FullConsistencyProof{LeafHashes: leaves})
	}()
	close(ready)
	<-errs
	<-errs
	checkpoint, found, err := first.LoadCheckpoint(audience)
	if err != nil || !found || checkpoint != sequenceThree {
		t.Fatalf("concurrent advance checkpoint=%#v found=%v err=%v", checkpoint, found, err)
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
