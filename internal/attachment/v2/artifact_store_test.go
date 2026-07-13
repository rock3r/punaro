package v2

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSQLiteSourceReservationStoreDurablyRejectsKeyAndNonceReuseAtomically(t *testing.T) {
	t.Parallel()
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "reservations.db")
	store, err := OpenSQLiteSourceReservationStore(path)
	if err != nil {
		t.Fatal(err)
	}
	keyA, keyB := directoryBytes32(1), directoryBytes32(2)
	nonceA := NonceReservation{TransferID: bytes16(3), ManifestCommitment: directoryBytes32(4), ChunkIndex: 0}
	if err := store.Reserve(keyA, directoryBytes32(9), []NonceReservation{nonceA}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenSQLiteSourceReservationStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Reserve(keyA, directoryBytes32(10), []NonceReservation{{TransferID: bytes16(9), ManifestCommitment: directoryBytes32(8), ChunkIndex: 0}}); err == nil {
		t.Fatal("reused file-key commitment was accepted after restart")
	}
	nonceB := NonceReservation{TransferID: bytes16(6), ManifestCommitment: directoryBytes32(7), ChunkIndex: 0}
	if err := store.Reserve(keyB, directoryBytes32(11), []NonceReservation{nonceA, nonceB}); err == nil {
		t.Fatal("nonce collision was accepted")
	}
	if err := store.Reserve(keyB, directoryBytes32(11), []NonceReservation{nonceB}); err != nil {
		t.Fatalf("failed reservation left a partial key/nonce record: %v", err)
	}
}
