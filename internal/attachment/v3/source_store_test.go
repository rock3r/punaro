package v3

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestSourceStoreStagesImmutableChunksBeforeReady(t *testing.T) {
	store, err := openSourceStore(privateDatabase(t), defaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	source := verifiedTestSource(t, now, 2, 4, 5)
	if err := store.initialize(context.Background(), source, now); err != nil {
		t.Fatal(err)
	}
	assertTransferStatus(t, store, source.TransferID(), transferSourceUploading)
	if ready, err := store.readyAt(source.TransferID(), now); err != nil || ready {
		t.Fatalf("ready=%v err=%v", ready, err)
	}
	if err := store.upload(context.Background(), source.TransferID(), 0, bytes.Repeat([]byte{1}, 20), now); err != nil {
		t.Fatal(err)
	}
	if err := store.upload(context.Background(), source.TransferID(), 1, bytes.Repeat([]byte{2}, 17), now); err != nil {
		t.Fatal(err)
	}
	if ready, err := store.readyAt(source.TransferID(), now); err != nil || !ready {
		t.Fatalf("ready=%v err=%v", ready, err)
	}
	assertTransferStatus(t, store, source.TransferID(), transferSourceReady)
}

func TestSourceStoreRejectsReplacementAndWrongCiphertextLength(t *testing.T) {
	store, err := openSourceStore(privateDatabase(t), defaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	source := verifiedTestSource(t, now, 1, 4, 4)
	if err := store.initialize(context.Background(), source, now); err != nil {
		t.Fatal(err)
	}
	chunk := bytes.Repeat([]byte{1}, 20)
	if err := store.upload(context.Background(), source.TransferID(), 0, chunk, now); err != nil {
		t.Fatal(err)
	}
	if err := store.upload(context.Background(), source.TransferID(), 0, bytes.Repeat([]byte{2}, 20), now); err == nil {
		t.Fatal("replacement chunk accepted")
	}
	changedManifest := source.manifest
	changedManifest.PlaintextCommitment = testHash(42)
	changed := verifiedSourceForManifest(t, changedManifest, now)
	if err := store.initialize(context.Background(), changed, now); err == nil {
		t.Fatal("replacement source specification accepted")
	}
}

func TestSourceStoreRejectsUnverifiedSource(t *testing.T) {
	store, err := openSourceStore(privateDatabase(t), defaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	if err := store.initialize(context.Background(), VerifiedSource{}, now); err == nil {
		t.Fatal("source init without directory verification accepted")
	}
}

func TestSourceStoreRejectsManifestCommitmentReuse(t *testing.T) {
	store, err := openSourceStore(privateDatabase(t), defaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	first := verifiedTestSource(t, now, 1, 4, 4)
	if err := store.initialize(context.Background(), first, now); err != nil {
		t.Fatal(err)
	}
	second := first
	second.manifest.TransferID = testID(9)
	if err := store.initialize(context.Background(), second, now); err == nil {
		t.Fatal("manifest commitment reuse accepted")
	}
}

func TestSourceStoreReadinessRejectsExpiredOrTamperedChunks(t *testing.T) {
	store, err := openSourceStore(privateDatabase(t), defaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	source := verifiedTestSource(t, now, 1, 4, 4)
	if err := store.initialize(context.Background(), source, now); err != nil {
		t.Fatal(err)
	}
	if err := store.upload(context.Background(), source.TransferID(), 0, bytes.Repeat([]byte{1}, 20), now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), `UPDATE v3_source_chunks SET ciphertext_commitment = zeroblob(32)`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.readyAt(source.TransferID(), now); err == nil {
		t.Fatal("tampered commitment accepted")
	}
	commitment := ciphertextCommitment(bytes.Repeat([]byte{1}, 20))
	if _, err := store.db.ExecContext(context.Background(), `UPDATE v3_source_chunks SET ciphertext_commitment = ?`, commitment[:]); err != nil {
		t.Fatal(err)
	}
	if ready, err := store.readyAt(source.TransferID(), now.Add(31*time.Second)); err != nil || ready {
		t.Fatalf("expired ready=%v err=%v", ready, err)
	}
}

func TestSourceStoreReadinessRejectsTamperedManifestOrDerivedColumns(t *testing.T) {
	store, err := openSourceStore(privateDatabase(t), defaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	source := verifiedTestSource(t, now, 1, 4, 4)
	if err := store.initialize(context.Background(), source, now); err != nil {
		t.Fatal(err)
	}
	if err := store.upload(context.Background(), source.TransferID(), 0, bytes.Repeat([]byte{1}, 20), now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), `UPDATE v3_source_specs SET plaintext_size = plaintext_size + 1`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.readyAt(source.TransferID(), now); err == nil {
		t.Fatal("tampered source geometry accepted")
	}
}

func TestSourceStoreFailsClosedWithoutMatchingLifecycleRow(t *testing.T) {
	path := privateDatabase(t)
	store, err := openSourceStore(path, defaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	source := verifiedTestSource(t, now, 1, 4, 4)
	if err := store.initialize(context.Background(), source, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), `DELETE FROM v3_transfers`); err != nil {
		t.Fatal(err)
	}
	if err := store.upload(context.Background(), source.TransferID(), 0, bytes.Repeat([]byte{1}, 20), now); err == nil {
		t.Fatal("final upload accepted without lifecycle row")
	}
	var ready int
	transferID := source.TransferID()
	if err := store.db.QueryRowContext(context.Background(), `SELECT ready FROM v3_source_specs WHERE transfer_id = ?`, transferID[:]).Scan(&ready); err != nil || ready != 0 {
		t.Fatalf("ready=%d err=%v", ready, err)
	}
	if err := store.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := openSourceStore(path, defaultSourceLimits()); err == nil {
		t.Fatal("untracked active source accepted on reopen")
	}
}

func TestSourceStoreReadinessRejectsLifecycleReadyMismatch(t *testing.T) {
	store, err := openSourceStore(privateDatabase(t), defaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	source := verifiedTestSource(t, now, 1, 4, 4)
	if err := store.initialize(context.Background(), source, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), `UPDATE v3_transfers SET status = ?`, transferSourceReady); err != nil {
		t.Fatal(err)
	}
	if _, err := store.readyAt(source.TransferID(), now); err == nil {
		t.Fatal("ready lifecycle mismatch accepted")
	}
}

func TestSourceStoreRejectsRelativeOrInsecureParent(t *testing.T) {
	if _, err := openSourceStore("source.db", defaultSourceLimits()); err == nil {
		t.Fatal("relative source store accepted")
	}
	if runtime.GOOS == "windows" {
		return
	}
	parent := t.TempDir()
	// #nosec G302 -- this fixture must be group-readable to exercise rejection.
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := openSourceStore(filepath.Join(parent, "source.db"), defaultSourceLimits()); err == nil {
		t.Fatal("insecure source store parent accepted")
	}
}

func TestSourceStoreDoesNotLeaveSQLiteWALSidecars(t *testing.T) {
	path := privateDatabase(t)
	store, err := openSourceStore(path, defaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	source := verifiedTestSource(t, now, 1, 4, 4)
	if err := store.initialize(context.Background(), source, now); err != nil {
		t.Fatal(err)
	}
	for _, sidecar := range []string{path + "-wal", path + "-shm", path + "-journal"} {
		if _, err := os.Lstat(sidecar); !os.IsNotExist(err) {
			t.Fatalf("unexpected SQLite sidecar %s: %v", sidecar, err)
		}
	}
}

func TestSourceStoreRejectsObsoleteSchema(t *testing.T) {
	path := privateDatabase(t)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(context.Background(), `CREATE TABLE v3_source_specs (transfer_id BLOB PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := openSourceStore(path, defaultSourceLimits()); err == nil {
		t.Fatal("obsolete source store schema accepted")
	}
}

func TestSourceStoreAcceptsPrivateRollbackJournalForRecovery(t *testing.T) {
	path := privateDatabase(t)
	if err := os.WriteFile(path+"-journal", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := openSourceStore(path, defaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
}

func TestSourceStoreReservesQuotaAndRetainsTerminalUniqueness(t *testing.T) {
	limits := defaultSourceLimits()
	limits.Relay.Transfers = 1
	store, err := openSourceStore(privateDatabase(t), limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	first := verifiedTestSource(t, now, 1, 4, 4)
	secondManifest := first.manifest
	secondManifest.TransferID = testID(99)
	secondManifest.PlaintextCommitment = testHash(99)
	second := verifiedSourceForManifest(t, secondManifest, now)
	if err := store.initialize(context.Background(), first, now); err != nil {
		t.Fatal(err)
	}
	if err := store.initialize(context.Background(), second, now); err == nil {
		t.Fatal("relay capacity exceeded")
	}
	if err := store.cancel(context.Background(), first.TransferID(), now); err != nil {
		t.Fatal(err)
	}
	assertTransferStatus(t, store, first.TransferID(), transferCancelled)
	if err := store.initialize(context.Background(), first, now); err == nil {
		t.Fatal("cancelled transfer identity was reused")
	}
	if err := store.initialize(context.Background(), second, now); err != nil {
		t.Fatal(err)
	}
}

func TestSourceStoreReaperReleasesCapacityButNotUniqueness(t *testing.T) {
	limits := defaultSourceLimits()
	limits.Relay.Transfers = 1
	store, err := openSourceStore(privateDatabase(t), limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	first := verifiedTestSource(t, now, 1, 4, 4)
	secondManifest := first.manifest
	secondManifest.TransferID, secondManifest.PlaintextCommitment = testID(98), testHash(98)
	second := verifiedSourceForManifest(t, secondManifest, now)
	if err := store.initialize(context.Background(), first, now); err != nil {
		t.Fatal(err)
	}
	if reaped, err := store.reapExpired(context.Background(), now.Add(31*time.Second), 1); err != nil || reaped != 1 {
		t.Fatalf("reaped=%d err=%v", reaped, err)
	}
	assertTransferStatus(t, store, first.TransferID(), transferExpired)
	if err := store.initialize(context.Background(), first, now); err == nil {
		t.Fatal("expired source identity was reused")
	}
	if err := store.initialize(context.Background(), second, now); err != nil {
		t.Fatal(err)
	}
}

func TestSourceStoreBoundsDurableAdmissionAfterCancellation(t *testing.T) {
	limits := defaultSourceLimits()
	limits.Relay.DurableSources = 1
	store, err := openSourceStore(privateDatabase(t), limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	first := verifiedTestSource(t, now, 1, 4, 4)
	secondManifest := first.manifest
	secondManifest.TransferID, secondManifest.PlaintextCommitment = testID(97), testHash(97)
	second := verifiedSourceForManifest(t, secondManifest, now)
	if err := store.initialize(context.Background(), first, now); err != nil {
		t.Fatal(err)
	}
	if err := store.cancel(context.Background(), first.TransferID(), now); err != nil {
		t.Fatal(err)
	}
	if err := store.initialize(context.Background(), second, now); err == nil {
		t.Fatal("durable admission budget did not bound cancelled-source growth")
	}
}

func testID(value byte) (id [16]byte)     { id[0] = value; return id }
func testHash(value byte) (hash [32]byte) { hash[0] = value; return hash }

func verifiedTestSource(t *testing.T, now time.Time, chunkCount, chunkSize, plaintextSize uint64) VerifiedSource {
	t.Helper()
	manifest := testManifest(now)
	manifest.ChunkCount, manifest.ChunkSize, manifest.PlaintextSize = chunkCount, chunkSize, plaintextSize
	// #nosec G115 -- test inputs constrain chunkCount to the v3 4096 limit.
	manifest.TransferID = testID(byte(10 + chunkCount))
	return verifiedSourceForManifest(t, manifest, now)
}

func verifiedSourceForManifest(t *testing.T, manifest Manifest, now time.Time) VerifiedSource {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	if err := SignManifest(&manifest, private); err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	source, err := DecodeAndVerifySourceInit(raw, manifestAuthorityStub{public: public}, now)
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func privateDatabase(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(directory, "source.db")
}

func assertTransferStatus(t *testing.T, store *sourceStore, transferID [16]byte, want transferStatus) {
	t.Helper()
	var got transferStatus
	if err := store.db.QueryRowContext(context.Background(), `SELECT status FROM v3_transfers WHERE transfer_id = ?`, transferID[:]).Scan(&got); err != nil || got != want {
		t.Fatalf("transfer status=%d err=%v want=%d", got, err, want)
	}
}
