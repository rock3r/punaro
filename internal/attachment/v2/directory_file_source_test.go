package v2

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDirectorySnapshotFileSourceReadsFreshCanonicalSnapshot(t *testing.T) {
	t.Parallel()
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "directory.cbor")
	first := testDirectorySnapshot(t, 1)
	if err := os.WriteFile(path, first, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := OpenDirectorySnapshotFileSource(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := source.CurrentDirectorySnapshot()
	if err != nil || string(got) != string(first) {
		t.Fatalf("first=%x err=%v", got, err)
	}
	snapshot, err := source.FetchDirectorySnapshot(context.Background())
	if err != nil || len(snapshot.Entries) != 1 {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	second := testDirectorySnapshot(t, 2)
	if err := os.WriteFile(path, second, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = source.CurrentDirectorySnapshot()
	if err != nil || string(got) != string(second) {
		t.Fatalf("second=%x err=%v", got, err)
	}
}

func TestDirectorySnapshotFileSourceAllowsReadOnlyServiceGroup(t *testing.T) {
	t.Parallel()
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o2750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "directory.cbor")
	if err := os.WriteFile(path, testDirectorySnapshot(t, 3), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	source, err := OpenDirectorySnapshotFileSource(path)
	if err != nil {
		t.Fatalf("read-only service group snapshot rejected: %v", err)
	}
	if _, err := source.CurrentDirectorySnapshot(); err != nil {
		t.Fatalf("read-only service group snapshot unavailable: %v", err)
	}
}

func TestDirectorySnapshotFileSourceRejectsUnsafeOrMalformedSource(t *testing.T) {
	t.Parallel()
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "directory.cbor")
	if err := os.WriteFile(path, []byte{0xa0}, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := OpenDirectorySnapshotFileSource(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.CurrentDirectorySnapshot(); err == nil {
		t.Fatal("malformed snapshot accepted")
	}
	if err := os.WriteFile(path, testDirectorySnapshot(t, 9), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o755); err != nil { // #nosec G302 -- intentional insecure test fixture.
		t.Fatal(err)
	}
	if _, err := source.CurrentDirectorySnapshot(); err == nil {
		t.Fatal("runtime source accepted an insecure parent")
	}
	if _, err := OpenDirectorySnapshotFileSource(path); err == nil {
		t.Fatal("insecure parent accepted")
	}
	if err := os.Chmod(parent, 0o770); err != nil { // #nosec G302 -- intentional insecure test fixture.
		t.Fatal(err)
	}
	if _, err := OpenDirectorySnapshotFileSource(path); err == nil {
		t.Fatal("group-writable parent accepted")
	}
	if err := os.Chmod(parent, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o660); err != nil { // #nosec G302 -- intentional insecure test fixture.
		t.Fatal(err)
	}
	if _, err := OpenDirectorySnapshotFileSource(path); err == nil {
		t.Fatal("group-writable snapshot accepted")
	}
}

func testDirectorySnapshot(t *testing.T, marker byte) []byte {
	t.Helper()
	head, err := EncodeDirectoryHead(DirectoryHead{Audience: [32]byte{marker}, RootKeyID: [32]byte{marker + 1}, TreeSize: 1, TreeRoot: [32]byte{marker + 2}, Sequence: uint64(marker), IssuedAt: 1, ExpiresAt: 2, RevocationEpoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeDirectorySnapshot(DirectorySnapshot{RawHead: head, Entries: []DirectoryEntry{{Issuer: &DirectoryPermitIssuer{KeyID: [32]byte{marker + 3}, PublicKey: [32]byte{marker + 4}}}}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
