package trustedattachmentclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const receiverArtifactID = "11111111-1111-4111-8111-111111111111"

func TestReceiverVerifiesAndFinalizesWithoutReplace(t *testing.T) {
	root := t.TempDir()
	receiver, err := NewReceiver(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = receiver.Close() })
	body := []byte("verified attachment")
	metadata := DownloadMetadata{ArtifactID: receiverArtifactID, SizeBytes: int64(len(body)), SHA256: sha256.Sum256(body), DisplayName: "report.txt", MediaType: "text/plain"}
	name, err := receiver.Receive(context.Background(), metadata, bytes.NewReader(body))
	if err != nil || name != "report.txt" {
		t.Fatalf("name=%q err=%v", name, err)
	}
	// #nosec G304 -- name is the receiver's validated basename inside t.TempDir.
	got, err := os.ReadFile(filepath.Join(root, name))
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("body=%q err=%v", got, err)
	}
	if err := os.WriteFile(filepath.Join(root, "existing.txt"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	metadata.DisplayName = "existing.txt"
	if _, err := receiver.Receive(context.Background(), metadata, bytes.NewReader(body)); !errors.Is(err, ErrDestinationExists) {
		t.Fatalf("existing destination error=%v", err)
	}
	// #nosec G304 -- the fixed test filename is inside t.TempDir.
	got, _ = os.ReadFile(filepath.Join(root, "existing.txt"))
	if string(got) != "keep" {
		t.Fatalf("existing destination changed to %q", got)
	}
}

func TestReceiverLeavesNoVisiblePartialOnIntegrityFailure(t *testing.T) {
	root := t.TempDir()
	receiver, err := NewReceiver(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = receiver.Close() })
	body := []byte("attachment")
	metadata := DownloadMetadata{ArtifactID: receiverArtifactID, SizeBytes: int64(len(body)), SHA256: sha256.Sum256([]byte("different")), DisplayName: "report.txt", MediaType: "text/plain"}
	if _, err := receiver.Receive(context.Background(), metadata, bytes.NewReader(body)); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("integrity error=%v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("entries=%v err=%v", entries, err)
	}
}

func TestReceiverContainsUntrustedNamesAndRootReplacement(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "downloads")
	outside := filepath.Join(parent, "outside")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	receiver, err := NewReceiver(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = receiver.Close() })
	moved := filepath.Join(parent, "moved-downloads")
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, root); err != nil {
		t.Fatal(err)
	}
	body := []byte("contained")
	metadata := DownloadMetadata{ArtifactID: receiverArtifactID, SizeBytes: int64(len(body)), SHA256: sha256.Sum256(body), DisplayName: "../escape.txt", MediaType: "text/plain"}
	name, err := receiver.Receive(context.Background(), metadata, bytes.NewReader(body))
	if err != nil || name != "attachment-"+receiverArtifactID {
		t.Fatalf("name=%q err=%v", name, err)
	}
	if _, err := os.Stat(filepath.Join(outside, name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("outside destination exists: %v", err)
	}
	// #nosec G304 -- name is the receiver's validated basename inside the moved test root.
	if got, err := os.ReadFile(filepath.Join(moved, name)); err != nil || string(got) != string(body) {
		t.Fatalf("contained body=%q err=%v", got, err)
	}
}

func TestSafeDownloadNameRejectsPortableReservedNames(t *testing.T) {
	for _, value := range []string{"", ".", "..", "a/b", `a\\b`, "/tmp/a", "NUL", "con.txt", "COM1.log", "trailing. ", "bad\x00name", strings.Repeat("a", 256)} {
		if got := safeDownloadName(value, receiverArtifactID); got != "attachment-"+receiverArtifactID {
			t.Fatalf("safeDownloadName(%q)=%q", value, got)
		}
	}
	if got := safeDownloadName("quarterly report.pdf", receiverArtifactID); got != "quarterly report.pdf" {
		t.Fatalf("safe name=%q", got)
	}
	stageName := ".punaro-" + receiverArtifactID + "-0123456789abcdef0123456789abcdef.part"
	if got := safeDownloadName(stageName, receiverArtifactID); got != "attachment-"+receiverArtifactID {
		t.Fatalf("stage-like safe name=%q", got)
	}
}

func TestReceiverAcceptsValidLongUnicodeMetadataWithOpaqueFallback(t *testing.T) {
	root := t.TempDir()
	receiver, err := NewReceiver(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = receiver.Close() })
	body := []byte("unicode")
	metadata := DownloadMetadata{ArtifactID: receiverArtifactID, SizeBytes: int64(len(body)), SHA256: sha256.Sum256(body), DisplayName: strings.Repeat("😀", 100), MediaType: "text/plain"}
	name, err := receiver.Receive(context.Background(), metadata, bytes.NewReader(body))
	if err != nil || name != "attachment-"+receiverArtifactID {
		t.Fatalf("name=%q err=%v", name, err)
	}
}

type cancelAtEOFReader struct {
	body   []byte
	cancel context.CancelFunc
	done   bool
}

func (reader *cancelAtEOFReader) Read(destination []byte) (int, error) {
	if reader.done {
		return 0, io.EOF
	}
	reader.done = true
	read := copy(destination, reader.body)
	reader.cancel()
	return read, io.EOF
}

func TestReceiverCancellationBeforeCommitLeavesNoVisibleFile(t *testing.T) {
	root := t.TempDir()
	receiver, err := NewReceiver(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = receiver.Close() })
	body := []byte("cancelled")
	ctx, cancel := context.WithCancel(context.Background())
	metadata := DownloadMetadata{ArtifactID: receiverArtifactID, SizeBytes: int64(len(body)), SHA256: sha256.Sum256(body), DisplayName: "report.txt", MediaType: "text/plain"}
	if _, err := receiver.Receive(ctx, metadata, &cancelAtEOFReader{body: body, cancel: cancel}); !errors.Is(err, context.Canceled) {
		t.Fatalf("receive error=%v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("entries=%v err=%v", entries, err)
	}
}

func TestNewReceiverBoundsAndRetiresOnlyOldPrivateStages(t *testing.T) {
	root := t.TempDir()
	oldStage := ".punaro-" + receiverArtifactID + "-11111111111111111111111111111111.part"
	recentStage := ".punaro-" + receiverArtifactID + "-22222222222222222222222222222222.part"
	for _, name := range []string{oldStage, recentStage, "ordinary.txt"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("stage"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-25 * time.Hour)
	if err := os.Chtimes(filepath.Join(root, oldStage), old, old); err != nil {
		t.Fatal(err)
	}
	receiver, err := NewReceiver(root)
	if err != nil {
		t.Fatal(err)
	}
	_ = receiver.Close()
	if _, err := os.Lstat(filepath.Join(root, oldStage)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old stage remains: %v", err)
	}
	for _, name := range []string{recentStage, "ordinary.txt"} {
		if _, err := os.Lstat(filepath.Join(root, name)); err != nil {
			t.Fatalf("%s was removed: %v", name, err)
		}
	}
}

func TestNewReceiverRejectsRootBeyondCleanupEntryBound(t *testing.T) {
	root := t.TempDir()
	for index := 0; index <= maxSafeRootEntries; index++ {
		name := filepath.Join(root, fmt.Sprintf("entry-%05d", index))
		if err := os.WriteFile(name, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := NewReceiver(root); err == nil || !strings.Contains(err.Error(), "cleanup bound") {
		t.Fatalf("oversized root error=%v", err)
	}
}
