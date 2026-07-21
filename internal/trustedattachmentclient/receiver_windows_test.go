//go:build windows

package trustedattachmentclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsTrustedAttachmentReceiverNoReplace(t *testing.T) {
	root := t.TempDir()
	receiver, err := NewReceiver(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = receiver.Close() }()
	body := []byte("windows native attachment")
	metadata := DownloadMetadata{ArtifactID: receiverArtifactID, SizeBytes: int64(len(body)), SHA256: sha256.Sum256(body), DisplayName: "NUL.txt", MediaType: "text/plain"}
	name, err := receiver.Receive(context.Background(), metadata, bytes.NewReader(body))
	if err != nil || name != "attachment-"+receiverArtifactID {
		t.Fatalf("name=%q err=%v", name, err)
	}
	// #nosec G304 -- name is the receiver's validated basename inside t.TempDir.
	if got, err := os.ReadFile(filepath.Join(root, name)); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("body=%q err=%v", got, err)
	}
	if _, err := receiver.Receive(context.Background(), metadata, bytes.NewReader(body)); !errors.Is(err, ErrDestinationExists) {
		t.Fatalf("existing destination error=%v", err)
	}
}
