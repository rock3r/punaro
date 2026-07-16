package controller

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
)

func TestWriteCompletedReceiptAtomicallyPublishesOnlyVerifiedPlaintext(t *testing.T) {
	mapping := Mapping{RelayConversationID: "relay-conversation", ConversationID: bytes16(1), SenderDeviceID: bytes16(2), SenderGeneration: 1, RecipientDeviceID: bytes16(3), RecipientGeneration: 1, MembershipCommitment: bytes32(4)}
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0).UTC()
	manifest, _ := stagedSenderManifest(t, mapping, private, now)
	manifest.Signature = [ed25519.SignatureSize]byte{}
	manifest.ContentSalt, manifest.PlaintextCommitment = [32]byte{}, [32]byte{}
	manifest.ChunkCount, manifest.PlaintextSize = 0, 0
	privateDir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := attachmentv3.OpenArtifactStore(filepath.Join(privateDir, "artifact.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	plain := []byte("recipient plaintext")
	prepared, commitment, err := attachmentv3.PrepareSourceManifest(plain, manifest, private, attachmentv3.SourceArtifactMaterial{FileKey: bytes32(71), ContentSalt: bytes32(72)})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := attachmentv3.EncryptPreparedSourceArtifact(plain, prepared, commitment, bytes32(71), store)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := attachmentv3.EncodeManifest(prepared)
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "received.bin")
	authority := testSenderAuthority(t, mapping, private)
	if err := WriteCompletedReceiptAtomically(destination, raw, artifact.Chunks, bytes32(71), authority, now.Unix()); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(written, plain) {
		t.Fatalf("written=%q err=%v", written, err)
	}
	if info, err := os.Stat(destination); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v err=%v", info.Mode(), err)
	}
	if err := WriteCompletedReceiptAtomically(destination, raw, artifact.Chunks, bytes32(71), authority, now.Unix()); err == nil {
		t.Fatal("existing output was overwritten")
	}
}
