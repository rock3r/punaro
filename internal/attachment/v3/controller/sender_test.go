package controller

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
)

func TestSenderStagerPersistsEncryptedIntentOnlyAfterFreshExactMapping(t *testing.T) {
	journal, err := OpenJournal(filepath.Join(t.TempDir(), "private", "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = journal.Close() }()
	mapping := Mapping{RelayConversationID: "relay-conversation", ConversationID: bytes16(1), SenderDeviceID: bytes16(2), SenderGeneration: 1, RecipientDeviceID: bytes16(3), RecipientGeneration: 1, MembershipCommitment: bytes32(4)}
	if err := journal.AddMapping(mapping); err != nil {
		t.Fatal(err)
	}
	artifactParent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(artifactParent, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := attachmentv3.OpenArtifactStore(filepath.Join(artifactParent, "artifact.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0).UTC()
	stager, err := NewSenderStager(SenderStageOptions{Journal: journal, ArtifactStore: store, BindingResolver: &bindingResolverStub{binding: testCurrentBinding(mapping, 120)}, Sender: SenderIdentity{DeviceID: mapping.SenderDeviceID, Generation: mapping.SenderGeneration}, SigningKey: private, Now: func() time.Time { return now }, NewID: sequenceID(bytes16(90)), ChunkSize: 1024})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := stager.Stage(context.Background(), mapping.RelayConversationID, []byte("local plaintext must not enter the sender journal"))
	if err != nil {
		t.Fatal(err)
	}
	var rawManifest, fileKey, ciphertext []byte
	if err := journal.db.QueryRow(`SELECT manifest, file_key FROM controller_sender_transfers WHERE transfer_id = ?`, manifest.TransferID[:]).Scan(&rawManifest, &fileKey); err != nil {
		t.Fatal(err)
	}
	if len(rawManifest) == 0 || len(fileKey) != 32 {
		t.Fatal("sender intent was not durable")
	}
	if err := journal.db.QueryRow(`SELECT ciphertext FROM controller_sender_chunks WHERE transfer_id = ? AND chunk_index = 0`, manifest.TransferID[:]).Scan(&ciphertext); err != nil || len(ciphertext) == 0 {
		t.Fatalf("ciphertext=%x err=%v", ciphertext, err)
	}
	var count int
	if err := journal.db.QueryRow(`SELECT COUNT(*) FROM controller_sender_transfers`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	if manifest.TransferID != bytes16(90) || manifest.SenderDeviceID != mapping.SenderDeviceID {
		t.Fatalf("manifest=%+v", manifest)
	}
}
