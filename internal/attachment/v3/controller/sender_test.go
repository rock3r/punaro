package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
	"github.com/zeebo/blake3"
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
	binding := testCurrentBinding(mapping, 120)
	copy(binding.Sender.SigningPublicKey[:], private.Public().(ed25519.PublicKey))
	protector := &senderKeyProtectorStub{}
	stager, err := NewSenderStager(SenderStageOptions{Journal: journal, ArtifactStore: store, BindingResolver: &bindingResolverStub{binding: binding}, Sender: SenderIdentity{DeviceID: mapping.SenderDeviceID, Generation: mapping.SenderGeneration}, SigningKey: private, FileKeyProtector: protector, Now: func() time.Time { return now }, NewID: sequenceID(bytes16(90)), ChunkSize: 1024})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := stager.Stage(context.Background(), bytes16(89), mapping.RelayConversationID, []byte("local plaintext must not enter the sender journal"))
	if err != nil {
		t.Fatal(err)
	}
	var rawManifest, fileKey, ciphertext []byte
	if err := journal.db.QueryRow(`SELECT manifest, wrapped_file_key FROM controller_sender_transfers WHERE transfer_id = ?`, manifest.TransferID[:]).Scan(&rawManifest, &fileKey); err != nil {
		t.Fatal(err)
	}
	if len(rawManifest) == 0 || len(fileKey) == 0 || bytes.Contains(fileKey, protector.key[:]) {
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

func TestSenderStagerRejectsMismatchedLocalSigningKeyBeforeArtifactOrJournalSideEffects(t *testing.T) {
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
	protector := &senderKeyProtectorStub{}
	stager, err := NewSenderStager(SenderStageOptions{Journal: journal, ArtifactStore: store, BindingResolver: &bindingResolverStub{binding: testCurrentBinding(mapping, 120)}, Sender: SenderIdentity{DeviceID: mapping.SenderDeviceID, Generation: mapping.SenderGeneration}, SigningKey: private, FileKeyProtector: protector, Now: func() time.Time { return time.Unix(100, 0).UTC() }, NewID: sequenceID(bytes16(90)), ChunkSize: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stager.Stage(context.Background(), bytes16(89), mapping.RelayConversationID, []byte("must not reserve artifact crypto")); err == nil {
		t.Fatal("mismatched local signing key was staged")
	}
	var count int
	if err := journal.db.QueryRow(`SELECT COUNT(*) FROM controller_sender_transfers`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("sender journal side effect count=%d err=%v", count, err)
	}
	if protector.calls != 0 {
		t.Fatal("mismatched local signing key reached key wrapping")
	}
}

func TestSenderStagerStageIDIsStableAndRejectsChangedPlaintext(t *testing.T) {
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
	binding := testCurrentBinding(mapping, 120)
	copy(binding.Sender.SigningPublicKey[:], private.Public().(ed25519.PublicKey))
	stager, err := NewSenderStager(SenderStageOptions{Journal: journal, ArtifactStore: store, BindingResolver: &bindingResolverStub{binding: binding}, Sender: SenderIdentity{DeviceID: mapping.SenderDeviceID, Generation: mapping.SenderGeneration}, SigningKey: private, FileKeyProtector: &senderKeyProtectorStub{}, Now: func() time.Time { return time.Unix(100, 0).UTC() }, NewID: sequenceID(bytes16(90)), ChunkSize: 1024})
	if err != nil {
		t.Fatal(err)
	}
	stageID := bytes16(89)
	first, err := stager.Stage(context.Background(), stageID, mapping.RelayConversationID, []byte("stable staged plaintext"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := stager.Stage(context.Background(), stageID, mapping.RelayConversationID, []byte("stable staged plaintext"))
	if err != nil || second != first {
		t.Fatalf("stable stage retry=%+v err=%v", second, err)
	}
	// Simulate a process death after ArtifactStore reserved the exact key/salt
	// tuple but before the controller's ciphertext transaction committed. The
	// durable stage intent must replay the same manifest and reservation.
	if _, err := journal.db.Exec(`DELETE FROM controller_sender_chunks WHERE transfer_id=?`, first.TransferID[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.db.Exec(`DELETE FROM controller_sender_transfers WHERE transfer_id=?`, first.TransferID[:]); err != nil {
		t.Fatal(err)
	}
	third, err := stager.Stage(context.Background(), stageID, mapping.RelayConversationID, []byte("stable staged plaintext"))
	if err != nil || third != first {
		t.Fatalf("crash-recovered stage=%+v err=%v", third, err)
	}
	if _, err := stager.Stage(context.Background(), stageID, mapping.RelayConversationID, []byte("changed staged plaintext")); err == nil {
		t.Fatal("same stage ID accepted changed plaintext")
	}
	var transfers, intents int
	if err := journal.db.QueryRow(`SELECT COUNT(*) FROM controller_sender_transfers`).Scan(&transfers); err != nil || transfers != 1 {
		t.Fatalf("transfers=%d err=%v", transfers, err)
	}
	if err := journal.db.QueryRow(`SELECT COUNT(*) FROM controller_sender_stage_intents`).Scan(&intents); err != nil || intents != 1 {
		t.Fatalf("intents=%d err=%v", intents, err)
	}
}

func TestJournalReapsExpiredSenderStagesAndCiphertext(t *testing.T) {
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
	binding := testCurrentBinding(mapping, 120)
	copy(binding.Sender.SigningPublicKey[:], private.Public().(ed25519.PublicKey))
	stager, err := NewSenderStager(SenderStageOptions{Journal: journal, ArtifactStore: store, BindingResolver: &bindingResolverStub{binding: binding}, Sender: SenderIdentity{DeviceID: mapping.SenderDeviceID, Generation: mapping.SenderGeneration}, SigningKey: private, FileKeyProtector: &senderKeyProtectorStub{}, Now: func() time.Time { return time.Unix(100, 0).UTC() }, NewID: sequenceID(bytes16(90)), ChunkSize: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stager.Stage(context.Background(), bytes16(89), mapping.RelayConversationID, []byte("expired staged plaintext")); err != nil {
		t.Fatal(err)
	}
	reaped, err := journal.ReapExpiredSenderStages(time.Unix(121, 0).UTC(), 1)
	if err != nil || reaped != 1 {
		t.Fatalf("reaped=%d err=%v", reaped, err)
	}
	for _, table := range []string{"controller_sender_stage_intents", "controller_sender_transfers", "controller_sender_chunks"} {
		var count int
		if err := journal.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("table=%s count=%d err=%v", table, count, err)
		}
	}
}

type senderKeyProtectorStub struct {
	key   [32]byte
	calls int
}

func (s *senderKeyProtectorStub) SealSenderFileKey(_ context.Context, key [32]byte, aad []byte) ([]byte, error) {
	s.calls++
	s.key = key
	sealed := blake3.Sum256(append(append([]byte("test-sealed-key\x00"), aad...), key[:]...))
	return append([]byte("sealed:"), sealed[:]...), nil
}
func (s *senderKeyProtectorStub) OpenSenderFileKey(context.Context, []byte, []byte) ([32]byte, error) {
	return s.key, nil
}
