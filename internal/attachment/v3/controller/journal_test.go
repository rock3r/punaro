package controller

import (
	"os"
	"path/filepath"
	"testing"
)

func TestJournalKeepsMappingsImmutableAndOffersIdempotent(t *testing.T) {
	t.Parallel()
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenJournal(filepath.Join(parent, "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	mapping := Mapping{RelayConversationID: "relay-conversation", ConversationID: bytes16(21), SenderDeviceID: bytes16(22), SenderGeneration: 1, RecipientDeviceID: bytes16(23), RecipientGeneration: 1, MembershipCommitment: bytes32(24)}
	if err := journal.AddMapping(mapping); err != nil {
		t.Fatal(err)
	}
	if err := journal.AddMapping(mapping); err != nil {
		t.Fatalf("exact mapping retry rejected: %v", err)
	}
	changed := mapping
	changed.RecipientDeviceID = bytes16(25)
	if err := journal.AddMapping(changed); err == nil {
		t.Fatal("mapping replacement accepted")
	}
	inbound := InboundOffer{PunaroMessageID: "message-1", RelayConversationID: mapping.RelayConversationID, Body: testOfferNotice(t, mapping)}
	notice, created, err := journal.RecordInboundOffer(inbound)
	if err != nil || !created || notice.Manifest.ConversationID != mapping.ConversationID {
		t.Fatalf("notice=%+v created=%t err=%v", notice, created, err)
	}
	if _, created, err := journal.RecordInboundOffer(inbound); err != nil || created {
		t.Fatalf("exact offer retry created=%t err=%v", created, err)
	}
	inbound.Body += "x"
	if _, _, err := journal.RecordInboundOffer(inbound); err == nil {
		t.Fatal("changed offer retry accepted")
	}
}

func TestOpenJournalRejectsUnsafeParent(t *testing.T) {
	t.Parallel()
	unsafe := filepath.Join(t.TempDir(), "unsafe")
	if err := os.Mkdir(unsafe, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(filepath.Join(unsafe, "controller.db")); err == nil {
		t.Fatal("journal accepted world-readable parent")
	}
}

func TestOpenJournalRejectsUnsafeSQLiteSidecar(t *testing.T) {
	t.Parallel()
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "controller.db")
	if err := os.WriteFile(path+"-journal", []byte("unexpected"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(path); err == nil {
		t.Fatal("journal accepted unsafe SQLite sidecar")
	}
}
