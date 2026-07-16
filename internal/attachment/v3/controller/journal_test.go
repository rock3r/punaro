package controller

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	attachmentv2 "github.com/rock3r/punaro/internal/attachment/v2"
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

func TestJournalRequiresExplicitReceiptApprovalAfterFreshBinding(t *testing.T) {
	t.Parallel()
	journal, err := OpenJournal(filepath.Join(t.TempDir(), "private", "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	mapping := Mapping{RelayConversationID: "relay-conversation", ConversationID: bytes16(21), SenderDeviceID: bytes16(22), SenderGeneration: 1, RecipientDeviceID: bytes16(23), RecipientGeneration: 1, MembershipCommitment: bytes32(24)}
	if err := journal.AddMapping(mapping); err != nil {
		t.Fatal(err)
	}
	inbound := InboundOffer{PunaroMessageID: "message-1", RelayConversationID: mapping.RelayConversationID, Body: testOfferNotice(t, mapping)}
	if _, _, err := journal.RecordInboundOffer(inbound); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0).UTC()
	resolver := &bindingResolverStub{binding: testCurrentBinding(mapping, 101)}
	if _, err := journal.PrepareApprovedReceipt(context.Background(), inbound, resolver, now); err == nil {
		t.Fatal("receipt progressed without an explicit approval")
	}
	if approved, err := journal.ApproveInboundOffer("unknown", now); err == nil || approved {
		t.Fatal("unknown offer approval was accepted")
	}
	if approved, err := journal.ApproveInboundOffer(inbound.PunaroMessageID, now); err != nil || !approved {
		t.Fatalf("approval=%t err=%v", approved, err)
	}
	if approved, err := journal.ApproveInboundOffer(inbound.PunaroMessageID, now); err != nil || approved {
		t.Fatalf("idempotent approval=%t err=%v", approved, err)
	}
	if notice, err := journal.PrepareApprovedReceipt(context.Background(), inbound, resolver, now); err != nil || notice.Manifest.TransferID == [16]byte{} {
		t.Fatalf("approved receipt notice=%+v err=%v", notice, err)
	}
	resolver.binding.Membership.Revoked = true
	if _, err := journal.PrepareApprovedReceipt(context.Background(), inbound, resolver, now); err == nil {
		t.Fatal("revoked relationship progressed after approval")
	}
}

func testCurrentBinding(mapping Mapping, expiresAt uint64) attachmentv2.DirectoryTransferBinding {
	return attachmentv2.DirectoryTransferBinding{
		Permit:     attachmentv2.DirectoryPermitBinding{Audience: bytes32(31), DirectoryHead: bytes32(32), RevocationEpoch: 1, ExpiresAt: expiresAt},
		Sender:     attachmentv2.DirectoryDevice{DeviceID: mapping.SenderDeviceID, Generation: mapping.SenderGeneration, SigningKeyID: bytes32(33), SigningPublicKey: bytes32(34), HPKEKeyID: bytes32(35), HPKEPublicKey: bytes32(36)},
		Recipient:  attachmentv2.DirectoryDevice{DeviceID: mapping.RecipientDeviceID, Generation: mapping.RecipientGeneration, SigningKeyID: bytes32(37), SigningPublicKey: bytes32(38), HPKEKeyID: bytes32(39), HPKEPublicKey: bytes32(40)},
		Membership: attachmentv2.DirectoryMembership{ConversationID: mapping.ConversationID, SenderDeviceID: mapping.SenderDeviceID, SenderGeneration: mapping.SenderGeneration, RecipientDeviceID: mapping.RecipientDeviceID, RecipientGeneration: mapping.RecipientGeneration, Commitment: mapping.MembershipCommitment},
	}
}
