package controller

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
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
	// #nosec G301 -- this fixture must be group-readable to exercise rejection.
	if err := os.Mkdir(unsafe, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(filepath.Join(unsafe, "controller.db")); err == nil {
		t.Fatal("journal accepted world-readable parent")
	}
}

func TestJournalBindsSenderIdentityAndExcludesRecipientRole(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "private", "controller.db")
	sender := SenderIdentity{DeviceID: bytes16(71), Generation: 1}
	journal, err := OpenJournalForSender(path, sender)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.AddMapping(Mapping{RelayConversationID: "relay-other", ConversationID: bytes16(74), SenderDeviceID: bytes16(72), SenderGeneration: 1, RecipientDeviceID: bytes16(75), RecipientGeneration: 1, MembershipCommitment: bytes32(76)}); err == nil {
		t.Fatal("sender journal accepted a non-local source mapping")
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournalForSender(path, SenderIdentity{DeviceID: bytes16(72), Generation: 1}); err == nil {
		t.Fatal("sender journal accepted a changed source identity")
	}
	if _, err := OpenJournalForRecipient(path, RecipientIdentity{DeviceID: bytes16(73), Generation: 1}); err == nil {
		t.Fatal("sender journal accepted a recipient role")
	}
}

func TestOpenJournalRejectsUnsafeSQLiteSidecar(t *testing.T) {
	t.Parallel()
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "controller.db")
	// #nosec G306 -- this fixture must be group-readable to exercise rejection.
	if err := os.WriteFile(path+"-journal", []byte("unexpected"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(path); err == nil {
		t.Fatal("journal accepted unsafe SQLite sidecar")
	}
}

func TestOpenJournalMigratesLegacyOfferExpiryWithoutGuessingIt(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "controller.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.ExecContext(context.Background(), `CREATE TABLE controller_inbound_offers (
		punaro_message_id TEXT PRIMARY KEY, relay_conversation_id TEXT NOT NULL,
		offer BLOB NOT NULL, transfer_id BLOB NOT NULL
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.ExecContext(context.Background(), `INSERT INTO controller_inbound_offers(punaro_message_id, relay_conversation_id, offer, transfer_id) VALUES ('legacy', 'relay', x'01', x'02')`); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	// The migration does not derive a lifetime by parsing old relay bytes. It
	// preserves recovery safety by retaining legacy records until an operator
	// explicitly resolves them.
	if reaped, err := journal.ReapExpiredUnapprovedOffers(time.Unix(1<<20, 0).UTC(), 1); err != nil || reaped != 0 {
		t.Fatalf("legacy offer was guessed expired: reaped=%d err=%v", reaped, err)
	}
	var retained int
	if err := journal.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM controller_inbound_offers WHERE punaro_message_id = 'legacy'`).Scan(&retained); err != nil || retained != 1 {
		t.Fatalf("legacy offer retained=%d err=%v", retained, err)
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
	if _, err := journal.PrepareApprovedReceipt(context.Background(), inbound, resolver, testOfferDirectory(t), now); err == nil {
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
	if notice, err := journal.PrepareApprovedReceipt(context.Background(), inbound, resolver, testOfferDirectory(t), now); err != nil || notice.Manifest.TransferID == [16]byte{} {
		t.Fatalf("approved receipt notice=%+v err=%v", notice, err)
	}
	resolver.binding.Membership.Revoked = true
	if _, err := journal.PrepareApprovedReceipt(context.Background(), inbound, resolver, testOfferDirectory(t), now); err == nil {
		t.Fatal("revoked relationship progressed after approval")
	}
}

func TestApprovedInboundOfferRequiresMatchingImmutableApproval(t *testing.T) {
	journal, err := OpenJournal(filepath.Join(t.TempDir(), "private", "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = journal.Close() }()
	mapping := Mapping{RelayConversationID: "relay-approved", ConversationID: bytes16(61), SenderDeviceID: bytes16(62), SenderGeneration: 1, RecipientDeviceID: bytes16(63), RecipientGeneration: 1, MembershipCommitment: bytes32(64)}
	if err := journal.AddMapping(mapping); err != nil {
		t.Fatal(err)
	}
	inbound := InboundOffer{PunaroMessageID: "approved-message", RelayConversationID: mapping.RelayConversationID, Body: testOfferNotice(t, mapping)}
	if _, _, err := journal.RecordInboundOffer(inbound); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.ApprovedInboundOffer(inbound.PunaroMessageID); err == nil {
		t.Fatal("unapproved offer was returned")
	}
	if approved, err := journal.ApproveInboundOffer(inbound.PunaroMessageID, time.Unix(100, 0)); err != nil || !approved {
		t.Fatalf("approved=%t err=%v", approved, err)
	}
	if got, err := journal.ApprovedInboundOffer(inbound.PunaroMessageID); err != nil || got.PunaroMessageID != inbound.PunaroMessageID || got.RelayConversationID != inbound.RelayConversationID || got.Body == "" {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	tampered := bytes32(99)
	if _, err := journal.db.ExecContext(context.Background(), `UPDATE controller_receipt_approvals SET offer_commitment=? WHERE punaro_message_id=?`, tampered[:], inbound.PunaroMessageID); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.ApprovedInboundOffer(inbound.PunaroMessageID); err == nil {
		t.Fatal("tampered approval commitment was accepted")
	}
}

func TestReceiptApprovalSurvivesRestartButRejectsChangedDelivery(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "private", "controller.db")
	journal, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	mapping := Mapping{RelayConversationID: "relay-conversation", ConversationID: bytes16(41), SenderDeviceID: bytes16(42), SenderGeneration: 1, RecipientDeviceID: bytes16(43), RecipientGeneration: 1, MembershipCommitment: bytes32(44)}
	if err := journal.AddMapping(mapping); err != nil {
		t.Fatal(err)
	}
	inbound := InboundOffer{PunaroMessageID: "message-1", RelayConversationID: mapping.RelayConversationID, Body: testOfferNotice(t, mapping)}
	if _, _, err := journal.RecordInboundOffer(inbound); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0).UTC()
	if _, err := journal.ApproveInboundOffer(inbound.PunaroMessageID, now); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal, err = OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	resolver := &bindingResolverStub{binding: testCurrentBinding(mapping, 101)}
	if _, err := journal.PrepareApprovedReceipt(context.Background(), inbound, resolver, testOfferDirectory(t), now); err != nil {
		t.Fatalf("approved receipt did not recover after restart: %v", err)
	}
	inbound.Body += "x"
	if _, err := journal.PrepareApprovedReceipt(context.Background(), inbound, resolver, testOfferDirectory(t), now); err == nil {
		t.Fatal("changed delivery was accepted after restart")
	}
}

func TestJournalAcceptsConcurrentExactMappingRetries(t *testing.T) {
	journal, err := OpenJournal(filepath.Join(t.TempDir(), "private", "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	mapping := Mapping{RelayConversationID: "relay-conversation", ConversationID: bytes16(51), SenderDeviceID: bytes16(52), SenderGeneration: 1, RecipientDeviceID: bytes16(53), RecipientGeneration: 1, MembershipCommitment: bytes32(54)}
	const workers = 16
	errs := make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			errs <- journal.AddMapping(mapping)
		}()
	}
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent exact mapping retry rejected: %v", err)
		}
	}
}

func TestJournalAcceptsConcurrentExactReceiptApprovals(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "controller.db")
	journal, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	mapping := Mapping{RelayConversationID: "relay-conversation", ConversationID: bytes16(55), SenderDeviceID: bytes16(56), SenderGeneration: 1, RecipientDeviceID: bytes16(57), RecipientGeneration: 1, MembershipCommitment: bytes32(58)}
	if err := journal.AddMapping(mapping); err != nil {
		t.Fatal(err)
	}
	inbound := InboundOffer{PunaroMessageID: "message-1", RelayConversationID: mapping.RelayConversationID, Body: testOfferNotice(t, mapping)}
	if _, _, err := journal.RecordInboundOffer(inbound); err != nil {
		t.Fatal(err)
	}

	const workers = 16
	approved := make(chan bool, workers)
	errs := make(chan error, workers)
	start := make(chan struct{})
	var group sync.WaitGroup
	for range workers {
		peer, err := OpenJournal(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = peer.Close() })
		group.Add(1)
		go func(j *Journal) {
			defer group.Done()
			<-start
			ok, err := j.ApproveInboundOffer(inbound.PunaroMessageID, time.Unix(100, 0).UTC())
			approved <- ok
			errs <- err
		}(peer)
	}
	close(start)
	group.Wait()
	close(approved)
	close(errs)
	approvals := 0
	for ok := range approved {
		if ok {
			approvals++
		}
	}
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent exact approval rejected: %v", err)
		}
	}
	if approvals != 1 {
		t.Fatalf("approvals=%d, want exactly one durable approval", approvals)
	}
}

func TestJournalDeduplicatesTransferAcrossRelayMessages(t *testing.T) {
	journal, err := OpenJournal(filepath.Join(t.TempDir(), "private", "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	mapping := Mapping{RelayConversationID: "relay-conversation", ConversationID: bytes16(61), SenderDeviceID: bytes16(62), SenderGeneration: 1, RecipientDeviceID: bytes16(63), RecipientGeneration: 1, MembershipCommitment: bytes32(64)}
	if err := journal.AddMapping(mapping); err != nil {
		t.Fatal(err)
	}
	body := testOfferNotice(t, mapping)
	if _, created, err := journal.RecordInboundOffer(InboundOffer{PunaroMessageID: "message-1", RelayConversationID: mapping.RelayConversationID, Body: body}); err != nil || !created {
		t.Fatalf("first discovery created=%t err=%v", created, err)
	}
	if _, created, err := journal.RecordInboundOffer(InboundOffer{PunaroMessageID: "message-2", RelayConversationID: mapping.RelayConversationID, Body: body}); err != nil || created {
		t.Fatalf("duplicate transfer created=%t err=%v", created, err)
	}
}

func TestJournalReapsOnlyExpiredUnapprovedOffers(t *testing.T) {
	journal, err := OpenJournal(filepath.Join(t.TempDir(), "private", "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	mapping := Mapping{RelayConversationID: "relay-conversation", ConversationID: bytes16(65), SenderDeviceID: bytes16(66), SenderGeneration: 1, RecipientDeviceID: bytes16(67), RecipientGeneration: 1, MembershipCommitment: bytes32(68)}
	if err := journal.AddMapping(mapping); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= maxPendingOffers; i++ {
		inbound := InboundOffer{PunaroMessageID: fmt.Sprintf("message-%d", i), RelayConversationID: mapping.RelayConversationID, Body: testOfferNoticeWith(t, mapping, bytes16(byte(i)), 1, 2)}
		if _, created, err := journal.RecordInboundOffer(inbound); err != nil || !created {
			t.Fatalf("record %d created=%t err=%v", i, created, err)
		}
	}
	protected := InboundOffer{PunaroMessageID: "message-1", RelayConversationID: mapping.RelayConversationID, Body: testOfferNoticeWith(t, mapping, bytes16(1), 1, 2)}
	if approved, err := journal.ApproveInboundOffer(protected.PunaroMessageID, time.Unix(1, 0).UTC()); err != nil || !approved {
		t.Fatalf("approved=%t err=%v", approved, err)
	}
	overflow := InboundOffer{PunaroMessageID: "message-overflow", RelayConversationID: mapping.RelayConversationID, Body: testOfferNoticeWith(t, mapping, bytes16(99), 1, 2)}
	if _, _, err := journal.RecordInboundOffer(overflow); err == nil {
		t.Fatal("unbounded pending offer discovery accepted")
	}
	reaped, err := journal.ReapExpiredUnapprovedOffers(time.Unix(3, 0).UTC(), maxPendingOffers)
	if err != nil || reaped != maxPendingOffers-1 {
		t.Fatalf("reaped=%d err=%v", reaped, err)
	}
	if _, created, err := journal.RecordInboundOffer(overflow); err != nil || !created {
		t.Fatalf("record after reap created=%t err=%v", created, err)
	}
	if _, created, err := journal.RecordInboundOffer(protected); err != nil || created {
		t.Fatalf("approved offer removed by reaper: created=%t err=%v", created, err)
	}
}

func TestRecipientBoundJournalRejectsOtherDeviceMappings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "controller.db")
	recipient := RecipientIdentity{DeviceID: bytes16(71), Generation: 2}
	journal, err := OpenJournalForRecipient(path, recipient)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	mapping := Mapping{RelayConversationID: "relay-conversation", ConversationID: bytes16(72), SenderDeviceID: bytes16(73), SenderGeneration: 1, RecipientDeviceID: bytes16(74), RecipientGeneration: 1, MembershipCommitment: bytes32(75)}
	if err := journal.AddMapping(mapping); err == nil {
		t.Fatal("foreign recipient mapping was accepted")
	}
	mapping.RecipientDeviceID, mapping.RecipientGeneration = bytes16(71), 2
	if err := journal.AddMapping(mapping); err != nil {
		t.Fatalf("local recipient mapping rejected: %v", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournalForRecipient(path, RecipientIdentity{DeviceID: bytes16(76), Generation: 1}); err == nil {
		t.Fatal("journal reopened under a different recipient identity")
	}
	if _, err := OpenJournal(path); err == nil {
		t.Fatal("recipient-bound journal reopened without its local identity")
	}
}

func TestJournalUsesNamedWrappedSenderKeyStorage(t *testing.T) {
	journal, err := OpenJournal(filepath.Join(t.TempDir(), "private", "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = journal.Close() }()
	rows, err := journal.db.QueryContext(context.Background(), `PRAGMA table_info(controller_sender_transfers)`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var hasRaw, hasWrapped bool
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, primary int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &primary); err != nil {
			t.Fatal(err)
		}
		hasRaw = hasRaw || name == "file_key"
		hasWrapped = hasWrapped || name == "wrapped_file_key"
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if hasRaw || !hasWrapped {
		t.Fatalf("sender transfer schema raw=%t wrapped=%t", hasRaw, hasWrapped)
	}
}

func TestJournalRefusesLegacyRawSenderKeyRows(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "controller.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.ExecContext(context.Background(), `CREATE TABLE controller_sender_transfers(transfer_id BLOB PRIMARY KEY, file_key BLOB NOT NULL); INSERT INTO controller_sender_transfers(transfer_id,file_key) VALUES (x'01',x'01020304')`); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(path); err == nil {
		t.Fatal("legacy journal with raw sender key rows was opened")
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
