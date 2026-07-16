package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
	"github.com/zeebo/blake3"
)

func TestRecipientAcceptanceWorkerPersistsAndReplaysOnlyExactAcceptedOperation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "controller.db")
	recipient := RecipientIdentity{DeviceID: bytes16(3), Generation: 1}
	journal, err := OpenJournalForRecipient(path, recipient)
	if err != nil {
		t.Fatal(err)
	}
	mapping := Mapping{RelayConversationID: "relay-conversation", ConversationID: bytes16(1), SenderDeviceID: bytes16(2), SenderGeneration: 1, RecipientDeviceID: bytes16(3), RecipientGeneration: 1, MembershipCommitment: bytes32(4)}
	if err := journal.AddMapping(mapping); err != nil {
		t.Fatal(err)
	}
	inbound := InboundOffer{PunaroMessageID: "message-1", RelayConversationID: mapping.RelayConversationID, Body: testOfferNoticeWith(t, mapping, bytes16(6), 100, 130)}
	if _, _, err := journal.RecordInboundOffer(inbound); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0).UTC()
	if approved, err := journal.ApproveInboundOffer(inbound.PunaroMessageID, now); err != nil || !approved {
		t.Fatalf("approved=%t err=%v", approved, err)
	}
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	notice, err := attachmentv3.DecodeOfferNotice(inbound.Body)
	if err != nil {
		t.Fatal(err)
	}
	transport := &acceptanceTransportStub{result: acceptedTransferResult(t, notice.Manifest.TransferID, blake3.Sum256(notice.ManifestRaw), 120)}
	worker, err := NewRecipientAcceptanceWorker(RecipientAcceptanceWorkerOptions{
		Journal: journal, AuthorityProvider: testAcceptanceAuthority(t, mapping, private),
		Signer:    NewLocalRecipientOperationSigner(RecipientIdentity{DeviceID: mapping.RecipientDeviceID, Generation: mapping.RecipientGeneration}, private),
		Transport: transport, Now: func() time.Time { return now },
		NewID: sequenceID(bytes16(90), bytes16(91)), NewIdempotencyKey: func() ([32]byte, error) { return bytes32(92), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := worker.Accept(context.Background(), inbound)
	if err != nil {
		t.Fatal(err)
	}
	if result.TransferID != bytes16(6) || result.State != attachmentv3.TransferStateAccepted || transport.issueCalls != 1 || transport.operationCalls != 1 {
		t.Fatalf("result=%+v issue=%d operation=%d", result, transport.issueCalls, transport.operationCalls)
	}
	if transport.request.HolderDeviceID != mapping.RecipientDeviceID || transport.request.Operation != attachmentv3.PermitOperationAccept || transport.request.AttemptGeneration != 0 || transport.request.MaxOperations != 1 {
		t.Fatalf("unsafe acceptance request: %+v", transport.request)
	}
	if transport.method != http.MethodPost || transport.path != "/v3/attachments/06060606060606060606060606060606/accept" || len(transport.body) != 32 || transport.operation.Operation != attachmentv3.PermitOperationAccept {
		t.Fatalf("unsafe acceptance operation: %s %s op=%+v", transport.method, transport.path, transport.operation)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal, err = OpenJournalForRecipient(path, recipient)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = journal.Close() }()
	stored, found, err := journal.receiptAcceptance(inbound.PunaroMessageID)
	if err != nil || !found || stored.transferID != notice.Manifest.TransferID || stored.manifestCommitment != blake3.Sum256(notice.ManifestRaw) {
		t.Fatalf("stored=%+v found=%t err=%v transfer=%x commitment=%x", stored, found, err, notice.Manifest.TransferID, blake3.Sum256(notice.ManifestRaw))
	}
	restartedTransport := &acceptanceTransportStub{result: transport.result}
	restarted, err := NewRecipientAcceptanceWorker(RecipientAcceptanceWorkerOptions{
		Journal: journal, AuthorityProvider: testAcceptanceAuthority(t, mapping, private),
		Signer: NewLocalRecipientOperationSigner(recipient, private), Transport: restartedTransport, Now: func() time.Time { return now },
		NewID: sequenceID(bytes16(93)), NewIdempotencyKey: func() ([32]byte, error) { return bytes32(94), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := restarted.Accept(context.Background(), inbound); err != nil || got != result {
		t.Fatalf("restart result=%+v err=%v", got, err)
	}
	if restartedTransport.issueCalls != 0 || restartedTransport.operationCalls != 0 {
		t.Fatalf("completed acceptance retried remotely issue=%d operation=%d", restartedTransport.issueCalls, restartedTransport.operationCalls)
	}
}

func TestRecipientAcceptanceWorkerRetriesOnlyPersistedCredentialsAfterRemoteFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "controller.db")
	recipient := RecipientIdentity{DeviceID: bytes16(3), Generation: 1}
	journal, err := OpenJournalForRecipient(path, recipient)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = journal.Close() }()
	mapping := Mapping{RelayConversationID: "relay-conversation", ConversationID: bytes16(1), SenderDeviceID: bytes16(2), SenderGeneration: 1, RecipientDeviceID: bytes16(3), RecipientGeneration: 1, MembershipCommitment: bytes32(4)}
	if err := journal.AddMapping(mapping); err != nil {
		t.Fatal(err)
	}
	inbound := InboundOffer{PunaroMessageID: "message-1", RelayConversationID: mapping.RelayConversationID, Body: testOfferNoticeWith(t, mapping, bytes16(6), 100, 130)}
	if _, _, err := journal.RecordInboundOffer(inbound); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0).UTC()
	if approved, err := journal.ApproveInboundOffer(inbound.PunaroMessageID, now); err != nil || !approved {
		t.Fatalf("approved=%t err=%v", approved, err)
	}
	notice, err := attachmentv3.DecodeOfferNotice(inbound.Body)
	if err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	transport := &acceptanceTransportStub{result: acceptedTransferResult(t, notice.Manifest.TransferID, blake3.Sum256(notice.ManifestRaw), 120), operationErr: errTest("offline")}
	worker, err := NewRecipientAcceptanceWorker(RecipientAcceptanceWorkerOptions{
		Journal: journal, AuthorityProvider: testAcceptanceAuthority(t, mapping, private),
		Signer: NewLocalRecipientOperationSigner(recipient, private), Transport: transport, Now: func() time.Time { return now },
		NewID: sequenceID(bytes16(90), bytes16(91)), NewIdempotencyKey: func() ([32]byte, error) { return bytes32(92), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := worker.Accept(context.Background(), inbound); err == nil {
		t.Fatal("remote acceptance failure was accepted")
	}
	transport.operationErr = nil
	if result, err := worker.Accept(context.Background(), inbound); err != nil || result.State != attachmentv3.TransferStateAccepted {
		t.Fatalf("retry result=%+v err=%v", result, err)
	}
	if transport.issueCalls != 1 || transport.operationCalls != 2 || len(transport.operations) != 2 || transport.operations[0] != transport.operations[1] {
		t.Fatalf("retry created new credentials issue=%d operation=%d records=%d", transport.issueCalls, transport.operationCalls, len(transport.operations))
	}
}

func TestRecipientAcceptanceRejectsPermitOutsideFreshAuthorityBeforeTransport(t *testing.T) {
	worker, inbound, transport := newAcceptanceWorkerForNegativeTest(t, nil)
	transport.badPermit = true
	if _, err := worker.Accept(context.Background(), inbound); err == nil {
		t.Fatal("foreign issuer permit reached transport")
	}
	if transport.operationCalls != 0 {
		t.Fatal("foreign issuer permit called attachment transport")
	}
}

func TestRecipientAcceptanceRejectsChangedOperationBeforeTransport(t *testing.T) {
	worker, inbound, transport := newAcceptanceWorkerForNegativeTest(t, changedAcceptanceSigner{})
	if _, err := worker.Accept(context.Background(), inbound); err == nil {
		t.Fatal("changed operation reached transport")
	}
	if transport.operationCalls != 0 {
		t.Fatal("changed operation called attachment transport")
	}
}

func TestRecipientAcceptanceNeverRetriesTerminalUncertainState(t *testing.T) {
	worker, inbound, transport := newAcceptanceWorkerForNegativeTest(t, nil)
	now := time.Unix(100, 0).UTC()
	notice, err := attachmentv3.DecodeOfferNotice(inbound.Body)
	if err != nil {
		t.Fatal(err)
	}
	mapping, found, err := worker.options.Journal.mapping(inbound.RelayConversationID)
	if err != nil || !found {
		t.Fatal("missing acceptance mapping")
	}
	if _, err := worker.options.Journal.ensureReceiptAcceptance(inbound.PunaroMessageID, notice, mapping, now, worker.options.Signer, worker.options.NewID, worker.options.NewIdempotencyKey); err != nil {
		t.Fatal(err)
	}
	if err := worker.options.Journal.markReceiptUncertain(inbound.PunaroMessageID, now); err != nil {
		t.Fatal(err)
	}
	if err := worker.options.Journal.terminalizeReceiptUncertain(inbound.PunaroMessageID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := worker.Accept(context.Background(), inbound); err == nil {
		t.Fatal("terminal uncertain acceptance retried")
	}
	if transport.issueCalls != 0 || transport.operationCalls != 0 {
		t.Fatalf("terminal uncertain reached transport issue=%d operation=%d", transport.issueCalls, transport.operationCalls)
	}
}

func TestRecipientAcceptanceReconcilesExpiredUncertainOutcome(t *testing.T) {
	worker, inbound, transport := newAcceptanceWorkerForNegativeTest(t, nil)
	transport.operationErr = errTest("ambiguous network failure")
	if _, err := worker.Accept(context.Background(), inbound); err == nil {
		t.Fatal("ambiguous acceptance failure was accepted")
	}
	if transport.operationCalls != 1 || transport.operation.Operation != attachmentv3.PermitOperationAccept {
		t.Fatalf("initial operation=%+v calls=%d", transport.operation, transport.operationCalls)
	}
	worker.options.Now = func() time.Time { return time.Unix(125, 0).UTC() }
	worker.options.NewID = sequenceID(bytes16(93), bytes16(94))
	transport.operationErr = nil
	result, err := worker.Accept(context.Background(), inbound)
	if err != nil || result.State != attachmentv3.TransferStateAccepted {
		t.Fatalf("outcome result=%+v err=%v", result, err)
	}
	if transport.issueCalls != 2 || transport.operationCalls != 2 || transport.operation.Operation != attachmentv3.PermitOperationOutcome || transport.method != http.MethodGet {
		t.Fatalf("outcome was not used issue=%d operation=%d method=%s op=%+v", transport.issueCalls, transport.operationCalls, transport.method, transport.operation)
	}
}

func TestRecipientAcceptanceDoesNotExtendOutcomeBeyondOfferLifetime(t *testing.T) {
	worker, inbound, transport := newAcceptanceWorkerForNegativeTest(t, nil)
	// The accept can have committed at the relay even though its response was
	// lost. Its local record is therefore uncertain before the first lookup.
	transport.operationErr = errTest("accept response lost")
	if _, err := worker.Accept(context.Background(), inbound); err == nil {
		t.Fatal("ambiguous acceptance failure was accepted")
	}
	worker.options.Now = func() time.Time { return time.Unix(125, 0).UTC() }
	worker.options.NewID = sequenceID(bytes16(93), bytes16(94))
	transport.operationErr = errTest("outcome response lost")
	if _, err := worker.Accept(context.Background(), inbound); err == nil {
		t.Fatal("ambiguous outcome lookup was accepted")
	}
	if transport.issueCalls != 2 || transport.operationCalls != 2 || transport.operation.Operation != attachmentv3.PermitOperationOutcome {
		t.Fatalf("first outcome lookup was not attempted safely issue=%d calls=%d op=%+v", transport.issueCalls, transport.operationCalls, transport.operation)
	}
	firstOutcomeOperation := transport.operation
	// Once the offer itself expires, the worker must not mint a new lookup
	// capability. Extending its authority beyond the signed offer lifetime
	// would turn a transient relay outage into a post-expiry read capability.
	worker.options.Now = func() time.Time { return time.Unix(131, 0).UTC() }
	worker.options.NewID = sequenceID(bytes16(95), bytes16(96))
	transport.operationErr = nil
	if _, err := worker.Accept(context.Background(), inbound); err == nil {
		t.Fatal("outcome authority was extended past the offer lifetime")
	}
	if transport.issueCalls != 2 || transport.operationCalls != 2 || transport.operation != firstOutcomeOperation {
		t.Fatalf("post-expiry outcome reached transport issue=%d calls=%d op=%+v first=%+v", transport.issueCalls, transport.operationCalls, transport.operation, firstOutcomeOperation)
	}
}

func TestRecipientAcceptanceRejectsOutcomePermitForAnotherTransferBeforeTransport(t *testing.T) {
	worker, inbound, transport := newAcceptanceWorkerForNegativeTest(t, nil)
	transport.operationErr = errTest("accept response lost")
	if _, err := worker.Accept(context.Background(), inbound); err == nil {
		t.Fatal("ambiguous acceptance failure was accepted")
	}
	worker.options.Now = func() time.Time { return time.Unix(125, 0).UTC() }
	worker.options.NewID = sequenceID(bytes16(93), bytes16(94))
	transport.operationErr = nil
	transport.wrongTransfer = true
	if _, err := worker.Accept(context.Background(), inbound); err == nil {
		t.Fatal("foreign outcome permit was accepted")
	}
	if transport.issueCalls != 2 || transport.operationCalls != 1 {
		t.Fatalf("foreign outcome permit reached attachment transport issue=%d calls=%d", transport.issueCalls, transport.operationCalls)
	}
}

func TestRecipientAcceptanceRejectsOutcomeAcceptedResultAtDownloadAttempt(t *testing.T) {
	worker, inbound, transport := newAcceptanceWorkerForNegativeTest(t, nil)
	notice, err := attachmentv3.DecodeOfferNotice(inbound.Body)
	if err != nil {
		t.Fatal(err)
	}
	transport.operationErr = errTest("accept response lost")
	if _, err := worker.Accept(context.Background(), inbound); err == nil {
		t.Fatal("ambiguous acceptance failure was accepted")
	}
	worker.options.Now = func() time.Time { return time.Unix(125, 0).UTC() }
	worker.options.NewID = sequenceID(bytes16(93), bytes16(94))
	transport.operationErr = nil
	transport.result = acceptedTransferResultWithAttempt(t, notice.Manifest.TransferID, blake3.Sum256(notice.ManifestRaw), 120, 1)
	if _, err := worker.Accept(context.Background(), inbound); err == nil {
		t.Fatal("outcome accepted at attempt one")
	}
}

type changedAcceptanceSigner struct{ RecipientOperationSigner }

func (changedAcceptanceSigner) SignReceiptPermit(*attachmentv3.PermitRequest) error { return nil }
func (changedAcceptanceSigner) BuildReceiptOperation(attachmentv3.Permit, string, string, []byte, [16]byte, [32]byte, uint64, uint64) (attachmentv3.OperationRecord, error) {
	return attachmentv3.OperationRecord{}, errTest("changed operation")
}

func newAcceptanceWorkerForNegativeTest(t *testing.T, override RecipientOperationSigner) (*RecipientAcceptanceWorker, InboundOffer, *acceptanceTransportStub) {
	t.Helper()
	recipient := RecipientIdentity{DeviceID: bytes16(3), Generation: 1}
	journal, err := OpenJournalForRecipient(filepath.Join(t.TempDir(), "private", "controller.db"), recipient)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	mapping := Mapping{RelayConversationID: "relay-conversation", ConversationID: bytes16(1), SenderDeviceID: bytes16(2), SenderGeneration: 1, RecipientDeviceID: bytes16(3), RecipientGeneration: 1, MembershipCommitment: bytes32(4)}
	if err := journal.AddMapping(mapping); err != nil {
		t.Fatal(err)
	}
	inbound := InboundOffer{PunaroMessageID: "message-1", RelayConversationID: mapping.RelayConversationID, Body: testOfferNoticeWith(t, mapping, bytes16(6), 100, 130)}
	if _, _, err := journal.RecordInboundOffer(inbound); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0).UTC()
	if ok, err := journal.ApproveInboundOffer(inbound.PunaroMessageID, now); err != nil || !ok {
		t.Fatal(err)
	}
	notice, err := attachmentv3.DecodeOfferNotice(inbound.Body)
	if err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer := RecipientOperationSigner(NewLocalRecipientOperationSigner(recipient, private))
	if override != nil {
		signer = override
	}
	transport := &acceptanceTransportStub{result: acceptedTransferResult(t, notice.Manifest.TransferID, blake3.Sum256(notice.ManifestRaw), 120)}
	worker, err := NewRecipientAcceptanceWorker(RecipientAcceptanceWorkerOptions{Journal: journal, AuthorityProvider: testAcceptanceAuthority(t, mapping, private), Signer: signer, Transport: transport, Now: func() time.Time { return now }, NewID: sequenceID(bytes16(90), bytes16(91)), NewIdempotencyKey: func() ([32]byte, error) { return bytes32(92), nil }})
	if err != nil {
		t.Fatal(err)
	}
	return worker, inbound, transport
}

func TestRecipientAcceptanceWorkerSerializesConcurrentLocalAccepts(t *testing.T) {
	journal, err := OpenJournalForRecipient(filepath.Join(t.TempDir(), "private", "controller.db"), RecipientIdentity{DeviceID: bytes16(3), Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = journal.Close() }()
	mapping := Mapping{RelayConversationID: "relay-conversation", ConversationID: bytes16(1), SenderDeviceID: bytes16(2), SenderGeneration: 1, RecipientDeviceID: bytes16(3), RecipientGeneration: 1, MembershipCommitment: bytes32(4)}
	if err := journal.AddMapping(mapping); err != nil {
		t.Fatal(err)
	}
	inbound := InboundOffer{PunaroMessageID: "message-1", RelayConversationID: mapping.RelayConversationID, Body: testOfferNotice(t, mapping)}
	if _, _, err := journal.RecordInboundOffer(inbound); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0).UTC()
	if approved, err := journal.ApproveInboundOffer(inbound.PunaroMessageID, now); err != nil || !approved {
		t.Fatalf("approved=%t err=%v", approved, err)
	}
	notice, err := attachmentv3.DecodeOfferNotice(inbound.Body)
	if err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	transport := &acceptanceTransportStub{result: acceptedTransferResult(t, notice.Manifest.TransferID, blake3.Sum256(notice.ManifestRaw), 120)}
	worker, err := NewRecipientAcceptanceWorker(RecipientAcceptanceWorkerOptions{Journal: journal, AuthorityProvider: testAcceptanceAuthority(t, mapping, private), Signer: NewLocalRecipientOperationSigner(RecipientIdentity{DeviceID: bytes16(3), Generation: 1}, private), Transport: transport, Now: func() time.Time { return now }, NewID: sequenceID(bytes16(90), bytes16(91)), NewIdempotencyKey: func() ([32]byte, error) { return bytes32(92), nil }})
	if err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 2)
	var group sync.WaitGroup
	for range 2 {
		group.Add(1)
		go func() { defer group.Done(); _, err := worker.Accept(context.Background(), inbound); errCh <- err }()
	}
	group.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	if transport.issueCalls != 1 || transport.operationCalls != 1 {
		t.Fatalf("concurrent acceptance was not serialized issue=%d operation=%d", transport.issueCalls, transport.operationCalls)
	}
}

func TestReceiptAcceptanceCredentialsConvergeAcrossJournalProcesses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "controller.db")
	recipient := RecipientIdentity{DeviceID: bytes16(3), Generation: 1}
	first, err := OpenJournalForRecipient(path, recipient)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	second, err := OpenJournalForRecipient(path, recipient)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	mapping := Mapping{RelayConversationID: "relay-conversation", ConversationID: bytes16(1), SenderDeviceID: bytes16(2), SenderGeneration: 1, RecipientDeviceID: bytes16(3), RecipientGeneration: 1, MembershipCommitment: bytes32(4)}
	if err := first.AddMapping(mapping); err != nil {
		t.Fatal(err)
	}
	inbound := InboundOffer{PunaroMessageID: "message-1", RelayConversationID: mapping.RelayConversationID, Body: testOfferNotice(t, mapping)}
	if _, _, err := first.RecordInboundOffer(inbound); err != nil {
		t.Fatal(err)
	}
	notice, err := attachmentv3.DecodeOfferNotice(inbound.Body)
	if err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer := NewLocalRecipientOperationSigner(recipient, private)
	now := time.Unix(100, 0).UTC()
	record, err := first.ensureReceiptAcceptance(inbound.PunaroMessageID, notice, mapping, now, signer, sequenceID(bytes16(90), bytes16(91)), func() ([32]byte, error) { return bytes32(92), nil })
	if err != nil {
		t.Fatal(err)
	}
	makeCredential := func(serial byte) (attachmentv3.Permit, attachmentv3.OperationRecord) {
		permit := attachmentv3.Permit{Audience: bytes32(5), Serial: bytes16(serial), IssuerKeyID: bytes32(81), HolderDeviceID: record.request.HolderDeviceID, HolderGeneration: record.request.HolderGeneration, HolderRole: record.request.HolderRole, TransferID: record.request.TransferID, ConversationID: record.request.ConversationID, SenderDeviceID: record.request.SenderDeviceID, SenderGeneration: record.request.SenderGeneration, RecipientDeviceID: record.request.RecipientDeviceID, RecipientGeneration: record.request.RecipientGeneration, Operation: record.request.Operation, DirectoryHead: bytes32(7), MembershipCommitment: record.request.MembershipCommitment, RevocationEpoch: 1, IssuedAt: record.request.IssuedAt, ExpiresAt: record.request.ExpiresAt, MaxBytes: record.request.MaxBytes, MaxChunks: record.request.MaxChunks, MaxOperations: record.request.MaxOperations, StagedManifestCommitment: record.request.StagedManifestCommitment}
		op, err := signer.BuildReceiptOperation(permit, http.MethodPost, acceptancePath(permit.TransferID), record.acceptanceNonce[:], record.operationID, record.idempotencyKey, permit.IssuedAt, permit.ExpiresAt)
		if err != nil {
			t.Fatal(err)
		}
		return permit, op
	}
	permitA, opA := makeCredential(80)
	permitB, opB := makeCredential(81)
	type outcome struct {
		record receiptAcceptanceRecord
		err    error
	}
	results := make(chan outcome, 2)
	go func() {
		r, err := first.storeReceiptAcceptanceCredentials(record.messageID, permitA, opA)
		results <- outcome{r, err}
	}()
	go func() {
		r, err := second.storeReceiptAcceptanceCredentials(record.messageID, permitB, opB)
		results <- outcome{r, err}
	}()
	left, right := <-results, <-results
	if left.err != nil || right.err != nil || !bytes.Equal(left.record.permit, right.record.permit) || !bytes.Equal(left.record.operation, right.record.operation) {
		t.Fatalf("cross-process credentials diverged left=%v right=%v", left.err, right.err)
	}
}

func TestRecipientAcceptanceWorkersConvergeAcrossJournalProcesses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "controller.db")
	recipient := RecipientIdentity{DeviceID: bytes16(3), Generation: 1}
	first, err := OpenJournalForRecipient(path, recipient)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	second, err := OpenJournalForRecipient(path, recipient)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	mapping := Mapping{RelayConversationID: "relay-conversation", ConversationID: bytes16(1), SenderDeviceID: bytes16(2), SenderGeneration: 1, RecipientDeviceID: bytes16(3), RecipientGeneration: 1, MembershipCommitment: bytes32(4)}
	if err := first.AddMapping(mapping); err != nil {
		t.Fatal(err)
	}
	inbound := InboundOffer{PunaroMessageID: "message-1", RelayConversationID: mapping.RelayConversationID, Body: testOfferNotice(t, mapping)}
	if _, _, err := first.RecordInboundOffer(inbound); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0).UTC()
	if approved, err := first.ApproveInboundOffer(inbound.PunaroMessageID, now); err != nil || !approved {
		t.Fatalf("approved=%t err=%v", approved, err)
	}
	notice, err := attachmentv3.DecodeOfferNotice(inbound.Body)
	if err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	result := acceptedTransferResult(t, notice.Manifest.TransferID, blake3.Sum256(notice.ManifestRaw), 120)
	newWorker := func(journal *Journal, transport *acceptanceTransportStub) *RecipientAcceptanceWorker {
		worker, err := NewRecipientAcceptanceWorker(RecipientAcceptanceWorkerOptions{Journal: journal, AuthorityProvider: testAcceptanceAuthority(t, mapping, private), Signer: NewLocalRecipientOperationSigner(recipient, private), Transport: transport, Now: func() time.Time { return now }, NewID: sequenceID(bytes16(90), bytes16(91)), NewIdempotencyKey: func() ([32]byte, error) { return bytes32(92), nil }})
		if err != nil {
			t.Fatal(err)
		}
		return worker
	}
	leftTransport := &acceptanceTransportStub{result: result, serial: 80, acceptAnyPermit: true}
	rightTransport := &acceptanceTransportStub{result: result, serial: 81, acceptAnyPermit: true}
	left, right := newWorker(first, leftTransport), newWorker(second, rightTransport)
	errCh := make(chan error, 2)
	go func() { _, err := left.Accept(context.Background(), inbound); errCh <- err }()
	go func() { _, err := right.Accept(context.Background(), inbound); errCh <- err }()
	for range 2 {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
	if leftTransport.operationCalls+rightTransport.operationCalls < 1 || leftTransport.operationCalls+rightTransport.operationCalls > 2 {
		t.Fatalf("unexpected cross-process operation count left=%d right=%d", leftTransport.operationCalls, rightTransport.operationCalls)
	}
	if leftTransport.operationCalls == 1 && rightTransport.operationCalls == 1 && leftTransport.operation != rightTransport.operation {
		t.Fatalf("cross-process workers used divergent operations left=%+v right=%+v", leftTransport.operation, rightTransport.operation)
	}
}

type acceptanceTransportStub struct {
	request         attachmentv3.PermitRequest
	permit          attachmentv3.Permit
	operation       attachmentv3.OperationRecord
	method, path    string
	body            []byte
	result          []byte
	operationErr    error
	operations      []attachmentv3.OperationRecord
	serial          byte
	acceptAnyPermit bool
	badPermit       bool
	wrongTransfer   bool
	issueCalls      int
	operationCalls  int
}

type acceptanceAuthorityProviderStub struct{ authority RecipientAcceptanceAuthority }

func (p acceptanceAuthorityProviderStub) ResolveRecipientAcceptanceAuthority(context.Context, time.Time) (RecipientAcceptanceAuthority, error) {
	return p.authority, nil
}

type acceptanceAuthorityStub struct {
	*bindingResolverStub
	offerDirectoryStub
	issuer, holder ed25519.PublicKey
}

func (a acceptanceAuthorityStub) ValidatePermitAuthority(attachmentv3.Permit, time.Time) (ed25519.PublicKey, error) {
	return a.issuer, nil
}
func (a acceptanceAuthorityStub) CurrentDeviceSigningKey([16]byte, uint64) (ed25519.PublicKey, error) {
	return a.holder, nil
}
func testAcceptanceAuthority(t *testing.T, mapping Mapping, holder ed25519.PrivateKey) RecipientAcceptanceAuthorityProvider {
	issuer, _ := testOfferSigner()
	return acceptanceAuthorityProviderStub{authority: acceptanceAuthorityStub{bindingResolverStub: &bindingResolverStub{binding: testCurrentBinding(mapping, 130)}, offerDirectoryStub: testOfferDirectory(t), issuer: issuer, holder: holder.Public().(ed25519.PublicKey)}}
}

func (s *acceptanceTransportStub) IssueV3Permit(_ context.Context, request attachmentv3.PermitRequest) (attachmentv3.Permit, error) {
	s.issueCalls++
	s.request = request
	serial := s.serial
	if serial == 0 {
		serial = 80
	}
	s.permit = attachmentv3.Permit{Audience: bytes32(5), Serial: bytes16(serial), IssuerKeyID: bytes32(81), HolderDeviceID: request.HolderDeviceID, HolderGeneration: request.HolderGeneration, HolderRole: request.HolderRole, TransferID: request.TransferID, ConversationID: request.ConversationID, SenderDeviceID: request.SenderDeviceID, SenderGeneration: request.SenderGeneration, RecipientDeviceID: request.RecipientDeviceID, RecipientGeneration: request.RecipientGeneration, AttemptGeneration: request.AttemptGeneration, Operation: request.Operation, DirectoryHead: bytes32(7), MembershipCommitment: request.MembershipCommitment, RevocationEpoch: 1, IssuedAt: request.IssuedAt, ExpiresAt: request.ExpiresAt, MaxBytes: request.MaxBytes, MaxChunks: request.MaxChunks, MaxOperations: request.MaxOperations, StagedManifestCommitment: request.StagedManifestCommitment, OutcomeOfSerial: request.OutcomeOfSerial}
	if s.wrongTransfer {
		s.permit.TransferID = bytes16(99)
	}
	_, issuer := testOfferSigner()
	if err := attachmentv3.SignPermit(&s.permit, issuer); err != nil {
		return attachmentv3.Permit{}, err
	}
	if s.badPermit {
		s.permit.Signature[0] ^= 1
	}
	return s.permit, nil
}

func (s *acceptanceTransportStub) DoV3Attachment(_ context.Context, method, path string, body []byte, permit attachmentv3.Permit, operation attachmentv3.OperationRecord) ([]byte, error) {
	s.operationCalls++
	s.method, s.path, s.body, s.operation = method, path, append([]byte(nil), body...), operation
	s.operations = append(s.operations, operation)
	if !s.acceptAnyPermit && permit != s.permit {
		return nil, errTest("changed permit")
	}
	if s.operationErr != nil {
		return nil, s.operationErr
	}
	return append([]byte(nil), s.result...), nil
}

func acceptedTransferResult(t *testing.T, transfer [16]byte, commitment [32]byte, expires int64) []byte {
	return acceptedTransferResultWithAttempt(t, transfer, commitment, expires, 0)
}
func acceptedTransferResultWithAttempt(t *testing.T, transfer [16]byte, commitment [32]byte, expires int64, attempt uint64) []byte {
	t.Helper()
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := mode.Marshal(map[uint64]any{1: uint64(3), 2: transfer, 3: commitment, 4: uint64(attachmentv3.TransferStateAccepted), 5: attempt, 6: expires})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type testError string

func (e testError) Error() string { return string(e) }
func errTest(value string) error  { return testError(value) }

func sequenceID(values ...[16]byte) func() ([16]byte, error) {
	position := 0
	return func() ([16]byte, error) {
		if position >= len(values) {
			return [16]byte{}, errTest("unexpected random identity")
		}
		value := values[position]
		position++
		return value, nil
	}
}
