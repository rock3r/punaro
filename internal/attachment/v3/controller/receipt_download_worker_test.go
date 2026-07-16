package controller

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
	"github.com/zeebo/blake3"
)

func TestRecipientDownloadWorkerPersistsVerifiedCiphertextAndPublishesAfterCompletion(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	recipient := RecipientIdentity{DeviceID: bytes16(3), Generation: 1}
	mapping := Mapping{RelayConversationID: "relay-conversation", ConversationID: bytes16(1), SenderDeviceID: bytes16(2), SenderGeneration: 1, RecipientDeviceID: recipient.DeviceID, RecipientGeneration: recipient.Generation, MembershipCommitment: bytes32(4)}
	plain := []byte("durable receipt")
	inbound, artifact, fileKey := encryptedInboundOffer(t, mapping, plain, now)
	noticeForArtifact, err := attachmentv3.DecodeOfferNotice(inbound.Body)
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := attachmentv3.OpenSourceArtifact(noticeForArtifact.ManifestRaw, artifact.Chunks, fileKey, testOfferDirectory(t), now); err != nil || !bytes.Equal(opened, plain) {
		t.Fatalf("test artifact open=%q err=%v", opened, err)
	}
	notice, err := attachmentv3.DecodeOfferNotice(inbound.Body)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := OpenJournalForRecipient(filepath.Join(t.TempDir(), "private", "controller.db"), recipient)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = journal.Close() }()
	if err := journal.AddMapping(mapping); err != nil {
		t.Fatal(err)
	}
	if _, _, err := journal.RecordInboundOffer(inbound); err != nil {
		t.Fatal(err)
	}
	if approved, err := journal.ApproveInboundOffer(inbound.PunaroMessageID, now); err != nil || !approved {
		t.Fatalf("approved=%t err=%v", approved, err)
	}
	_, recipientPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	transport := &receiptDownloadTransport{acceptanceTransportStub: &acceptanceTransportStub{acceptAnyPermit: true}, accepted: acceptedTransferResult(t, notice.Manifest.TransferID, blake3.Sum256(notice.ManifestRaw), 120), transferring: receiptTransferResult(t, notice.Manifest.TransferID, blake3.Sum256(notice.ManifestRaw), attachmentv3.TransferStateTransferring, 120), completed: receiptTransferResult(t, notice.Manifest.TransferID, blake3.Sum256(notice.ManifestRaw), attachmentv3.TransferStateCompleted, 120), chunks: artifact.Chunks}
	authority := testAcceptanceAuthority(t, mapping, recipientPrivate)
	acceptance, err := NewRecipientAcceptanceWorker(RecipientAcceptanceWorkerOptions{Journal: journal, AuthorityProvider: authority, Signer: NewLocalRecipientOperationSigner(recipient, recipientPrivate), Transport: transport, Now: func() time.Time { return now }, NewID: sequenceID(bytes16(80), bytes16(81)), NewIdempotencyKey: func() ([32]byte, error) { return bytes32(82), nil }})
	if err != nil {
		t.Fatal(err)
	}
	hpkePrivate, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{91}, 32))
	if err != nil {
		t.Fatal(err)
	}
	worker, err := NewRecipientDownloadWorker(RecipientDownloadWorkerOptions{Acceptance: acceptance, AuthorityProvider: authority, Signer: NewLocalRecipientOperationSigner(recipient, recipientPrivate), Transport: transport, EnvelopeOpener: NewLocalRecipientEnvelopeOpener(hpkePrivate), Now: func() time.Time { return now }, NewID: sequenceID(bytes16(83), bytes16(84), bytes16(85), bytes16(86), bytes16(87), bytes16(88), bytes16(89), bytes16(90), bytes16(91), bytes16(92), bytes16(93), bytes16(94), bytes16(95), bytes16(96), bytes16(97), bytes16(98), bytes16(99), bytes16(100), bytes16(101), bytes16(102), bytes16(103), bytes16(104), bytes16(105), bytes16(106), bytes16(107), bytes16(108), bytes16(109), bytes16(110), bytes16(111), bytes16(112)), NewIdempotencyKey: sequenceReceiptKey(bytes32(83), bytes32(84), bytes32(85), bytes32(86), bytes32(87), bytes32(88), bytes32(89), bytes32(90), bytes32(91), bytes32(92), bytes32(93), bytes32(94), bytes32(95), bytes32(96), bytes32(97))})
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "receipt.bin")
	result, err := worker.Receive(context.Background(), inbound, destination)
	if err != nil || result.State != attachmentv3.TransferStateCompleted {
		record, _, recordErr := journal.receiptDownload(inbound.PunaroMessageID)
		stored, chunkErr := journal.receiptDownloadChunks(record, notice.Manifest.ChunkCount)
		opened, openErr := attachmentv3.OpenSourceArtifact(notice.ManifestRaw, stored, fileKey, testOfferDirectory(t), now)
		t.Fatalf("result=%+v err=%v calls=%d journal=%v chunks=%d chunkErr=%v open=%q openErr=%v permit=%+v operation=%+v", result, err, transport.operationCalls, recordErr, len(stored), chunkErr, opened, openErr, transport.permit, transport.operation)
	}
	// #nosec G304 -- destination is the test-controlled temporary output path.
	written, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(written, plain) {
		t.Fatalf("written=%q err=%v", written, err)
	}
	if info, err := os.Stat(destination); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v err=%v", info.Mode(), err)
	}
	calls := transport.operationCalls
	if _, err := worker.Receive(context.Background(), inbound, destination); err != nil {
		t.Fatal(err)
	}
	if transport.operationCalls != calls {
		t.Fatalf("completed receipt retried remotely: before=%d after=%d", calls, transport.operationCalls)
	}
	if _, err := worker.Receive(context.Background(), inbound, filepath.Join(t.TempDir(), "different.bin")); err == nil {
		t.Fatal("same message accepted a changed output destination")
	}
	if transport.operationCalls != calls {
		t.Fatalf("changed destination contacted relay: before=%d after=%d", calls, transport.operationCalls)
	}
	if fileKey == [32]byte{} {
		t.Fatal("test file key was lost")
	}
}

func TestReceiptCiphertextLengthAllowsEmptyArtifact(t *testing.T) {
	manifest := attachmentv3.Manifest{ChunkSize: 1, ChunkCount: 1, PlaintextSize: 0}
	if got, err := receiptCiphertextLength(manifest, 0); err != nil || got != 16 {
		t.Fatalf("length=%d err=%v", got, err)
	}
}

func TestRecipientDownloadRecoversLostChunkResponseAfterPermitExpiry(t *testing.T) {
	clock := time.Unix(100, 0).UTC()
	recipient := RecipientIdentity{DeviceID: bytes16(3), Generation: 1}
	mapping := Mapping{RelayConversationID: "recovery-relay", ConversationID: bytes16(1), SenderDeviceID: bytes16(2), SenderGeneration: 1, RecipientDeviceID: recipient.DeviceID, RecipientGeneration: recipient.Generation, MembershipCommitment: bytes32(4)}
	inbound, artifact, _ := encryptedInboundOffer(t, mapping, []byte("ok"), clock)
	notice, err := attachmentv3.DecodeOfferNotice(inbound.Body)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := OpenJournalForRecipient(filepath.Join(t.TempDir(), "private", "controller.db"), recipient)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = journal.Close() }()
	if err := journal.AddMapping(mapping); err != nil {
		t.Fatal(err)
	}
	if _, _, err := journal.RecordInboundOffer(inbound); err != nil {
		t.Fatal(err)
	}
	if approved, err := journal.ApproveInboundOffer(inbound.PunaroMessageID, clock); err != nil || !approved {
		t.Fatalf("approved=%t err=%v", approved, err)
	}
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	transport := &receiptDownloadTransport{acceptanceTransportStub: &acceptanceTransportStub{acceptAnyPermit: true, incrementSerial: true, permitExpiresAt: 105, shortDownloadPermits: true}, accepted: acceptedTransferResult(t, notice.Manifest.TransferID, blake3.Sum256(notice.ManifestRaw), 120), transferring: receiptTransferResult(t, notice.Manifest.TransferID, blake3.Sum256(notice.ManifestRaw), attachmentv3.TransferStateTransferring, 120), completed: receiptTransferResult(t, notice.Manifest.TransferID, blake3.Sum256(notice.ManifestRaw), attachmentv3.TransferStateCompleted, 120), chunks: artifact.Chunks, failDownloadOnce: true}
	authority := testAcceptanceAuthority(t, mapping, private)
	signer := NewLocalRecipientOperationSigner(recipient, private)
	acceptance, err := NewRecipientAcceptanceWorker(RecipientAcceptanceWorkerOptions{Journal: journal, AuthorityProvider: authority, Signer: signer, Transport: transport, Now: func() time.Time { return clock }, NewID: sequenceID(bytes16(120), bytes16(121)), NewIdempotencyKey: sequenceReceiptKey(bytes32(120), bytes32(121))})
	if err != nil {
		t.Fatal(err)
	}
	hpkePrivate, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{91}, 32))
	if err != nil {
		t.Fatal(err)
	}
	worker, err := NewRecipientDownloadWorker(RecipientDownloadWorkerOptions{Acceptance: acceptance, AuthorityProvider: authority, Signer: signer, Transport: transport, EnvelopeOpener: NewLocalRecipientEnvelopeOpener(hpkePrivate), Now: func() time.Time { return clock }, NewID: incrementingReceiptID(1), NewIdempotencyKey: incrementingReceiptKey(1)})
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "recovered.bin")
	if _, err := worker.Receive(context.Background(), inbound, destination); err == nil {
		t.Fatal("first receive unexpectedly succeeded")
	}
	clock = time.Unix(106, 0).UTC()
	result, err := worker.Receive(context.Background(), inbound, destination)
	if err != nil || result.State != attachmentv3.TransferStateCompleted {
		t.Fatalf("result=%+v err=%v permits=%d operations=%d", result, err, transport.issueCalls, transport.operationCalls)
	}
	// #nosec G304 -- destination is a test-controlled temporary output path.
	if got, err := os.ReadFile(destination); err != nil || !bytes.Equal(got, []byte("ok")) {
		t.Fatalf("output=%q err=%v", got, err)
	}
	if retry, found, err := journal.receiptDownloadRetryOperation(inbound.PunaroMessageID, receiptDownloadChunk, 0, 1); err != nil || !found || retry.attempt != 1 {
		t.Fatalf("retry=%+v found=%t err=%v", retry, found, err)
	}
	if transport.outcomePermit.OutcomeOfSerial != transport.lostDownloadPermit.Serial {
		t.Fatalf("outcome serial=%x lost serial=%x", transport.outcomePermit.OutcomeOfSerial, transport.lostDownloadPermit.Serial)
	}
	if transport.outcomePermit.Serial == transport.lostDownloadPermit.Serial || transport.retryDownloadPermit.Serial == transport.lostDownloadPermit.Serial {
		t.Fatalf("recovery reused original serial outcome=%x retry=%x original=%x", transport.outcomePermit.Serial, transport.retryDownloadPermit.Serial, transport.lostDownloadPermit.Serial)
	}
}

// A lost download response must never cause the original one-use operation to
// be overwritten. The recovered fetch receives a separately durable identity
// so a second lost response can itself be reconciled.
func TestReceiptDownloadRetryOperationRetainsOriginalCapability(t *testing.T) {
	recipient := RecipientIdentity{DeviceID: bytes16(3), Generation: 1}
	journal, err := OpenJournalForRecipient(filepath.Join(t.TempDir(), "private", "controller.db"), recipient)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = journal.Close() }()
	mapping := Mapping{RelayConversationID: "retry-relay", ConversationID: bytes16(1), SenderDeviceID: bytes16(2), SenderGeneration: 1, RecipientDeviceID: bytes16(3), RecipientGeneration: 1, MembershipCommitment: bytes32(4)}
	inbound, _, _ := encryptedInboundOffer(t, mapping, []byte("retry"), time.Unix(100, 0).UTC())
	notice, err := attachmentv3.DecodeOfferNotice(inbound.Body)
	if err != nil {
		t.Fatal(err)
	}
	record := receiptDownloadRecord{messageID: "retry-message", transferID: notice.Manifest.TransferID, manifest: notice.ManifestRaw, envelope: notice.EnvelopeRaw, outputPath: "/tmp/receipt", manifestCommitment: blake3.Sum256(notice.ManifestRaw), state: receiptDownloadActive}
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	original := receiptDownloadOperation{phase: receiptDownloadChunk, chunk: 0, request: attachmentv3.PermitRequest{RequestID: bytes16(10), HolderDeviceID: recipient.DeviceID, HolderGeneration: recipient.Generation, HolderRole: attachmentv3.PermitHolderRecipient, TransferID: record.transferID, ConversationID: mapping.ConversationID, SenderDeviceID: mapping.SenderDeviceID, SenderGeneration: mapping.SenderGeneration, RecipientDeviceID: mapping.RecipientDeviceID, RecipientGeneration: mapping.RecipientGeneration, AttemptGeneration: 1, Operation: attachmentv3.PermitOperationDownload, MembershipCommitment: mapping.MembershipCommitment, StagedManifestCommitment: record.manifestCommitment, IssuedAt: 90, ExpiresAt: 110, MaxBytes: 20, MaxChunks: 1, MaxOperations: 1}, operationID: bytes16(11), idempotencyKey: bytes32(12), permit: []byte{3}, operation: []byte{4}}
	if err := attachmentv3.SignPermitRequest(&original.request, private); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.db.ExecContext(context.Background(), `PRAGMA foreign_keys=OFF`); err != nil {
		t.Fatal(err)
	}
	if err := journal.insertReceiptDownloadOperationForTest(record, original); err != nil {
		t.Fatal(err)
	}
	retry, err := journal.newReceiptDownloadRetryOperation(record, original, time.Unix(100, 0), func(request *attachmentv3.PermitRequest) error {
		return attachmentv3.SignPermitRequest(request, private)
	}, sequenceID(bytes16(13), bytes16(15)), func() ([32]byte, error) { return bytes32(14), nil })
	if err != nil {
		t.Fatal(err)
	}
	if retry.attempt != 1 || retry.operationID != bytes16(15) || retry.idempotencyKey != bytes32(14) {
		t.Fatalf("retry=%+v", retry)
	}
	if stored, found, err := journal.receiptDownloadOperation(record.messageID, receiptDownloadChunk, 0); err != nil || !found || stored.operationID != original.operationID || !bytes.Equal(stored.permit, original.permit) {
		t.Fatalf("original changed: stored=%+v found=%t err=%v", stored, found, err)
	}
}

func (j *Journal) insertReceiptDownloadOperationForTest(record receiptDownloadRecord, operation receiptDownloadOperation) error {
	raw, err := attachmentv3.EncodePermitRequest(operation.request)
	if err != nil {
		return err
	}
	if _, err := j.db.ExecContext(context.Background(), `INSERT INTO controller_receipt_downloads(punaro_message_id,transfer_id,manifest,envelope,output_path,manifest_commitment,state) VALUES(?,?,?,?,?,?,?)`, record.messageID, record.transferID[:], record.manifest, record.envelope, record.outputPath, record.manifestCommitment[:], record.state); err != nil {
		return err
	}
	_, err = j.db.ExecContext(context.Background(), `INSERT INTO controller_receipt_download_operations(punaro_message_id,phase,chunk_index,permit_request,operation_id,idempotency_key,permit,operation) VALUES(?,?,?,?,?,?,?,?)`, record.messageID, string(operation.phase), operation.chunk, raw, operation.operationID[:], operation.idempotencyKey[:], operation.permit, operation.operation)
	return err
}

type receiptDownloadTransport struct {
	*acceptanceTransportStub
	accepted, transferring, completed                      []byte
	chunks                                                 []attachmentv3.EncryptedChunk
	failDownloadOnce                                       bool
	lostDownloadPermit, retryDownloadPermit, outcomePermit attachmentv3.Permit
}

func (s *receiptDownloadTransport) DoV3Attachment(ctx context.Context, method, path string, body []byte, permit attachmentv3.Permit, operation attachmentv3.OperationRecord) ([]byte, error) {
	switch permit.Operation {
	case attachmentv3.PermitOperationAccept:
		s.result = s.accepted
	case attachmentv3.PermitOperationBegin:
		s.result = s.transferring
	case attachmentv3.PermitOperationDownload:
		if s.failDownloadOnce {
			s.failDownloadOnce = false
			s.lostDownloadPermit = permit
			// The relay commits the fenced download before the caller loses its
			// response. Preserve that ordering in the fake rather than merely
			// returning an early local error.
			s.result = nil
			for _, candidate := range s.chunks {
				if path == fmt.Sprintf("/v3/attachments/%x/chunks/%d", permit.TransferID, candidate.Index) {
					s.result = candidate.Ciphertext
					break
				}
			}
			if _, err := s.acceptanceTransportStub.DoV3Attachment(ctx, method, path, body, permit, operation); err != nil {
				return nil, err
			}
			return nil, errTest("lost committed download response")
		}
		if s.lostDownloadPermit.Serial != [16]byte{} {
			s.retryDownloadPermit = permit
		}
		if operation.Operation != attachmentv3.PermitOperationDownload || len(s.chunks) == 0 {
			return nil, errTest("missing test ciphertext")
		}
		for _, candidate := range s.chunks {
			if path == fmt.Sprintf("/v3/attachments/%x/chunks/%d", permit.TransferID, candidate.Index) {
				s.result = candidate.Ciphertext
				return s.acceptanceTransportStub.DoV3Attachment(ctx, method, path, body, permit, operation)
			}
		}
		return nil, errTest("invalid test chunk route")
	case attachmentv3.PermitOperationComplete:
		s.result = s.completed
	case attachmentv3.PermitOperationOutcome:
		s.outcomePermit = permit
		s.result = s.transferring
	default:
		return nil, errTest("unexpected receipt operation")
	}
	return s.acceptanceTransportStub.DoV3Attachment(ctx, method, path, body, permit, operation)
}

func encryptedInboundOffer(t *testing.T, mapping Mapping, plain []byte, now time.Time) (InboundOffer, attachmentv3.SourceArtifact, [32]byte) {
	t.Helper()
	_, sender := testOfferSigner()
	manifest := attachmentv3.Manifest{Audience: bytes32(5), TransferID: bytes16(6), ConversationID: mapping.ConversationID, SenderDeviceID: mapping.SenderDeviceID, SenderGeneration: mapping.SenderGeneration, RecipientDeviceID: mapping.RecipientDeviceID, RecipientGeneration: mapping.RecipientGeneration, DirectoryHead: bytes32(7), MembershipCommitment: mapping.MembershipCommitment, RevocationEpoch: 1, IssuedAt: uint64(now.Unix()), ExpiresAt: uint64(now.Add(20 * time.Second).Unix()), ChunkSize: 4, SignerKeyID: bytes32(10)}
	privateDir := filepath.Join(t.TempDir(), "artifact-private")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := attachmentv3.OpenArtifactStore(filepath.Join(privateDir, "artifact.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	prepared, commitment, err := attachmentv3.PrepareSourceManifest(plain, manifest, sender, attachmentv3.SourceArtifactMaterial{FileKey: bytes32(71), ContentSalt: bytes32(72)})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := attachmentv3.EncryptPreparedSourceArtifact(plain, prepared, commitment, bytes32(71), store)
	if err != nil {
		t.Fatal(err)
	}
	rawManifest, err := attachmentv3.EncodeManifest(prepared)
	if err != nil {
		t.Fatal(err)
	}
	directory := testOfferDirectory(t)
	source, err := attachmentv3.DecodeAndVerifySourceInit(rawManifest, directory, now)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := attachmentv3.SealRecipientEnvelope(source, directory, bytes32(71), sender, now)
	if err != nil {
		t.Fatal(err)
	}
	rawOffer, err := attachmentv3.EncodeOfferPayload(prepared, envelope, bytes32(73))
	if err != nil {
		t.Fatal(err)
	}
	body, err := attachmentv3.EncodeOfferNotice(rawOffer)
	if err != nil {
		t.Fatal(err)
	}
	return InboundOffer{PunaroMessageID: "message-encrypted", RelayConversationID: mapping.RelayConversationID, Body: body}, artifact, bytes32(71)
}

func receiptTransferResult(t *testing.T, transfer [16]byte, commitment [32]byte, state attachmentv3.TransferState, expires int64) []byte {
	t.Helper()
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := mode.Marshal(map[uint64]any{1: uint64(3), 2: transfer, 3: commitment, 4: uint64(state), 5: uint64(1), 6: expires})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func sequenceReceiptKey(values ...[32]byte) func() ([32]byte, error) {
	position := 0
	return func() ([32]byte, error) {
		if position >= len(values) {
			return [32]byte{}, errTest("unexpected test idempotency key")
		}
		value := values[position]
		position++
		return value, nil
	}
}

func incrementingReceiptID(start byte) func() ([16]byte, error) {
	n := start
	return func() ([16]byte, error) { value := bytes16(n); n++; return value, nil }
}

func incrementingReceiptKey(start byte) func() ([32]byte, error) {
	n := start
	return func() ([32]byte, error) { value := bytes32(n); n++; return value, nil }
}
