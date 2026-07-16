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
	defer journal.Close()
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

type receiptDownloadTransport struct {
	*acceptanceTransportStub
	accepted, transferring, completed []byte
	chunks                            []attachmentv3.EncryptedChunk
}

func (s *receiptDownloadTransport) DoV3Attachment(ctx context.Context, method, path string, body []byte, permit attachmentv3.Permit, operation attachmentv3.OperationRecord) ([]byte, error) {
	switch permit.Operation {
	case attachmentv3.PermitOperationAccept:
		s.result = s.accepted
	case attachmentv3.PermitOperationBegin:
		s.result = s.transferring
	case attachmentv3.PermitOperationDownload:
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
		s.acceptanceTransportStub.result = s.completed
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
