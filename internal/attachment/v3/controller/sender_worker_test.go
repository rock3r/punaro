package controller

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
	"github.com/zeebo/blake3"
)

func TestSenderSourceInitializerPersistsExactCredentialsBeforeSubmission(t *testing.T) {
	journal, err := OpenJournal(filepath.Join(t.TempDir(), "private", "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = journal.Close() }()
	mapping := Mapping{RelayConversationID: "relay-conversation", ConversationID: bytes16(1), SenderDeviceID: bytes16(2), SenderGeneration: 1, RecipientDeviceID: bytes16(3), RecipientGeneration: 1, MembershipCommitment: bytes32(4)}
	if err := journal.AddMapping(mapping); err != nil {
		t.Fatal(err)
	}
	_, senderPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0).UTC()
	manifest, raw := stagedSenderManifest(t, mapping, senderPrivate, now)
	if err := insertStagedSenderTransfer(journal, mapping, manifest, raw); err != nil {
		t.Fatal(err)
	}
	transport := &senderTransportStub{result: sourceUploadingTransferResult(t, manifest.TransferID, attachmentCommitment(t, raw), int64(manifest.ExpiresAt))}
	authority := testSenderAuthority(t, mapping, senderPrivate)
	worker, err := NewSenderSourceInitializer(SenderSourceInitializerOptions{
		Journal: journal, AuthorityProvider: senderAuthorityProviderStub{authority: authority}, Signer: NewLocalSenderOperationSigner(SenderIdentity{DeviceID: mapping.SenderDeviceID, Generation: mapping.SenderGeneration}, senderPrivate), Transport: transport,
		Now: func() time.Time { return now }, NewID: sequenceID(bytes16(70), bytes16(71)), NewIdempotencyKey: sequenceKey(bytes32(72)),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := worker.Initialize(context.Background(), manifest.TransferID)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != attachmentv3.TransferStateSourceUploading || transport.method != http.MethodPost || transport.path != sourceInitPath(manifest.TransferID) || string(transport.body) != string(raw) {
		t.Fatalf("result=%+v request=%s %s", result, transport.method, transport.path)
	}
	var permit, operation, storedResult []byte
	if err := journal.db.QueryRow(`SELECT permit,operation,result FROM controller_sender_operations WHERE transfer_id=? AND phase='source-init' AND chunk_index=0`, manifest.TransferID[:]).Scan(&permit, &operation, &storedResult); err != nil || len(permit) == 0 || len(operation) == 0 || string(storedResult) != string(transport.result) {
		t.Fatalf("credentials/result durable permit=%d operation=%d result=%d err=%v", len(permit), len(operation), len(storedResult), err)
	}
	if transport.issueCalls != 1 || transport.operationCalls != 1 {
		t.Fatalf("issue=%d operation=%d", transport.issueCalls, transport.operationCalls)
	}
	if _, err := worker.Initialize(context.Background(), manifest.TransferID); err != nil {
		t.Fatal(err)
	}
	if transport.issueCalls != 1 || transport.operationCalls != 1 {
		t.Fatalf("durable result replay issued=%d submitted=%d", transport.issueCalls, transport.operationCalls)
	}
}

func TestSenderSourceInitializerUploadsDurableChunksBeforeReady(t *testing.T) {
	journal, err := OpenJournal(filepath.Join(t.TempDir(), "private", "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = journal.Close() }()
	mapping := Mapping{RelayConversationID: "relay-conversation", ConversationID: bytes16(1), SenderDeviceID: bytes16(2), SenderGeneration: 1, RecipientDeviceID: bytes16(3), RecipientGeneration: 1, MembershipCommitment: bytes32(4)}
	if err := journal.AddMapping(mapping); err != nil {
		t.Fatal(err)
	}
	_, senderPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0).UTC()
	manifest, raw := stagedSenderManifest(t, mapping, senderPrivate, now)
	if err := insertStagedSenderTransfer(journal, mapping, manifest, raw); err != nil {
		t.Fatal(err)
	}
	ciphertext := bytes.Repeat([]byte{0xA5}, 17)
	chunkCommitment := senderCiphertextCommitment(ciphertext)
	if _, err := journal.db.Exec(`INSERT INTO controller_sender_chunks(transfer_id,chunk_index,ciphertext,ciphertext_commitment) VALUES(?,?,?,?)`, manifest.TransferID[:], 0, ciphertext, chunkCommitment[:]); err != nil {
		t.Fatal(err)
	}
	commitment := attachmentCommitment(t, raw)
	initPath := sourceInitPath(manifest.TransferID)
	uploadPath := fmt.Sprintf("/v3/attachments/%x/source/chunks/0", manifest.TransferID)
	transport := &senderTransportStub{results: map[string][]byte{initPath: sourceUploadingTransferResult(t, manifest.TransferID, commitment, int64(manifest.ExpiresAt)), uploadPath: sourceReadyTransferResult(t, manifest.TransferID, commitment, int64(manifest.ExpiresAt))}}
	worker, err := NewSenderSourceInitializer(SenderSourceInitializerOptions{Journal: journal, AuthorityProvider: senderAuthorityProviderStub{authority: testSenderAuthority(t, mapping, senderPrivate)}, Signer: NewLocalSenderOperationSigner(SenderIdentity{DeviceID: mapping.SenderDeviceID, Generation: mapping.SenderGeneration}, senderPrivate), Transport: transport, Now: func() time.Time { return now }, NewID: sequenceID(bytes16(70), bytes16(71), bytes16(72), bytes16(73)), NewIdempotencyKey: sequenceKey(bytes32(74), bytes32(75))})
	if err != nil {
		t.Fatal(err)
	}
	result, err := worker.UploadAll(context.Background(), manifest.TransferID)
	if err != nil || result.State != attachmentv3.TransferStateSourceReady {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if transport.issueCalls != 2 || transport.operationCalls != 2 || transport.path != uploadPath || string(transport.body) != string(ciphertext) {
		t.Fatalf("issue=%d calls=%d last=%s body=%x", transport.issueCalls, transport.operationCalls, transport.path, transport.body)
	}
	var stored []byte
	if err := journal.db.QueryRow(`SELECT result FROM controller_sender_operations WHERE transfer_id=? AND phase='source-upload' AND chunk_index=0`, manifest.TransferID[:]).Scan(&stored); err != nil || string(stored) != string(transport.results[uploadPath]) {
		t.Fatalf("stored=%x err=%v", stored, err)
	}
}

func TestSenderOfferWorkerSealsAndPersistsOfferAfterUpload(t *testing.T) {
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
	_, senderPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0).UTC()
	binding := testCurrentBinding(mapping, 120)
	copy(binding.Sender.SigningPublicKey[:], senderPrivate.Public().(ed25519.PublicKey))
	protector := &senderKeyProtectorStub{}
	stager, err := NewSenderStager(SenderStageOptions{Journal: journal, ArtifactStore: store, BindingResolver: &bindingResolverStub{binding: binding}, Sender: SenderIdentity{DeviceID: mapping.SenderDeviceID, Generation: mapping.SenderGeneration}, SigningKey: senderPrivate, FileKeyProtector: protector, Now: func() time.Time { return now }, NewID: sequenceID(bytes16(60)), ChunkSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := stager.Stage(context.Background(), bytes16(59), mapping.RelayConversationID, []byte("a"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := attachmentv3.EncodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	commitment := attachmentCommitment(t, raw)
	initPath := sourceInitPath(manifest.TransferID)
	uploadPath := fmt.Sprintf("/v3/attachments/%x/source/chunks/0", manifest.TransferID)
	offerPath := fmt.Sprintf("/v3/attachments/%x/offer", manifest.TransferID)
	transport := &senderTransportStub{results: map[string][]byte{initPath: sourceUploadingTransferResult(t, manifest.TransferID, commitment, int64(manifest.ExpiresAt)), uploadPath: sourceReadyTransferResult(t, manifest.TransferID, commitment, int64(manifest.ExpiresAt)), offerPath: offeredTransferResult(t, manifest.TransferID, commitment, int64(manifest.ExpiresAt))}}
	signer := NewLocalSenderOperationSigner(SenderIdentity{DeviceID: mapping.SenderDeviceID, Generation: mapping.SenderGeneration}, senderPrivate)
	source, err := NewSenderSourceInitializer(SenderSourceInitializerOptions{Journal: journal, AuthorityProvider: senderAuthorityProviderStub{authority: testSenderAuthority(t, mapping, senderPrivate)}, Signer: signer, Transport: transport, Now: func() time.Time { return now }, NewID: sequenceID(bytes16(70), bytes16(71), bytes16(72), bytes16(73), bytes16(74), bytes16(75)), NewIdempotencyKey: sequenceKey(bytes32(76), bytes32(77), bytes32(78))})
	if err != nil {
		t.Fatal(err)
	}
	offerWorker, err := NewSenderOfferWorker(SenderOfferWorkerOptions{Source: source, FileKeyProtector: protector, NewAcceptanceNonce: func() ([32]byte, error) { return bytes32(79), nil }})
	if err != nil {
		t.Fatal(err)
	}
	result, err := offerWorker.Offer(context.Background(), manifest.TransferID)
	if err != nil || result.State != attachmentv3.TransferStateOffered {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	var offer []byte
	if err := journal.db.QueryRow(`SELECT offer FROM controller_sender_transfers WHERE transfer_id=?`, manifest.TransferID[:]).Scan(&offer); err != nil {
		t.Fatal(err)
	}
	noticeBody, err := attachmentv3.EncodeOfferNotice(offer)
	if err != nil {
		t.Fatal(err)
	}
	notice, err := attachmentv3.DecodeOfferNotice(noticeBody)
	if err != nil || notice.Manifest.TransferID != manifest.TransferID || transport.path != offerPath {
		t.Fatalf("notice=%+v path=%s err=%v", notice.Manifest, transport.path, err)
	}
	if _, err := offerWorker.Offer(context.Background(), manifest.TransferID); err != nil {
		t.Fatal(err)
	}
	if transport.issueCalls != 3 || transport.operationCalls != 3 {
		t.Fatalf("offer retry issued=%d called=%d", transport.issueCalls, transport.operationCalls)
	}
}

func stagedSenderManifest(t *testing.T, mapping Mapping, private ed25519.PrivateKey, now time.Time) (attachmentv3.Manifest, []byte) {
	t.Helper()
	binding := testCurrentBinding(mapping, 120)
	manifest := attachmentv3.Manifest{Audience: binding.Permit.Audience, TransferID: bytes16(61), ConversationID: mapping.ConversationID, SenderDeviceID: mapping.SenderDeviceID, SenderGeneration: mapping.SenderGeneration, RecipientDeviceID: mapping.RecipientDeviceID, RecipientGeneration: mapping.RecipientGeneration, DirectoryHead: binding.Permit.DirectoryHead, MembershipCommitment: mapping.MembershipCommitment, RevocationEpoch: binding.Permit.RevocationEpoch, IssuedAt: uint64(now.Unix()), ExpiresAt: binding.Permit.ExpiresAt, ContentSalt: bytes32(62), PlaintextCommitment: bytes32(63), ChunkSize: 1, ChunkCount: 1, PlaintextSize: 1, SignerKeyID: binding.Sender.SigningKeyID}
	if err := attachmentv3.SignManifest(&manifest, private); err != nil {
		t.Fatal(err)
	}
	raw, err := attachmentv3.EncodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return manifest, raw
}

func attachmentCommitment(t *testing.T, raw []byte) [32]byte { t.Helper(); return blake3.Sum256(raw) }

func insertStagedSenderTransfer(journal *Journal, mapping Mapping, manifest attachmentv3.Manifest, raw []byte) error {
	commitment := blake3.Sum256(raw)
	_, err := journal.db.Exec(`INSERT INTO controller_sender_transfers(transfer_id,relay_conversation_id,manifest,manifest_commitment,wrapped_file_key) VALUES(?,?,?,?,?)`, manifest.TransferID[:], mapping.RelayConversationID, raw, commitment[:], []byte("test-wrapped-key"))
	return err
}

type senderAuthorityProviderStub struct{ authority SenderDeliveryAuthority }

func (p senderAuthorityProviderStub) ResolveSenderDeliveryAuthority(context.Context, time.Time) (SenderDeliveryAuthority, error) {
	return p.authority, nil
}

type senderAuthorityStub struct {
	*bindingResolverStub
	offerDirectoryStub
	issuer, holder ed25519.PublicKey
}

func (a senderAuthorityStub) ValidatePermitAuthority(attachmentv3.Permit, time.Time) (ed25519.PublicKey, error) {
	return a.issuer, nil
}
func (a senderAuthorityStub) CurrentDeviceSigningKey(_ [16]byte, _ uint64) (ed25519.PublicKey, error) {
	return a.holder, nil
}

func testSenderAuthority(t *testing.T, mapping Mapping, sender ed25519.PrivateKey) SenderDeliveryAuthority {
	t.Helper()
	seed := bytes32(91)
	key, err := ecdh.X25519().NewPrivateKey(seed[:])
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := testOfferSigner()
	binding := testCurrentBinding(mapping, 120)
	copy(binding.Sender.SigningPublicKey[:], sender.Public().(ed25519.PublicKey))
	return senderAuthorityStub{bindingResolverStub: &bindingResolverStub{binding: binding}, offerDirectoryStub: offerDirectoryStub{signer: sender.Public().(ed25519.PublicKey), recipient: key.PublicKey()}, issuer: issuer, holder: sender.Public().(ed25519.PublicKey)}
}

type senderTransportStub struct {
	request                    attachmentv3.PermitRequest
	permit                     attachmentv3.Permit
	result                     []byte
	results                    map[string][]byte
	method, path               string
	body                       []byte
	issueCalls, operationCalls int
}

func (s *senderTransportStub) IssueV3Permit(_ context.Context, request attachmentv3.PermitRequest) (attachmentv3.Permit, error) {
	s.issueCalls++
	s.request = request
	s.permit = attachmentv3.Permit{Audience: bytes32(31), Serial: bytes16(80), IssuerKeyID: bytes32(81), HolderDeviceID: request.HolderDeviceID, HolderGeneration: request.HolderGeneration, HolderRole: request.HolderRole, TransferID: request.TransferID, ConversationID: request.ConversationID, SenderDeviceID: request.SenderDeviceID, SenderGeneration: request.SenderGeneration, RecipientDeviceID: request.RecipientDeviceID, RecipientGeneration: request.RecipientGeneration, AttemptGeneration: request.AttemptGeneration, Operation: request.Operation, DirectoryHead: bytes32(32), MembershipCommitment: request.MembershipCommitment, RevocationEpoch: 1, IssuedAt: request.IssuedAt, ExpiresAt: request.ExpiresAt, MaxBytes: request.MaxBytes, MaxChunks: request.MaxChunks, MaxOperations: request.MaxOperations, StagedManifestCommitment: request.StagedManifestCommitment}
	_, signer := testOfferSigner()
	if err := attachmentv3.SignPermit(&s.permit, signer); err != nil {
		return attachmentv3.Permit{}, err
	}
	return s.permit, nil
}
func (s *senderTransportStub) DoV3Attachment(_ context.Context, method, path string, body []byte, permit attachmentv3.Permit, _ attachmentv3.OperationRecord) ([]byte, error) {
	s.operationCalls++
	s.method, s.path, s.body = method, path, append([]byte(nil), body...)
	if permit != s.permit {
		return nil, errors.New("changed sender permit")
	}
	if s.results != nil {
		return append([]byte(nil), s.results[path]...), nil
	}
	return append([]byte(nil), s.result...), nil
}

func sourceUploadingTransferResult(t *testing.T, transfer [16]byte, commitment [32]byte, expires int64) []byte {
	t.Helper()
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := mode.Marshal(map[uint64]any{1: uint64(3), 2: transfer, 3: commitment, 4: uint64(attachmentv3.TransferStateSourceUploading), 5: uint64(0), 6: expires})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func sourceReadyTransferResult(t *testing.T, transfer [16]byte, commitment [32]byte, expires int64) []byte {
	t.Helper()
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := mode.Marshal(map[uint64]any{1: uint64(3), 2: transfer, 3: commitment, 4: uint64(attachmentv3.TransferStateSourceReady), 5: uint64(0), 6: expires})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func offeredTransferResult(t *testing.T, transfer [16]byte, commitment [32]byte, expires int64) []byte {
	t.Helper()
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := mode.Marshal(map[uint64]any{1: uint64(3), 2: transfer, 3: commitment, 4: uint64(attachmentv3.TransferStateOffered), 5: uint64(0), 6: expires})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func sequenceKey(values ...[32]byte) func() ([32]byte, error) {
	position := 0
	return func() ([32]byte, error) {
		if position >= len(values) {
			return [32]byte{}, errors.New("unexpected random key")
		}
		value := values[position]
		position++
		return value, nil
	}
}
