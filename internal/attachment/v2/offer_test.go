package v2

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteTransferStoreOffersVerifiedManifestAndEnvelopeAtomically(t *testing.T) {
	t.Parallel()
	signerPublic, signerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerPublic, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipientPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipientSignerPublic, recipientSignerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now().UTC().Truncate(time.Second)
	permit := samplePermit()
	permit.Operation = PermitOperationOffer
	permit.IssuedAt, permit.ExpiresAt = testUnix(t, clock.Add(-time.Second)), testUnix(t, clock.Add(20*time.Second))
	if err := SignPermit(&permit, issuerPrivate); err != nil {
		t.Fatal(err)
	}
	manifest := sampleManifest()
	manifest.Audience, manifest.TransferID, manifest.ConversationID = permit.Audience, permit.TransferID, permit.ConversationID
	manifest.SenderDeviceID, manifest.SenderGeneration = permit.SenderDeviceID, permit.SenderGeneration
	manifest.RecipientDeviceID, manifest.RecipientGeneration = permit.RecipientDeviceID, permit.RecipientGeneration
	manifest.DirectoryHead, manifest.MembershipCommitment, manifest.RevocationEpoch = permit.DirectoryHead, permit.MembershipCommitment, permit.RevocationEpoch
	manifest.SignerKeyID, manifest.IssuedAt, manifest.ExpiresAt = bytes32(77), permit.IssuedAt, testUnix(t, clock.Add(25*time.Second))
	if err := SignManifest(&manifest, signerPrivate); err != nil {
		t.Fatal(err)
	}
	directory := directoryStub{signerID: manifest.SignerKeyID, signer: signerPublic, recipientID: bytes32(78), recipient: recipientPrivate.PublicKey()}
	verified, err := verifyManifestFromDirectory(manifest, directory)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SealRecipientEnvelope(verified, directory, bytes32(79), signerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	acceptanceNonce := bytes32(81)
	payload, err := EncodeOfferPayload(manifest, envelope, acceptanceNonce)
	if err != nil {
		t.Fatal(err)
	}
	route, request, err := NewAttachmentOperationRequest("POST", "/v2/attachments/05050505050505050505050505050505/offer", payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	operation := sampleOperation(permit, request)
	operation.IssuedAt, operation.ExpiresAt = permit.IssuedAt, permit.ExpiresAt
	if err := SignOperation(&operation, signerPrivate); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	ledger, err := OpenSQLitePermitLedger(filepath.Join(parent, "ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	authority := permitAuthorityStub{keyID: permit.IssuerKeyID, key: issuerPublic}
	holders := operationHolderStub{device: permit.HolderDeviceID, generation: permit.HolderGeneration, key: signerPublic}
	if err := ledger.Issue(permit, authority, clock); err != nil {
		t.Fatal(err)
	}
	store, err := OpenSQLiteTransferStore(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Offer(context.Background(), permit, operation, request, route, payload, authority, holders, directory, clock); err == nil {
		t.Fatal("offer without a complete relay source was accepted")
	}
	if _, found, err := store.Load(permit.TransferID); err != nil || found {
		t.Fatalf("failed offer left transfer state found=%v err=%v", found, err)
	}
	ciphertext := make([]byte, 58) // manifest has one 42-byte plaintext chunk plus tag.
	ciphertextHash := ciphertextCommitment(ciphertext)
	if _, err := ledger.db.ExecContext(context.Background(), "INSERT INTO attachment_chunks(transfer_id, chunk_index, ciphertext, ciphertext_commitment) VALUES (?, ?, ?, ?)", permit.TransferID[:], uint64Bytes(0), ciphertext, ciphertextHash[:]); err != nil {
		t.Fatal(err)
	}
	record, replayed, err := store.Offer(context.Background(), permit, operation, request, route, payload, authority, holders, directory, clock)
	if err != nil || replayed || record.Status != TransferOffered || record.ManifestCommitment != verified.commitment {
		t.Fatalf("record=%+v replayed=%v err=%v", record, replayed, err)
	}
	storedManifest, storedEnvelope, found, err := store.LoadOffer(permit.TransferID)
	storedEnvelopeRaw, encodeErr := EncodeEnvelope(storedEnvelope)
	envelopeRaw, expectedEncodeErr := EncodeEnvelope(envelope)
	if err != nil || encodeErr != nil || expectedEncodeErr != nil || !found || storedManifest != manifest || !bytes.Equal(storedEnvelopeRaw, envelopeRaw) {
		t.Fatalf("manifest=%+v envelope=%+v found=%v err=%v", storedManifest, storedEnvelope, found, err)
	}
	record, replayed, err = store.Offer(context.Background(), permit, operation, request, route, payload, authority, holders, directory, clock)
	if err != nil || !replayed || record.Status != TransferOffered {
		t.Fatalf("retry record=%+v replayed=%v err=%v", record, replayed, err)
	}
	uploadPermit := permit
	uploadPermit.Serial, uploadPermit.Operation, uploadPermit.MaxOperations = bytes16(80), PermitOperationUpload, 1
	if err := SignPermit(&uploadPermit, issuerPrivate); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Issue(uploadPermit, authority, clock); err != nil {
		t.Fatal(err)
	}
	uploadRoute, uploadRequest, err := NewAttachmentOperationRequest("PUT", "/v2/attachments/05050505050505050505050505050505/chunks/0", ciphertext, nil)
	if err != nil {
		t.Fatal(err)
	}
	uploadOperation := sampleOperation(uploadPermit, uploadRequest)
	uploadOperation.IssuedAt, uploadOperation.ExpiresAt = uploadPermit.IssuedAt, uploadPermit.ExpiresAt
	if err := SignOperation(&uploadOperation, signerPrivate); err != nil {
		t.Fatal(err)
	}
	if _, replayed, err := store.Upload(context.Background(), uploadPermit, uploadOperation, uploadRequest, uploadRoute, authority, holders, directory, clock); err != nil || replayed {
		t.Fatalf("upload replayed=%v err=%v", replayed, err)
	}
	loadedChunk, found, err := store.LoadChunk(permit.TransferID, 0)
	if err != nil || !found || string(loadedChunk.Ciphertext) != string(ciphertext) || loadedChunk.CiphertextCommitment != ciphertextCommitment(ciphertext) {
		t.Fatalf("chunk=%+v found=%v err=%v", loadedChunk, found, err)
	}
	acceptPermit := permit
	acceptPermit.Serial, acceptPermit.Operation = bytes16(82), PermitOperationAccept
	acceptPermit.HolderDeviceID, acceptPermit.HolderGeneration, acceptPermit.HolderRole = permit.RecipientDeviceID, permit.RecipientGeneration, PermitHolderRecipient
	if err := SignPermit(&acceptPermit, issuerPrivate); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Issue(acceptPermit, authority, clock); err != nil {
		t.Fatal(err)
	}
	acceptRoute, acceptRequest, err := NewAttachmentOperationRequest("POST", "/v2/attachments/05050505050505050505050505050505/accept", acceptanceNonce[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	acceptOperation := sampleOperation(acceptPermit, acceptRequest)
	acceptOperation.IssuedAt, acceptOperation.ExpiresAt = acceptPermit.IssuedAt, acceptPermit.ExpiresAt
	if err := SignOperation(&acceptOperation, recipientSignerPrivate); err != nil {
		t.Fatal(err)
	}
	acceptHolders := operationHolderStub{device: acceptPermit.HolderDeviceID, generation: acceptPermit.HolderGeneration, key: recipientSignerPublic}
	if accepted, replayed, err := store.Accept(context.Background(), acceptPermit, acceptOperation, acceptRequest, acceptRoute, authority, acceptHolders, directory, clock); err != nil || replayed || accepted.Status != TransferAccepted {
		t.Fatalf("accepted=%+v replayed=%v err=%v", accepted, replayed, err)
	}
	downloadPermit := acceptPermit
	downloadPermit.Serial, downloadPermit.Operation, downloadPermit.MaxOperations = bytes16(83), PermitOperationDownload, 1
	if err := SignPermit(&downloadPermit, issuerPrivate); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Issue(downloadPermit, authority, clock); err != nil {
		t.Fatal(err)
	}
	downloadRoute, downloadRequest, err := NewAttachmentOperationRequest("GET", "/v2/attachments/05050505050505050505050505050505/chunks/0", nil, loadedChunk.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	downloadOperation := sampleOperation(downloadPermit, downloadRequest)
	downloadOperation.IssuedAt, downloadOperation.ExpiresAt = downloadPermit.IssuedAt, downloadPermit.ExpiresAt
	if err := SignOperation(&downloadOperation, recipientSignerPrivate); err != nil {
		t.Fatal(err)
	}
	downloaded, replayed, err := store.Download(context.Background(), downloadPermit, downloadOperation, downloadRequest, downloadRoute, authority, acceptHolders, directory, clock)
	if err != nil || replayed || string(downloaded.Ciphertext) != string(ciphertext) {
		t.Fatalf("downloaded=%+v replayed=%v err=%v", downloaded, replayed, err)
	}
}
