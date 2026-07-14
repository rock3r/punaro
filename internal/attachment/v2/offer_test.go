package v2

import (
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
	payload, err := EncodeOfferPayload(manifest, envelope)
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
	record, replayed, err := store.Offer(context.Background(), permit, operation, request, route, payload, authority, holders, directory, clock)
	if err != nil || replayed || record.Status != TransferOffered || record.ManifestCommitment != verified.commitment {
		t.Fatalf("record=%+v replayed=%v err=%v", record, replayed, err)
	}
	record, replayed, err = store.Offer(context.Background(), permit, operation, request, route, payload, authority, holders, directory, clock)
	if err != nil || !replayed || record.Status != TransferOffered {
		t.Fatalf("retry record=%+v replayed=%v err=%v", record, replayed, err)
	}
}
