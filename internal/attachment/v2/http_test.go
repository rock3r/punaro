package v2

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type failingAttachmentAuthorityProvider struct{}

func (failingAttachmentAuthorityProvider) ResolveAttachmentAuthority(_ context.Context, _ time.Time) (AttachmentAuthority, error) {
	return nil, errors.New("authority must not be resolved for unsigned input")
}

type attachmentAuthorityStub struct {
	directoryStub
	permitAuthorityStub
	operationHolderStub
}

type staticAttachmentAuthorityProvider struct{ authority AttachmentAuthority }

func (p staticAttachmentAuthorityProvider) ResolveAttachmentAuthority(_ context.Context, _ time.Time) (AttachmentAuthority, error) {
	return p.authority, nil
}

func TestAttachmentHTTPHandlerRejectsUnsignedRequestBeforeDirectoryLookup(t *testing.T) {
	t.Parallel()
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	ledger, err := OpenSQLitePermitLedger(filepath.Join(parent, "ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	store, err := OpenSQLiteTransferStore(ledger)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewAttachmentHTTPHandler(AttachmentHTTPHandlerOptions{
		Store:     store,
		Authority: failingAttachmentAuthorityProvider{},
		Now:       time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v2/attachments/05050505050505050505050505050505/chunks/0", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestAttachmentHTTPHandlerRedeemsSignedOfferAgainstFreshAuthority(t *testing.T) {
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
	payload, err := EncodeOfferPayload(manifest, envelope, bytes32(81))
	if err != nil {
		t.Fatal(err)
	}
	path := "/v2/attachments/05050505050505050505050505050505/offer"
	_, operationRequest, err := NewAttachmentOperationRequest(http.MethodPost, path, payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	operation := sampleOperation(permit, operationRequest)
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
	authority := attachmentAuthorityStub{
		directoryStub:       directory,
		permitAuthorityStub: permitAuthorityStub{keyID: permit.IssuerKeyID, key: issuerPublic},
		operationHolderStub: operationHolderStub{device: permit.HolderDeviceID, generation: permit.HolderGeneration, key: signerPublic},
	}
	if err := ledger.Issue(permit, authority, clock); err != nil {
		t.Fatal(err)
	}
	store, err := OpenSQLiteTransferStore(ledger)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewAttachmentHTTPHandler(AttachmentHTTPHandlerOptions{Store: store, Authority: staticAttachmentAuthorityProvider{authority: authority}, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	permitRaw, err := EncodePermit(permit)
	if err != nil {
		t.Fatal(err)
	}
	operationRaw, err := EncodeOperation(operation)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, bytes.NewReader(payload))
	request.Header.Set(attachmentPermitHeader, base64.RawURLEncoding.EncodeToString(permitRaw))
	request.Header.Set(attachmentOperationHeader, base64.RawURLEncoding.EncodeToString(operationRaw))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/cbor" {
		t.Fatalf("status=%d content-type=%q body=%x", response.Code, response.Header().Get("Content-Type"), response.Body.Bytes())
	}
	record, err := decodeTransferResult(response.Body.Bytes())
	if err != nil || record.Status != TransferOffered || record.ManifestCommitment != verified.commitment {
		t.Fatalf("record=%+v err=%v", record, err)
	}
}
