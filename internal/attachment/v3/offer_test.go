package v3

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func TestOfferPayloadRequiresCanonicalManifestAndEnvelopeBoundToPermit(t *testing.T) {
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	manifest := testManifest(now)
	if err := SignManifest(&manifest, private); err != nil {
		t.Fatal(err)
	}
	manifestRaw, err := EncodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	envelope := testEnvelopeForManifest(manifest, manifestRaw)
	if err := SignEnvelope(&envelope, private); err != nil {
		t.Fatal(err)
	}
	payload, err := EncodeOfferPayload(manifest, envelope, testHash(42))
	if err != nil {
		t.Fatal(err)
	}
	permit := permitForManifest(manifest, manifestRaw, now)
	permit.Operation = permitOperationOffer
	if err := validateOfferPayloadForPermit(payload, permit); err != nil {
		t.Fatal(err)
	}
	refreshed := permit
	refreshed.DirectoryHead, refreshed.RevocationEpoch = testHash(98), manifest.RevocationEpoch+1
	if err := validateOfferPayloadForPermit(payload, refreshed); err != nil {
		t.Fatalf("offer rejected after fresh permit directory rollover: %v", err)
	}
	if sourceInitPermitBinding(refreshed, manifest, manifestRaw) {
		t.Fatal("source-init accepted a permit with a rolled directory head")
	}
	route, request, err := NewAttachmentOperationRequest("POST", "/v3/attachments/02000000000000000000000000000000/offer", payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAttachmentRequestRoute(route, permit, request); err != nil {
		t.Fatal(err)
	}
	changed := permit
	changed.StagedManifestCommitment = testHash(99)
	if err := validateOfferPayloadForPermit(payload, changed); err == nil {
		t.Fatal("offer with another staged manifest commitment accepted")
	}
	if err := validateOfferPayloadForPermit([]byte{0xa0}, permit); err == nil {
		t.Fatal("malformed offer accepted")
	}
}

func permitForManifest(manifest Manifest, raw []byte, now time.Time) Permit {
	permit := testPermit(now)
	permit.Audience, permit.TransferID, permit.ConversationID = manifest.Audience, manifest.TransferID, manifest.ConversationID
	permit.SenderDeviceID, permit.SenderGeneration = manifest.SenderDeviceID, manifest.SenderGeneration
	permit.RecipientDeviceID, permit.RecipientGeneration = manifest.RecipientDeviceID, manifest.RecipientGeneration
	permit.HolderDeviceID, permit.HolderGeneration, permit.HolderRole = manifest.SenderDeviceID, manifest.SenderGeneration, permitHolderSender
	permit.DirectoryHead, permit.MembershipCommitment, permit.RevocationEpoch = manifest.DirectoryHead, manifest.MembershipCommitment, manifest.RevocationEpoch
	permit.ExpiresAt, permit.StagedManifestCommitment = manifest.ExpiresAt, manifestCommitment(raw)
	return permit
}

func testEnvelopeForManifest(manifest Manifest, raw []byte) Envelope {
	return Envelope{Audience: manifest.Audience, TransferID: manifest.TransferID, ConversationID: manifest.ConversationID,
		SenderDeviceID: manifest.SenderDeviceID, SenderGeneration: manifest.SenderGeneration,
		RecipientDeviceID: manifest.RecipientDeviceID, RecipientGeneration: manifest.RecipientGeneration,
		RecipientHPKEKeyID: testHash(61), ManifestCommitment: manifestCommitment(raw),
		EncapsulatedKey: testHash(62), Ciphertext: make([]byte, 16), SignerKeyID: manifest.SignerKeyID}
}
