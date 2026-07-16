package v3

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

type envelopeDirectoryStub struct {
	signer    ed25519.PublicKey
	keyID     [32]byte
	recipient *ecdh.PublicKey
	reject    bool
}

func (d envelopeDirectoryStub) ValidateManifestAuthority(Manifest, time.Time) (ed25519.PublicKey, error) {
	if d.reject {
		return nil, errors.New("revoked")
	}
	return d.signer, nil
}
func (d envelopeDirectoryStub) ValidateRetainedManifestAuthority(m Manifest, now time.Time) (ed25519.PublicKey, error) {
	return d.ValidateManifestAuthority(m, now)
}
func (d envelopeDirectoryStub) CurrentRecipientHPKEKey([16]byte, uint64) ([32]byte, *ecdh.PublicKey, error) {
	if d.reject {
		return [32]byte{}, nil, errors.New("revoked")
	}
	return d.keyID, d.recipient, nil
}
func (d envelopeDirectoryStub) ResolveRecipientHPKEKey(_ [16]byte, _ uint64, keyID [32]byte) (*ecdh.PublicKey, error) {
	if d.reject || keyID != d.keyID {
		return nil, errors.New("unknown")
	}
	return d.recipient, nil
}

func TestRecipientEnvelopeSealAndOpenV3(t *testing.T) {
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := testManifest(now)
	if err := SignManifest(&manifest, private); err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := envelopeDirectoryStub{signer: public, keyID: testHash(71), recipient: recipient.PublicKey()}
	source, err := DecodeAndVerifySourceInit(raw, directory, now)
	if err != nil {
		t.Fatal(err)
	}
	fileKey := testHash(72)
	envelope, err := SealRecipientEnvelope(source, directory, fileKey, private, now)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenRecipientEnvelope(encoded, source, directory, recipient, now)
	if err != nil || got != fileKey {
		t.Fatalf("key=%x err=%v", got, err)
	}
	offer, err := EncodeOfferPayload(manifest, envelope, testHash(73))
	if err != nil {
		t.Fatal(err)
	}
	noticeBody, err := EncodeOfferNotice(offer)
	if err != nil {
		t.Fatal(err)
	}
	notice, err := DecodeOfferNotice(noticeBody)
	if err != nil {
		t.Fatal(err)
	}
	if verified, _, err := VerifyOfferNotice(notice, directory, now); err != nil || verified.ManifestCommitment() != source.ManifestCommitment() {
		t.Fatalf("offer verification commitment=%x err=%v", verified.ManifestCommitment(), err)
	}
	notice.Envelope.Signature[0] ^= 1
	changedOffer, err := EncodeOfferPayload(notice.Manifest, notice.Envelope, notice.AcceptanceNonce)
	if err != nil {
		t.Fatal(err)
	}
	changedBody, err := EncodeOfferNotice(changedOffer)
	if err != nil {
		t.Fatal(err)
	}
	changedNotice, err := DecodeOfferNotice(changedBody)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyOfferNotice(changedNotice, directory, now); err == nil {
		t.Fatal("verified offer with a changed envelope signature")
	}
	envelope.RecipientHPKEKeyID[0] ^= 1
	changed, err := EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRecipientEnvelope(changed, source, directory, recipient, now); err == nil {
		t.Fatal("opened changed envelope binding")
	}
	if _, err := SealRecipientEnvelope(source, directory, [32]byte{}, private, now); err == nil {
		t.Fatal("sealed an all-zero file key")
	}
	wrong, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRecipientEnvelope(encoded, source, directory, wrong, now); err == nil {
		t.Fatal("opened envelope with wrong recipient private key")
	}
	withdrawn := directory
	withdrawn.reject = true
	if _, err := OpenRecipientEnvelope(encoded, source, withdrawn, recipient, now); err == nil {
		t.Fatal("opened envelope after directory withdrawal")
	}
	wrongManifest := manifest
	wrongManifest.TransferID = testID(99)
	if err := SignManifest(&wrongManifest, private); err != nil {
		t.Fatal(err)
	}
	wrongRaw, err := EncodeManifest(wrongManifest)
	if err != nil {
		t.Fatal(err)
	}
	wrongSource, err := DecodeAndVerifySourceInit(wrongRaw, directory, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRecipientEnvelope(encoded, wrongSource, directory, recipient, now); err == nil {
		t.Fatal("opened envelope for another source")
	}
}
