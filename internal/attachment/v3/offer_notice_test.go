package v3

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestOfferNoticeRoundTripsOnlyCanonicalOfferPayload(t *testing.T) {
	manifest, envelope := testOfferNoticeMaterial(t)
	payload, err := EncodeOfferPayload(manifest, envelope, testHash(61))
	if err != nil {
		t.Fatal(err)
	}
	notice, err := EncodeOfferNotice(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(notice, offerNoticePrefix) || len(notice) > maxOfferNoticeBodyBytes {
		t.Fatalf("unexpected bounded notice %q", notice)
	}
	decoded, err := DecodeOfferNotice(notice)
	if err != nil {
		t.Fatal(err)
	}
	envelopeRaw, err := EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Raw, payload) || decoded.Manifest.TransferID != manifest.TransferID || !bytes.Equal(decoded.EnvelopeRaw, envelopeRaw) || decoded.AcceptanceNonce != testHash(61) {
		t.Fatal("offer notice changed authenticated offer payload")
	}
}

func TestOfferNoticeRejectsNonCanonicalAndOversizedInput(t *testing.T) {
	manifest, envelope := testOfferNoticeMaterial(t)
	payload, err := EncodeOfferPayload(manifest, envelope, testHash(62))
	if err != nil {
		t.Fatal(err)
	}
	notice, err := EncodeOfferNotice(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeOfferNotice(notice + "="); err == nil {
		t.Fatal("non-canonical base64 notice accepted")
	}
	if _, err := DecodeOfferNotice("punaro/attachment-offer/v2:abc"); err == nil {
		t.Fatal("wrong offer notice version accepted")
	}
	if _, err := EncodeOfferNotice(bytes.Repeat([]byte{0}, maxOfferPayloadBytes+1)); err == nil {
		t.Fatal("oversized offer payload notice accepted")
	}
}

func TestEveryAdmittedOfferFitsOneRelayNotice(t *testing.T) {
	if len(offerNoticePrefix)+base64.RawURLEncoding.EncodedLen(maxOfferPayloadBytes) > maxOfferNoticeBodyBytes {
		t.Fatal("admitted offer maximum cannot fit the durable relay notice")
	}
	if len(offerNoticePrefix)+base64.RawURLEncoding.EncodedLen(maxOfferPayloadBytes+1) <= maxOfferNoticeBodyBytes {
		t.Fatal("offer payload cap is not the largest transportable raw size")
	}
}

func testOfferNoticeMaterial(t *testing.T) (Manifest, Envelope) {
	t.Helper()
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	manifest := testManifest(now)
	if err := SignManifest(&manifest, private); err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	envelope := testEnvelopeForManifest(manifest, raw)
	if err := SignEnvelope(&envelope, private); err != nil {
		t.Fatal(err)
	}
	return manifest, envelope
}
