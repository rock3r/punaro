package v3

import (
	"bytes"
	"crypto/ed25519"
	"net/http"
	"testing"
	"time"
)

func FuzzDecodeManifest(f *testing.F) {
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	manifest := testManifest(now)
	if err := SignManifest(&manifest, private); err != nil {
		f.Fatal(err)
	}
	raw, err := EncodeManifest(manifest)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xff}, maxManifestEncodedBytes+1))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = DecodeManifest(raw)
	})
}

func FuzzDecodeOfferNotice(f *testing.F) {
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, ed25519.SeedSize))
	manifest := testManifest(now)
	if err := SignManifest(&manifest, private); err != nil {
		f.Fatal(err)
	}
	rawManifest, err := EncodeManifest(manifest)
	if err != nil {
		f.Fatal(err)
	}
	envelope := testEnvelopeForManifest(manifest, rawManifest)
	if err := SignEnvelope(&envelope, private); err != nil {
		f.Fatal(err)
	}
	offer, err := EncodeOfferPayload(manifest, envelope, testHash(63))
	if err != nil {
		f.Fatal(err)
	}
	notice, err := EncodeOfferNotice(offer)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(notice)
	f.Add(offerNoticePrefix)
	f.Add(string(bytes.Repeat([]byte{'x'}, maxOfferNoticeBodyBytes+1)))
	f.Fuzz(func(t *testing.T, body string) {
		_, _ = DecodeOfferNotice(body)
	})
}

func FuzzParseAttachmentRoute(f *testing.F) {
	f.Add(http.MethodGet, "/v3/attachments/01000000000000000000000000000000/chunks/0")
	f.Add(http.MethodPost, "/v3/attachments/")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, method, path string) {
		_, _ = ParseAttachmentRoute(method, path)
	})
}
