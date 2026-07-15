package v3

import (
	"bytes"
	"crypto/ed25519"
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
