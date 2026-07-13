package v2

import "testing"

func FuzzDecodeManifest(f *testing.F) {
	manifest := sampleManifest()
	raw, err := EncodeManifest(manifest)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte{0xa0})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = DecodeManifest(input)
	})
}

func FuzzDecodeEnvelope(f *testing.F) {
	f.Add([]byte{0xa0})
	f.Add(make([]byte, maxEnvelopeEncodedBytes+1))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = DecodeEnvelope(input)
	})
}
