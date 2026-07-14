package v2

import "testing"

func TestExpectedCiphertextChunkLengthRejectsImpossibleGeometry(t *testing.T) {
	t.Parallel()
	manifest := sampleManifest()
	manifest.ChunkSize, manifest.ChunkCount, manifest.PlaintextSize = 8, 2, 11
	if got, err := expectedCiphertextChunkLength(manifest, 0); err != nil || got != 24 {
		t.Fatalf("first chunk=%d err=%v", got, err)
	}
	if got, err := expectedCiphertextChunkLength(manifest, 1); err != nil || got != 19 {
		t.Fatalf("last chunk=%d err=%v", got, err)
	}
	if _, err := expectedCiphertextChunkLength(manifest, 2); err == nil {
		t.Fatal("out-of-range chunk index was accepted")
	}
}
