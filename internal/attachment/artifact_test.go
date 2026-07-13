package attachment

import (
	"bytes"
	"testing"
)

func TestEncryptArtifactBindsChunksToArtifactAndIndex(t *testing.T) {
	artifact, err := EncryptArtifact([]byte("0123456789abcdef"), []byte("a small secret attachment"), 8)
	if err != nil {
		t.Fatalf("EncryptArtifact() error = %v", err)
	}
	if artifact.ChunkCount != 4 {
		t.Fatalf("chunk count = %d, want 4", artifact.ChunkCount)
	}
	plain, err := artifact.Decrypt()
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if !bytes.Equal(plain, []byte("a small secret attachment")) {
		t.Fatalf("plaintext = %q", plain)
	}
	artifact.Chunks[1].Ciphertext[0] ^= 1
	if _, err := artifact.Decrypt(); err == nil {
		t.Fatal("Decrypt() succeeded for tampered ciphertext")
	}
}
