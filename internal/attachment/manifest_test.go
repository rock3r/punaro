package attachment

import (
	"bytes"
	"testing"
)

func TestNewManifestBindsSinglePlaintextWithRandomSalt(t *testing.T) {
	manifest, err := NewManifest([]byte("the chicken has an attachment"))
	if err != nil {
		t.Fatalf("NewManifest() error = %v", err)
	}
	if len(manifest.ContentSalt) != ContentSaltSize {
		t.Fatalf("salt length = %d, want %d", len(manifest.ContentSalt), ContentSaltSize)
	}
	if bytes.Equal(manifest.ContentSalt, make([]byte, ContentSaltSize)) {
		t.Fatal("salt must not be all zero")
	}
	if !manifest.Verifies([]byte("the chicken has an attachment")) {
		t.Fatal("manifest did not verify its plaintext")
	}
	if manifest.Verifies([]byte("a different attachment")) {
		t.Fatal("manifest verified different plaintext")
	}
}
