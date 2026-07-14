package v2

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPrivateEd25519KeyFileAcceptsOnlyPrivateCanonicalKey(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "issuer.key")
	if err := os.WriteFile(path, []byte(base64.RawURLEncoding.EncodeToString(private)), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPrivateEd25519KeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(loaded) != string(private) {
		t.Fatal("loaded private key differs from source")
	}
	if err := os.Chmod(path, 0o644); err != nil { // #nosec G302 -- test intentionally proves the loader rejects an insecure mode.
		t.Fatal(err)
	}
	if _, err := LoadPrivateEd25519KeyFile(path); err == nil {
		t.Fatal("world-readable private key was accepted")
	}
}

func TestLoadPrivateEd25519KeyFileRejectsInconsistentKey(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, ed25519.PrivateKeySize)
	key[0] = 1
	path := filepath.Join(directory, "issuer.key")
	if err := os.WriteFile(path, []byte(base64.RawURLEncoding.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateEd25519KeyFile(path); err == nil {
		t.Fatal("inconsistent private key was accepted")
	}
}
