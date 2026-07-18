//go:build !darwin && !windows

package controller

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestSystemdCredentialHostKeyRejectsUnsafeDirectory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "credentials")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- this fixture must deliberately be unsafe.
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	key[0] = 1
	if err := os.WriteFile(filepath.Join(directory, "sender-key"), []byte(base64.RawStdEncoding.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	provider := SystemdCredentialHostKeyProvider{CredentialDirectory: directory, CredentialName: "sender-key"}
	if _, err := provider.SenderKeyEncryptionKey(context.Background()); err == nil {
		t.Fatal("accepted group/world-accessible credential directory")
	}
}
