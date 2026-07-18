//go:build windows

package controller

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDPAPIHostKeyFileRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sender.dpapi")
	if err := WriteDPAPIHostKeyFile(path); err != nil {
		t.Fatal(err)
	}
	provider := DPAPIHostKeyProvider{File: path}
	key, err := provider.SenderKeyEncryptionKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if key == [32]byte{} {
		t.Fatal("DPAPI returned an all-zero wrapping key")
	}
	if _, err := provider.SenderKeyEncryptionKeyID(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDPAPIHostKeyFileRefusesExistingPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sender.dpapi")
	if err := os.WriteFile(path, []byte("already-present"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteDPAPIHostKeyFile(path); err == nil {
		t.Fatal("accepted an existing DPAPI key path")
	}
}
