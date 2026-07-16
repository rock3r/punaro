//go:build !darwin

package controller

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestSystemdCredentialHostKeyProviderRejectsUnsafeCredentialAndDerivesStableID(t *testing.T) {
	dir := t.TempDir()
	key := bytes32(91)
	path := filepath.Join(dir, "sender-kek")
	if err := os.WriteFile(path, []byte(base64.RawStdEncoding.EncodeToString(key[:])), 0o400); err != nil {
		t.Fatal(err)
	}
	p := SystemdCredentialHostKeyProvider{CredentialDirectory: dir, CredentialName: "sender-kek"}
	opened, err := p.SenderKeyEncryptionKey(context.Background())
	if err != nil || opened != key {
		t.Fatalf("key=%x err=%v", opened, err)
	}
	id, err := p.SenderKeyEncryptionKeyID(context.Background())
	if err != nil || id == [32]byte{} {
		t.Fatalf("id=%x err=%v", id, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := p.SenderKeyEncryptionKey(context.Background()); err == nil {
		t.Fatal("world-readable credential was accepted")
	}
}
