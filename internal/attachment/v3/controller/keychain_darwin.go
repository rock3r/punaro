//go:build darwin

package controller

import (
	"context"
	"encoding/base64"
	"errors"
	"os/exec"
	"strings"

	"github.com/zeebo/blake3"
)

// MacOSKeychainHostKeyProvider reads a 32-byte base64 key from a macOS
// Keychain generic-password item. The Keychain owns encryption at rest and
// access control; no key value is configured in Punaro files or environment.
type MacOSKeychainHostKeyProvider struct{ Service, Account string }

// SenderKeyEncryptionKey loads the host key-encryption key from the configured
// Keychain item.
func (p MacOSKeychainHostKeyProvider) SenderKeyEncryptionKey(ctx context.Context) ([32]byte, error) {
	var key [32]byte
	if p.Service == "" || p.Account == "" {
		return key, errors.New("invalid macOS keychain reference")
	}
	// #nosec G204 -- executable and argument structure are fixed; service and
	// account are local Keychain lookup selectors, never shell input.
	out, err := exec.CommandContext(ctx, "/usr/bin/security", "find-generic-password", "-s", p.Service, "-a", p.Account, "-w").Output()
	if err != nil {
		return key, errors.New("macOS keychain key is unavailable")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil || len(raw) != len(key) {
		return key, errors.New("invalid macOS keychain key")
	}
	copy(key[:], raw)
	return key, nil
}

// SenderKeyEncryptionKeyID derives a non-secret identifier for the configured
// Keychain item.
func (p MacOSKeychainHostKeyProvider) SenderKeyEncryptionKeyID(context.Context) ([32]byte, error) {
	if p.Service == "" || p.Account == "" {
		return [32]byte{}, errors.New("invalid macOS keychain reference")
	}
	return blake3.Sum256(append(append([]byte("punaro/host-key-id/v1\x00"), []byte(p.Service)...), []byte(p.Account)...)), nil
}
