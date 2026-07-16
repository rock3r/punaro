//go:build !darwin

package controller

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/zeebo/blake3"
)

// SystemdCredentialHostKeyProvider reads a 32-byte base64 key from a private
// systemd LoadCredential file. CredentialDirectory is normally
// $CREDENTIALS_DIRECTORY, resolved by the service composition rather than by
// this low-level provider. The key never enters the controller journal or an
// environment variable.
type SystemdCredentialHostKeyProvider struct {
	CredentialDirectory string
	CredentialName      string
}

func (p SystemdCredentialHostKeyProvider) SenderKeyEncryptionKey(context.Context) ([32]byte, error) {
	var key [32]byte
	raw, err := p.readCredential()
	if err != nil {
		return key, err
	}
	decoded, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(decoded) != len(key) {
		return key, errors.New("invalid systemd sender key credential")
	}
	copy(key[:], decoded)
	return key, nil
}

func (p SystemdCredentialHostKeyProvider) SenderKeyEncryptionKeyID(ctx context.Context) ([32]byte, error) {
	key, err := p.SenderKeyEncryptionKey(ctx)
	if err != nil {
		return [32]byte{}, err
	}
	return blake3.Sum256(append([]byte("punaro/host-key-id/v1\\x00"), key[:]...)), nil
}

func (p SystemdCredentialHostKeyProvider) readCredential() ([]byte, error) {
	if p.CredentialDirectory == "" || p.CredentialName == "" || filepath.Base(p.CredentialName) != p.CredentialName || strings.ContainsAny(p.CredentialName, `/\\`) {
		return nil, errors.New("invalid systemd sender key credential reference")
	}
	dir, err := os.Lstat(p.CredentialDirectory)
	if err != nil || !dir.IsDir() || dir.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("systemd sender credential directory is unavailable")
	}
	path := filepath.Join(p.CredentialDirectory, p.CredentialName)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("systemd sender key credential is unavailable")
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- path is an explicit private systemd credential reference, constrained above.
	if err != nil || len(raw) == 0 || len(raw) > 128 {
		return nil, errors.New("systemd sender key credential is unavailable")
	}
	return raw, nil
}
