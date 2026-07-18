//go:build !darwin && !windows

package controller

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
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

// SenderKeyEncryptionKey returns the credential's decoded 32-byte wrapping key.
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

// SenderKeyEncryptionKeyID returns the domain-separated identifier of the
// current sender-key wrapping credential.
func (p SystemdCredentialHostKeyProvider) SenderKeyEncryptionKeyID(ctx context.Context) ([32]byte, error) {
	key, err := p.SenderKeyEncryptionKey(ctx)
	if err != nil {
		return [32]byte{}, err
	}
	return blake3.Sum256(append([]byte("punaro/host-key-id/v1\\x00"), key[:]...)), nil
}

func (p SystemdCredentialHostKeyProvider) readCredential() ([]byte, error) {
	if !filepath.IsAbs(p.CredentialDirectory) || p.CredentialName == "" || filepath.Base(p.CredentialName) != p.CredentialName || strings.ContainsAny(p.CredentialName, `/\\`) {
		return nil, errors.New("invalid systemd sender key credential reference")
	}
	dir, err := os.Lstat(p.CredentialDirectory)
	if err != nil || !dir.IsDir() || dir.Mode()&os.ModeSymlink != 0 || dir.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("systemd sender credential directory is unavailable")
	}
	path := filepath.Join(p.CredentialDirectory, p.CredentialName)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("systemd sender key credential is unavailable")
	}
	// #nosec G304 -- path is an explicit private systemd credential reference,
	// constrained above. Read the checked descriptor rather than reopening the
	// path so a replacement cannot select a different wrapping key.
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("systemd sender key credential is unavailable")
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("systemd sender key credential is unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 129))
	if err != nil || len(raw) == 0 || len(raw) > 128 {
		return nil, errors.New("systemd sender key credential is unavailable")
	}
	return raw, nil
}
