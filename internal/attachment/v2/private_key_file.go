package v2

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// LoadPrivateEd25519KeyFile loads a canonical raw-base64url Ed25519 private
// key from a service-private, non-symlinked regular file. It never accepts a
// PEM or a newline-tolerant representation, so the deployed secret format is
// unambiguous and accidental shell formatting fails closed.
func LoadPrivateEd25519KeyFile(path string) (ed25519.PrivateKey, error) {
	if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) {
		return nil, errors.New("private key path must be absolute")
	}
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	// A root-owned publisher directory can grant its service group traversal
	// without granting the relay ownership or write access. The key stays
	// owner-only even when its parent is group-traversable.
	if err != nil || !safePrivateKeyParent(parentInfo) {
		return nil, errors.New("private key parent must be private and non-symlinked")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("private key file must be private and non-symlinked")
	}
	// #nosec G304,G703 -- path is locally configured and checked for a private,
	// non-symlinked regular file before opening; SameFile detects replacement.
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("private key is unavailable")
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("private key is unavailable")
	}
	encodedLength := base64.RawURLEncoding.EncodedLen(ed25519.PrivateKeySize)
	raw, err := io.ReadAll(io.LimitReader(file, int64(encodedLength+1)))
	if err != nil || len(raw) != encodedLength {
		return nil, errors.New("invalid private key encoding")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(string(raw))
	if err != nil || len(decoded) != ed25519.PrivateKeySize || base64.RawURLEncoding.EncodeToString(decoded) != string(raw) {
		return nil, errors.New("invalid private key encoding")
	}
	key := ed25519.PrivateKey(append([]byte(nil), decoded...))
	expected := ed25519.NewKeyFromSeed(key.Seed())
	if subtle.ConstantTimeCompare(expected, key) != 1 {
		return nil, errors.New("invalid private key")
	}
	return key, nil
}

func safePrivateKeyParent(info os.FileInfo) bool {
	return info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o027 == 0 && rootOwnsGroupAccessiblePath(info)
}
