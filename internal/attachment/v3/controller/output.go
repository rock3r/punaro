package controller

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
)

// WriteCompletedReceiptAtomically decrypts a fully verified v3 artifact and
// publishes plaintext only through an fsync+rename boundary. Callers must use
// it after their durable complete result: no partial or unauthenticated bytes
// are ever written to the requested destination.
func WriteCompletedReceiptAtomically(destination string, rawManifest []byte, chunks []attachmentv3.EncryptedChunk, fileKey [32]byte, directory attachmentv3.DirectoryKeyResolver, nowUnix int64) error {
	if destination == "" || !filepath.IsAbs(destination) || nowUnix < 0 {
		return errors.New("invalid receipt output destination")
	}
	parent := filepath.Dir(destination)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("receipt output parent is unavailable")
	}
	if existing, err := os.Lstat(destination); err == nil || !os.IsNotExist(err) {
		if err == nil && !existing.Mode().IsRegular() {
			return errors.New("receipt output destination is unsafe")
		}
		return errors.New("receipt output destination already exists")
	}
	plaintext, err := attachmentv3.OpenSourceArtifact(rawManifest, chunks, fileKey, directory, time.Unix(nowUnix, 0).UTC())
	if err != nil {
		return errors.New("invalid completed receipt artifact")
	}
	tmp, err := os.CreateTemp(parent, ".punaro-receipt-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(plaintext); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, destination); err != nil {
		return err
	}
	dir, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
