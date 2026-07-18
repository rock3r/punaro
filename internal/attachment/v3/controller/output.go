package controller

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"time"

	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
	"github.com/zeebo/blake3"
)

// WriteCompletedReceiptAtomically decrypts a fully verified v3 artifact and
// publishes plaintext only through an fsync+no-replace boundary. Callers must use
// it after their durable complete result: no partial or unauthenticated bytes
// are ever written to the requested destination.
func WriteCompletedReceiptAtomically(destination string, rawManifest []byte, chunks []attachmentv3.EncryptedChunk, fileKey [32]byte, directory attachmentv3.RetainedManifestAuthorityResolver, nowUnix int64) error {
	if nowUnix < 0 {
		return errors.New("invalid receipt output destination")
	}
	if err := validateReceiptOutputDestination(destination); err != nil {
		return err
	}
	parent := filepath.Dir(destination)
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
	// Link is deliberately used instead of rename: after the preflight above,
	// another local process could create destination. A same-directory hard link
	// atomically fails when that name already exists, whereas rename would
	// replace an attacker- or operator-created file. The temporary file and its
	// final name are in the same directory, so this cannot cross filesystems.
	if err := os.Link(tmpName, destination); err != nil {
		return err
	}
	if err := os.Remove(tmpName); err != nil {
		return err
	}
	return syncReceiptOutputParent(parent)
}

// validateReceiptOutputDestination is the pre-acceptance filesystem gate for
// a caller-selected destination. The final writer repeats equivalent checks
// and uses hard-link no-replace, so a local race cannot convert this preflight
// into an overwrite.
func validateReceiptOutputDestination(destination string) error {
	if destination == "" || !filepath.IsAbs(destination) {
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
	return nil
}

// completedReceiptOutputMatches is used only to recover the narrow crash
// window after no-replace publication but before the journal's written marker.
// It does not trust an existing filename: the file must be regular, private,
// bounded, and match the already authenticated manifest plaintext commitment.
func completedReceiptOutputMatches(record receiptDownloadRecord) (bool, error) {
	manifest, err := attachmentv3.DecodeManifest(record.manifest)
	if err != nil || manifest.TransferID != record.transferID || blake3.Sum256(record.manifest) != record.manifestCommitment || !filepath.IsAbs(record.outputPath) {
		return false, errors.New("invalid durable receipt output")
	}
	info, err := os.Lstat(record.outputPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	// #nosec G115 -- regular-file size is nonnegative before conversion.
	if err != nil || !safeCompletedReceiptOutput(info) || uint64(info.Size()) != manifest.PlaintextSize || manifest.PlaintextSize > 64<<20 {
		return false, errors.New("unsafe existing receipt output")
	}
	plain, err := os.ReadFile(record.outputPath)
	if err != nil || uint64(len(plain)) != manifest.PlaintextSize {
		return false, errors.New("unsafe existing receipt output")
	}
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], manifest.PlaintextSize)
	commitment := blake3.Sum256(append(append(append([]byte("punaro/attachment/plaintext/v3\x00"), manifest.ContentSalt[:]...), size[:]...), plain...))
	return bytes.Equal(commitment[:], manifest.PlaintextCommitment[:]), nil
}
