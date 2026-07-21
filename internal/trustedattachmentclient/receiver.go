// Package trustedattachmentclient implements the bounded native client side of
// Punaro's authenticated trusted-relay attachment protocol.
package trustedattachmentclient

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	maxDownloadBytes       int64 = 16 << 30
	maxConcurrentReceivers       = 4
	maxDisplayNameBytes          = 1020
	maxDisplayNameRunes          = 255
	maxSafeRootEntries           = 10000
	staleStageAge                = 24 * time.Hour
)

var (
	// ErrDestinationExists reports a safe no-replace conflict.
	ErrDestinationExists = errors.New("attachment destination already exists")
	// ErrIntegrity reports an exact size or digest mismatch.
	ErrIntegrity = errors.New("attachment integrity check failed")
)

// DownloadMetadata is the authenticated immutable declaration supplied by the
// trusted relay before the first body byte.
type DownloadMetadata struct {
	ArtifactID  string
	SizeBytes   int64
	SHA256      [sha256.Size]byte
	DisplayName string
	MediaType   string
}

func (metadata DownloadMetadata) valid() bool {
	return uuid.Validate(metadata.ArtifactID) == nil && metadata.SizeBytes >= 1 && metadata.SizeBytes <= maxDownloadBytes && metadata.DisplayName != "" && len(metadata.DisplayName) <= maxDisplayNameBytes && utf8.ValidString(metadata.DisplayName) && utf8.RuneCountInString(metadata.DisplayName) <= maxDisplayNameRunes && metadata.MediaType != ""
}

// Receiver owns an already-open safe root. os.Root keeps operations attached
// to the opened directory even if an attacker renames or replaces its path.
type Receiver struct {
	root *os.Root
}

// NewReceiver opens the configured safe download root without creating it.
func NewReceiver(path string) (*Receiver, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil || !pathInfo.IsDir() || pathInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("safe download root is unavailable")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, errors.New("safe download root is unavailable")
	}
	info, err := root.Stat(".")
	if err != nil || !info.IsDir() || !os.SameFile(pathInfo, info) {
		_ = root.Close()
		return nil, errors.New("safe download root is invalid")
	}
	if err := cleanupStaleStages(root, time.Now()); err != nil {
		_ = root.Close()
		return nil, err
	}
	return &Receiver{root: root}, nil
}

func cleanupStaleStages(root *os.Root, now time.Time) error {
	directory, err := root.Open(".")
	if err != nil {
		return errors.New("safe download root exceeds cleanup bound")
	}
	entries, readErr := directory.ReadDir(maxSafeRootEntries + 1)
	closeErr := directory.Close()
	if errors.Is(readErr, io.EOF) {
		readErr = nil
	}
	err = errors.Join(readErr, closeErr)
	if err != nil || len(entries) > maxSafeRootEntries {
		return errors.New("safe download root exceeds cleanup bound")
	}
	changed := false
	for _, entry := range entries {
		if !privateStageName(entry.Name()) {
			continue
		}
		info, err := root.Lstat(entry.Name())
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("safe download stage namespace is unsafe")
		}
		if info.ModTime().After(now.Add(-staleStageAge)) {
			continue
		}
		if err := root.Remove(entry.Name()); err != nil {
			return errors.New("stale attachment stage cannot be retired")
		}
		changed = true
	}
	if changed {
		_ = syncRoot(root)
	}
	return nil
}

func privateStageName(name string) bool {
	const prefix = ".punaro-"
	const suffix = ".part"
	if len(name) != len(prefix)+36+1+32+len(suffix) || !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) || name[len(prefix)+36] != '-' {
		return false
	}
	if uuid.Validate(name[len(prefix):len(prefix)+36]) != nil {
		return false
	}
	nonce := name[len(prefix)+37 : len(name)-len(suffix)]
	decoded, err := hex.DecodeString(nonce)
	return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == nonce
}

// Close releases the safe-root handle.
func (receiver *Receiver) Close() error {
	if receiver == nil || receiver.root == nil {
		return nil
	}
	return receiver.root.Close()
}

// Receive verifies one exact stream into a private hidden stage and makes it
// visible with a same-directory hard link, whose create fails if the final
// name already exists. The returned value is a root-relative safe name.
func (receiver *Receiver) Receive(ctx context.Context, metadata DownloadMetadata, source io.Reader) (string, error) {
	if receiver == nil || receiver.root == nil || source == nil || !metadata.valid() {
		return "", errors.New("invalid attachment download")
	}
	stageName, err := randomStageName(metadata.ArtifactID)
	if err != nil {
		return "", err
	}
	stage, err := receiver.root.OpenFile(stageName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", errors.New("attachment stage is unavailable")
	}
	stagePresent := true
	defer func() {
		_ = stage.Close()
		if stagePresent {
			_ = receiver.root.Remove(stageName)
		}
	}()
	hasher := sha256.New()
	written, err := copyDownload(ctx, io.MultiWriter(stage, hasher), source, metadata.SizeBytes+1)
	if err != nil {
		return "", err
	}
	if written != metadata.SizeBytes {
		return "", ErrIntegrity
	}
	var actual [sha256.Size]byte
	copy(actual[:], hasher.Sum(nil))
	if actual != metadata.SHA256 {
		return "", ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := stage.Sync(); err != nil {
		return "", errors.New("attachment stage cannot be synchronized")
	}
	if err := stage.Close(); err != nil {
		return "", errors.New("attachment stage cannot be closed")
	}
	name := safeDownloadName(metadata.DisplayName, metadata.ArtifactID)
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := receiver.root.Link(stageName, name); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return "", ErrDestinationExists
		}
		return "", errors.New("attachment destination cannot be finalized")
	}
	if err := syncRoot(receiver.root); err != nil {
		_ = receiver.root.Remove(name)
		return "", errors.New("attachment destination cannot be synchronized")
	}
	if err := receiver.root.Remove(stageName); err == nil {
		stagePresent = false
		// The visible link and file were already synchronized. Stage retirement
		// is cleanup-only after that commit point; a failed second directory
		// flush must not turn a correct visible file into an ambiguous failure.
		_ = syncRoot(receiver.root)
	}
	return name, nil
}

func randomStageName(artifactID string) (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", errors.New("attachment stage identity is unavailable")
	}
	return ".punaro-" + artifactID + "-" + hex.EncodeToString(nonce[:]) + ".part", nil
}

func copyDownload(ctx context.Context, destination io.Writer, source io.Reader, limit int64) (int64, error) {
	buffer := make([]byte, 64<<10)
	var total int64
	for total < limit {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		remaining := limit - total
		chunk := buffer
		if int64(len(chunk)) > remaining {
			chunk = chunk[:remaining]
		}
		read, readErr := source.Read(chunk)
		if read > 0 {
			written, writeErr := destination.Write(chunk[:read])
			total += int64(written)
			if writeErr != nil {
				return total, errors.New("attachment download stage write failed")
			}
			if written != read {
				return total, io.ErrShortWrite
			}
		}
		if errors.Is(readErr, io.EOF) {
			return total, nil
		}
		if readErr != nil {
			return total, errors.New("attachment download stream failed")
		}
		if read == 0 {
			return total, io.ErrNoProgress
		}
	}
	return total, nil
}

func safeDownloadName(displayName, artifactID string) string {
	fallback := "attachment-" + artifactID
	if displayName == "" || len(displayName) > 255 || !utf8.ValidString(displayName) || displayName == "." || displayName == ".." || strings.HasSuffix(displayName, ".") || strings.HasSuffix(displayName, " ") || privateStageName(displayName) {
		return fallback
	}
	for _, character := range displayName {
		if unicode.IsControl(character) || strings.ContainsRune(`<>:"/\\|?*`, character) {
			return fallback
		}
	}
	base := displayName
	if dot := strings.IndexByte(base, '.'); dot >= 0 {
		base = base[:dot]
	}
	switch strings.ToUpper(base) {
	case "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return fallback
	}
	return displayName
}
