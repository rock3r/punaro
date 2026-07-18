package v2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// DirectorySnapshotFileSource exposes an operator-published complete directory
// snapshot. The file may be atomically replaced; it is validated on every read
// and is never cached. The private parent requirement prevents an untrusted
// local user from turning a signed snapshot endpoint into a denial-of-service
// or metadata oracle.
type DirectorySnapshotFileSource struct{ path string }

// OpenDirectorySnapshotFileSource validates the local publication path. The
// snapshot itself need not contain a secret, but it remains service-private so
// an untrusted local account cannot replace or probe it.
func OpenDirectorySnapshotFileSource(path string) (*DirectorySnapshotFileSource, error) {
	if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) {
		return nil, errors.New("directory snapshot path must be absolute")
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || !safeDirectorySnapshotParent(info) {
		return nil, errors.New("directory snapshot parent must be private and non-symlinked")
	}
	if info, err := os.Lstat(path); err == nil {
		if !safeDirectorySnapshotFile(info) {
			return nil, errors.New("directory snapshot file must be private and non-symlinked")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect directory snapshot: %w", err)
	}
	return &DirectorySnapshotFileSource{path: path}, nil
}

// CurrentDirectorySnapshot reads a new file descriptor each time so an atomic
// publication replacement becomes visible immediately. It rejects a changed
// path type, oversized input, and anything other than the exact canonical
// complete snapshot wire format.
func (s *DirectorySnapshotFileSource) CurrentDirectorySnapshot() ([]byte, error) {
	if s == nil || s.path == "" {
		return nil, errors.New("directory snapshot source is unavailable")
	}
	parent, err := os.Lstat(filepath.Dir(s.path))
	if err != nil || !safeDirectorySnapshotParent(parent) {
		return nil, errors.New("directory snapshot source is unavailable")
	}
	info, err := os.Lstat(s.path)
	if err != nil || !safeDirectorySnapshotFile(info) {
		return nil, errors.New("directory snapshot source is unavailable")
	}
	// #nosec G304,G703 -- the path was explicitly configured locally and is
	// checked as a private non-symlinked regular file before opening.
	file, err := os.Open(s.path)
	if err != nil {
		return nil, errors.New("directory snapshot source is unavailable")
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, errors.New("directory snapshot source is unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxDirectorySnapshotEncodedBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxDirectorySnapshotEncodedBytes {
		return nil, errors.New("directory snapshot source is unavailable")
	}
	if _, err := DecodeDirectorySnapshot(raw); err != nil {
		return nil, errors.New("directory snapshot source is unavailable")
	}
	return append([]byte(nil), raw...), nil
}

// A separately privileged publisher may own the path while the relay runs in
// its non-writable service group. Group read/execute on the directory and
// group read on the snapshot are therefore safe; writes and all world access
// would let an untrusted account replace or probe the configured authority.
func safeDirectorySnapshotParent(info os.FileInfo) bool {
	return info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o027 == 0 && rootOwnsGroupAccessiblePath(info)
}

func safeDirectorySnapshotFile(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o037 == 0 && rootOwnsGroupAccessiblePath(info)
}

// FetchDirectorySnapshot makes the private publisher usable as the daemon's
// fresh authority source. Context is accepted for the common fetcher contract;
// local bounded file I/O has no independently cancellable operation.
func (s *DirectorySnapshotFileSource) FetchDirectorySnapshot(_ context.Context) (DirectorySnapshot, error) {
	raw, err := s.CurrentDirectorySnapshot()
	if err != nil {
		return DirectorySnapshot{}, err
	}
	return DecodeDirectorySnapshot(raw)
}
