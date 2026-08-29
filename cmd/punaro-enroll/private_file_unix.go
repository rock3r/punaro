//go:build !windows

package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func safeStateDir(path string) bool { return filepath.IsAbs(path) && filepath.Clean(path) == path }
func safeStateChild(directory, path string) bool {
	return safeStateDir(directory) && filepath.IsAbs(path) && filepath.Clean(path) == path && filepath.Dir(path) == directory && filepath.Base(path) != "." && filepath.Base(path) != ".."
}

func reservedStateFileName(name string) bool {
	return strings.EqualFold(name, redemptionJournalName) || strings.EqualFold(name, redemptionLockName)
}

func lockEnrollmentState(stateDir string) (func(), error) {
	path := filepath.Join(stateDir, redemptionLockName)
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path) // #nosec G115 -- unix.Open returns a non-negative descriptor for os.NewFile.
	info, err := file.Stat()
	if err != nil || !privateFile(info) {
		_ = file.Close()
		return nil, errors.New("unsafe enrollment lock")
	}
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, err
	}
	return func() {
		_ = unix.Flock(fd, unix.LOCK_UN)
		_ = file.Close()
	}, nil
}

func ensurePrivateDir(path string) error {
	info, err := os.Lstat(path)
	if err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("unsafe private directory")
		}
		if err := privateDir(path); err != nil {
			return err
		}
		// A previous attempt may have created this state directory but failed
		// before its parent directory entry was durable. Re-sync that parent
		// before an existing state directory can be reused to publish a binding.
		return syncPrivateDirectory(filepath.Dir(path))
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	// Create one directory at a time so each newly published directory entry
	// can be synced before files are placed below it. MkdirAll cannot tell us
	// which entries this invocation created.
	missing := []string{path}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("unsafe private directory")
			}
			// A reused intermediate directory may have been created by an earlier
			// failed attempt. Re-sync its own parent before publishing children.
			if grandparent := filepath.Dir(parent); grandparent != parent {
				if err := syncPrivateDirectory(grandparent); err != nil {
					return err
				}
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) || parent == filepath.Dir(parent) {
			return err
		}
		missing = append(missing, parent)
	}
	for index := len(missing) - 1; index >= 0; index-- {
		directory := missing[index]
		if err := mkdirPrivateDirectory(directory, 0o700); err != nil {
			if !errors.Is(err, os.ErrExist) {
				return err
			}
			// A concurrent creator may have published the entry but crashed
			// before syncing its parent. Make that raced entry durable before
			// accepting it and publishing anything beneath it.
			if err := syncPrivateDirectory(filepath.Dir(directory)); err != nil {
				return err
			}
		} else if err := syncPrivateDirectory(filepath.Dir(directory)); err != nil {
			return err
		}
		if err := privateDir(directory); err != nil {
			return err
		}
	}
	return privateDir(path)
}
func privateDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || !ownedByCurrentUser(info) {
		return errors.New("unsafe private directory")
	}
	return nil
}
func readPrivate(path string, maximum int) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("unsafe private file")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !privateFile(info) {
		return nil, errors.New("unsafe private file")
	}
	// O_NONBLOCK avoids a FIFO replacement blocking between the pre-open
	// Lstat and the post-open fstat validation below.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path) // #nosec G115 -- unix.Open returns a non-negative descriptor for os.NewFile.
	defer func() { _ = file.Close() }()
	info, err = file.Stat()
	if err != nil || !privateFile(info) {
		return nil, errors.New("unsafe private file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || len(raw) == 0 || len(raw) > maximum {
		return nil, errors.New("invalid private file")
	}
	return raw, nil
}

func protectEnrollmentMaterial(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("unsafe enrollment material")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || !ownedByCurrentUser(before) || before.Size() < 1 || before.Size() > maxEnrollmentMaterial {
		return errors.New("unsafe enrollment material")
	}
	// Open without following a replacement link. O_NONBLOCK prevents a raced
	// FIFO from blocking before the post-open type and identity checks.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), path) // #nosec G115 -- unix.Open returns a non-negative descriptor for os.NewFile.
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !ownedByCurrentUser(opened) || opened.Size() < 1 || opened.Size() > maxEnrollmentMaterial || !os.SameFile(before, opened) {
		_ = file.Close()
		return errors.New("enrollment material changed while opening")
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) || !privateFile(after) || after.Size() < 1 || after.Size() > maxEnrollmentMaterial {
		return errors.New("protected enrollment material could not be verified")
	}
	return syncPrivateDirectory(filepath.Dir(path))
}

func writePrivateNew(path string, raw []byte) error {
	if len(raw) == 0 || !filepath.IsAbs(path) {
		return errors.New("unsafe private file")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- fixed child of the validated private state directory.
	if err != nil {
		return err
	}
	removeOnFailure := true
	defer func() {
		if removeOnFailure {
			_ = os.Remove(path) // #nosec G703 -- exclusive new child of the validated private state directory.
		}
	}()
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	// The private file is complete and durable at this point. Preserve it if
	// syncing the containing directory is unsupported or fails so a retry can
	// recover rather than being blocked by an erased post-write state.
	removeOnFailure = false
	if err := syncPrivateDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	return nil
}

func writePrivateAtomic(path string, raw []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	removeOnFailure := true
	defer func() {
		if removeOnFailure {
			_ = os.Remove(temporary)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	removeOnFailure = false
	return syncPrivateDirectory(filepath.Dir(path))
}

// writePrivateAtomicNew publishes a complete private file without replacing a
// destination created after the caller's preflight. Hard-link publication is
// atomic on the same filesystem and fails when the destination already exists.
func writePrivateAtomicNew(path string, raw []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporary)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Link(temporary, path); err != nil {
		return err
	}
	if err := os.Remove(temporary); err != nil {
		return err
	}
	removeTemporary = false
	return syncPrivateDirectory(filepath.Dir(path))
}

var (
	mkdirPrivateDirectory = os.Mkdir
	syncPrivateDirectory  = syncPrivateDirectoryImpl
)

func syncPrivateDirectoryImpl(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Fsync(fd); err != nil {
		// Some supported filesystems do not implement directory fsync. A global
		// synchronous flush is slower, but preserves the durable-publication
		// invariant without allowing an already-written journal to poison all
		// later recovery attempts.
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) {
			if err := syncAllFilesystems(); err != nil {
				return err
			}
			return nil
		}
		return err
	}
	return nil
}

func removePrivate(path string) error {
	if err := os.Remove(path); err != nil {
		return err
	}
	if err := syncPrivateDirectory(filepath.Dir(path)); err != nil {
		// The credential is already safely persisted when this is called. A
		// journal that survives a crash is harmless: recovering it replays the
		// same idempotency key. Do not convert a successful enrollment into a
		// failure merely because its best-effort cleanup could not be synced.
		_ = syncAllFilesystems() // Best-effort cleanup must not turn a completed enrollment into a failure.
	}
	return nil
}
func writeCredential(path, credential string) error {
	if credential == "" || stringsContainsWhitespace(credential) {
		return errors.New("invalid credential")
	}
	if raw, err := readPrivate(path, maxEnrollmentFile); err == nil {
		if string(raw) == credential+"\n" {
			return nil
		}
		return errors.New("credential exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writePrivateAtomicNew(path, []byte(credential+"\n"))
}
func privateFile(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode().Perm()&0o077 == 0 && ownedByCurrentUser(info)
}
func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) // #nosec G115 -- effective UID is non-negative and represents uid_t.
}
func stringsContainsWhitespace(value string) bool {
	for _, r := range value {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return true
		}
	}
	return false
}
