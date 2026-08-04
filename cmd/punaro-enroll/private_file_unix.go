//go:build !windows

package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func safeStateDir(path string) bool { return filepath.IsAbs(path) && filepath.Clean(path) == path }
func safeStateChild(directory, path string) bool {
	return safeStateDir(directory) && filepath.Dir(path) == directory && filepath.Base(path) != "." && filepath.Base(path) != ".."
}

func ensurePrivateDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
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
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path) // #nosec G115 -- unix.Open returns a non-negative descriptor for os.NewFile.
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !privateFile(info) {
		return nil, errors.New("unsafe private file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || len(raw) == 0 || len(raw) > maximum {
		return nil, errors.New("invalid private file")
	}
	return raw, nil
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

func syncPrivateDirectory(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	return unix.Fsync(fd)
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
	return writePrivateNew(path, []byte(credential+"\n"))
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
