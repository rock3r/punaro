//go:build !windows

package canopiadapter

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func canonicalSpoolDirectory(path string) (string, error) {
	return filepath.EvalSymlinks(path)
}

func validateSpoolDirectoryAncestors(path string) error {
	current := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(filepath.Clean(path), current), current) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 && ownedSpoolDirectory(info) {
			return errors.New("canopi spool path must not traverse a current-user symlink")
		}
	}
	return nil
}

func prepareSpoolRepairCoordinator(string) error {
	return nil
}

func ownedSpoolDirectory(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	uid := os.Geteuid()
	return ok && uid >= 0 && stat.Uid == uint32(uid) // #nosec G115 -- nonnegative OS UID fits the platform field.
}

func privateSpoolDirectory(_ string, info os.FileInfo) bool {
	return ownedSpoolDirectory(info) && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o077 == 0
}

func secureSpoolDirectory(path string, before os.FileInfo) error {
	if !ownedSpoolDirectory(before) {
		return errors.New("canopi spool directory must be owned by the current user")
	}
	// #nosec G302 -- the current user's spool directory is deliberately owner-only.
	if err := os.Chmod(path, 0o700); err != nil {
		return err
	}
	after, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !after.IsDir() || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, after) ||
		!ownedSpoolDirectory(after) || after.Mode().Perm()&0o077 != 0 {
		return errors.New("canopi spool directory changed while securing it")
	}
	return nil
}

func privateSpoolFile(_ string, info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	uid := os.Geteuid()
	return ok && uid >= 0 && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 &&
		info.Mode().Perm()&0o077 == 0 && info.Mode().Perm()&0o400 != 0 &&
		stat.Uid == uint32(uid) // #nosec G115 -- nonnegative OS UID fits the platform field.
}

func openSpoolEventFile(path string) (*os.File, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0) // #nosec G304 -- path is inside the validated private spool and checked before and after.
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(descriptor), path), nil // #nosec G115 -- successful descriptors are nonnegative.
}

func protectSpoolFile(_ string, file *os.File) error {
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil || !privateSpoolFile("", info) {
		return errors.New("cannot protect queued Canopi event")
	}
	return nil
}
