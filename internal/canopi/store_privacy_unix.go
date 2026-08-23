//go:build !windows

package canopi

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func secureStateDirectory(path string, before os.FileInfo) error {
	if !ownedStateDirectory(before) {
		return errors.New("canopi state parent must be owned by the current user")
	}
	// #nosec G302 -- the current user's state directory is deliberately owner-only.
	if err := os.Chmod(path, 0o700); err != nil {
		return err
	}
	after, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !after.IsDir() || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, after) ||
		!ownedStateDirectory(after) || after.Mode().Perm()&0o077 != 0 {
		return errors.New("canopi state parent changed while securing it")
	}
	return nil
}

func ownedStateDirectory(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) // #nosec G115 -- effective UID is nonnegative and represented by uid_t.
}

func privateStateFile(_ string, info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 &&
		info.Mode().Perm()&0o077 == 0 && info.Mode().Perm()&0o400 != 0 &&
		stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1 // #nosec G115 -- effective UID is nonnegative and represented by uid_t.
}

func openStateFile(path string) (*os.File, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0) // #nosec G304 -- absolute operator-selected path is validated before and after this no-follow open.
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(descriptor), path), nil // #nosec G115 -- successful descriptors are nonnegative.
}

func protectStateFile(_ string, file *os.File) error {
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil || !privateStateFile("", info) {
		return errors.New("canopi state temporary is not private")
	}
	return nil
}
