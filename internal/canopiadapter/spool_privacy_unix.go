//go:build !windows

package canopiadapter

import (
	"errors"
	"os"
	"syscall"
)

func ownedSpoolDirectory(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	uid := os.Geteuid()
	return ok && uid >= 0 && stat.Uid == uint32(uid) // #nosec G115 -- nonnegative OS UID fits the platform field.
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
