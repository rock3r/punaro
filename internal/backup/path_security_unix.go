//go:build !windows

package backup

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func trustedPrivateDirectory(path string) error {
	if err := privateDirectory(path); err != nil || !ownedByCurrentUser(path) {
		return errors.New("private directory ownership is unsafe")
	}
	return trustedDirectoryAncestors(filepath.Dir(filepath.Clean(path)))
}

func trustedProtectedFile(path string, maximum int64) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maximum || info.Mode().Perm()&0o077 != 0 || !ownedByCurrentUser(path) {
		return errors.New("protected file is unsafe")
	}
	return trustedDirectoryAncestors(filepath.Dir(filepath.Clean(path)))
}

func ownedByCurrentUser(path string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Getuid()
}

func trustedDirectoryAncestors(path string) error {
	current := filepath.Clean(path)
	for {
		info, err := os.Lstat(current)
		if err != nil {
			return errors.New("path ancestors must exist")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != 0 {
				return errors.New("path may only traverse root-owned system symlinks")
			}
			if err := trustedDirectoryAncestors(filepath.Dir(current)); err != nil {
				return err
			}
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil {
				return errors.New("path ancestors cannot be resolved")
			}
			return trustedResolvedAncestors(resolved)
		}
		if !info.IsDir() || !trustedAncestor(info) || writableWithoutSticky(info) {
			return errors.New("path ancestor is unsafe")
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func trustedResolvedAncestors(path string) error {
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !trustedAncestor(info) || writableWithoutSticky(info) {
			return errors.New("resolved path ancestor is unsafe")
		}
		if filepath.Dir(current) == current {
			return nil
		}
	}
}

func trustedAncestor(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && (stat.Uid == 0 || int(stat.Uid) == os.Getuid())
}

func writableWithoutSticky(info os.FileInfo) bool {
	return info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0
}
