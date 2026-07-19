//go:build !windows

package operator

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

func requireTrustedPrivateDirectory(path string) error {
	if err := requirePrivateDirectory(path); err != nil {
		return err
	}
	if !ownedByCurrentUser(path) {
		return errors.New("private directory must be owned by the current user")
	}
	return requireTrustedDirectoryAncestors(filepath.Dir(filepath.Clean(path)))
}

func requireTrustedProtectedFile(path string, maximum int64) error {
	if err := requireProtectedFile(path, maximum); err != nil {
		return err
	}
	if !ownedByCurrentUser(path) {
		return errors.New("protected file must be owned by the current user")
	}
	return requireTrustedDirectoryAncestors(filepath.Dir(filepath.Clean(path)))
}

func ownedByCurrentUser(path string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Getuid()
}

func runtimeIdentityMatches(installation Installation) bool {
	return installation.RuntimeUID == strconv.Itoa(os.Getuid()) && installation.RuntimeGID == strconv.Itoa(os.Getgid())
}

func requireTrustedDirectoryAncestors(path string) error {
	current := filepath.Clean(path)
	for {
		info, err := os.Lstat(current)
		if err != nil {
			return errors.New("installation path ancestors must exist")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != 0 {
				return errors.New("installation path may only traverse root-owned system symlinks")
			}
			if err := requireTrustedDirectoryAncestors(filepath.Dir(current)); err != nil {
				return err
			}
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil {
				return errors.New("installation path ancestors could not be resolved")
			}
			return requireResolvedDirectoryAncestors(resolved)
		}
		if !info.IsDir() {
			return errors.New("installation path ancestors must be directories")
		}
		if !trustedAncestor(info) {
			return errors.New("installation path ancestors must be owned by root or the current user")
		}
		if writableWithoutSticky(info) {
			return errors.New("installation path ancestors must not be group or world writable unless sticky")
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func requireResolvedDirectoryAncestors(path string) error {
	current := filepath.Clean(path)
	for {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("resolved installation path ancestors must be existing directories")
		}
		if !trustedAncestor(info) {
			return errors.New("resolved installation path ancestors must be owned by root or the current user")
		}
		if writableWithoutSticky(info) {
			return errors.New("resolved installation path ancestors must not be group or world writable unless sticky")
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func trustedAncestor(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && trustedAncestorUID(int(stat.Uid))
}

func trustedAncestorUID(uid int) bool {
	return uid == 0 || uid == os.Getuid()
}

func writableWithoutSticky(info os.FileInfo) bool {
	return info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0
}
