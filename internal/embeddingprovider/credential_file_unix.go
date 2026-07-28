//go:build !windows

package embeddingprovider

import (
	"os"
	"path/filepath"
	"syscall"
)

func privateAPIKeyPath(path string) bool {
	uid := os.Getuid()
	if uid < 0 {
		return false
	}
	currentUID := uint32(uid) // #nosec G115 -- nonnegative OS UID fits the platform field.
	for directory := filepath.Dir(path); ; directory = filepath.Dir(directory) {
		info, err := os.Lstat(directory)
		if err != nil {
			return false
		}
		if !trustedAPIKeyDirectory(info, currentUID) {
			return false
		}
		if directory == filepath.Dir(directory) {
			return true
		}
	}
}

func trustedAPIKeyDirectory(info os.FileInfo, currentUID uint32) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o022 == 0 && (stat.Uid == currentUID || stat.Uid == 0)
}

func privateAPIKeyFile(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	uid := os.Getuid()
	return ok && uid >= 0 && stat.Uid == uint32(uid) && stat.Nlink == 1 && info.Mode().Perm()&0o077 == 0 && info.Mode().Perm()&0o400 != 0 // #nosec G115 -- nonnegative OS UID fits the platform field.
}

func openAPIKeyFile(path string) (*os.File, error) {
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(descriptor), path), nil // #nosec G115 -- successful syscall descriptors are nonnegative.
}
