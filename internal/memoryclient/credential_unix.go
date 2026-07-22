//go:build !windows

package memoryclient

import (
	"os"
	"path/filepath"
	"syscall"
)

func privateCredentialPath(path string) bool {
	for directory := filepath.Dir(path); ; directory = filepath.Dir(directory) {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return false
		}
		if directory == filepath.Dir(directory) {
			return true
		}
	}
}

func privateCredentialFile(_ string, info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	uid := os.Getuid()
	return ok && uid >= 0 && stat.Uid == uint32(uid) && stat.Nlink == 1 && info.Mode().Perm()&0o077 == 0 // #nosec G115 -- nonnegative OS UID fits the platform field.
}

func openCredential(path string) (*os.File, error) {
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(descriptor), path), nil // #nosec G115 -- successful syscall descriptors are nonnegative.
}
