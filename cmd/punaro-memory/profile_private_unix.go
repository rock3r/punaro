//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"syscall"
)

func privateProfilePath(path string) bool {
	uid := os.Getuid()
	for directory := filepath.Dir(path); ; directory = filepath.Dir(directory) {
		info, err := os.Lstat(directory) // #nosec G703 -- deliberate component walk of an explicit absolute profile path.
		if err != nil {
			return false
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return false
		}
		if uid < 0 {
			return false
		}
		currentUID := uint32(uid) // #nosec G115 -- nonnegative OS UID fits the platform field.
		if stat.Uid != currentUID && stat.Uid != 0 {
			return false
		}
		if directory == filepath.Dir(directory) {
			return true
		}
	}
}

func privateProfileFile(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	uid := os.Getuid()
	return ok && uid >= 0 && stat.Uid == uint32(uid) && stat.Nlink == 1 && info.Mode().Perm()&0o077 == 0 // #nosec G115 -- nonnegative OS UID fits the platform field.
}
