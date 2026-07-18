//go:build !windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func requirePrivateParent(path string) (os.FileInfo, error) {
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return nil, errors.New("output parent must be an existing private directory owned by the invoking user")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || int(stat.Uid) != os.Geteuid() {
		return nil, errors.New("output parent must be an existing private directory owned by the invoking user")
	}
	return info, nil
}

func sameDirectory(a, b os.FileInfo) bool {
	left, lok := a.Sys().(*syscall.Stat_t)
	right, rok := b.Sys().(*syscall.Stat_t)
	return lok && rok && left.Dev == right.Dev && left.Ino == right.Ino && left.Uid == right.Uid
}
