//go:build !windows

package main

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func privateHookTokenFile(_ string, info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 &&
		info.Mode().Perm()&0o077 == 0 && info.Mode().Perm()&0o400 != 0 &&
		stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1 // #nosec G115 -- effective UID is nonnegative and represented by uid_t.
}

func openHookTokenFile(path string) (*os.File, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0) // #nosec G304 -- absolute operator-selected path is validated before and after this no-follow open.
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(descriptor), path), nil // #nosec G115 -- successful descriptors are nonnegative.
}
