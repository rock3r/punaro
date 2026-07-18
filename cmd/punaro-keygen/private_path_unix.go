//go:build !windows

package main

import (
	"os"
	"syscall"
)

func isPrivateOwnedDirectory(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o077 == 0 && int(stat.Uid) == os.Geteuid()
}

func isPrivateOwnedRegularFile(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o077 == 0 && int(stat.Uid) == os.Geteuid()
}
