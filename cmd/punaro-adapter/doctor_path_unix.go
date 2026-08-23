//go:build !windows

package main

import (
	"os"
	"strconv"
	"syscall"
)

func privateDoctorDirectoryPlatform(_ string, info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && strconv.FormatUint(uint64(stat.Uid), 10) == strconv.Itoa(os.Geteuid()) && info.Mode().Perm()&0o077 == 0
}
