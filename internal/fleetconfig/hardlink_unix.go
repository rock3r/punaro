//go:build unix

package fleetconfig

import (
	"io/fs"
	"syscall"
)

func extraHardLink(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink > 1
}
