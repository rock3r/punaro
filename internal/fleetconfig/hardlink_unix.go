//go:build unix

package fleetconfig

import (
	"io/fs"
	"os"
	"syscall"
)

func extraHardLink(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink > 1
}

func extraHardLinkFile(file *os.File) bool {
	info, err := file.Stat()
	return err != nil || extraHardLink(info)
}
