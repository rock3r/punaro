//go:build windows

package fleetconfig

import (
	"os"
	"syscall"
)

func destIsJunctionOrReparse(info os.FileInfo) bool {
	if info == nil {
		return false
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return true
	}
	data, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return ok && data.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
}
