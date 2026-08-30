//go:build windows

package fleetconfig

import (
	"io/fs"
	"os"

	"golang.org/x/sys/windows"
)

func extraHardLink(fs.FileInfo) bool { return false }

func extraHardLinkFile(file *os.File) bool {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err != nil {
		return true
	}
	return info.NumberOfLinks > 1
}
