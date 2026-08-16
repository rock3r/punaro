//go:build windows

package bootstrap

import (
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsAncestorWriteMask = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.DELETE

func requireTrustedBootstrapDirectory(path string) error {
	info, err := os.Lstat(path) // #nosec G703 -- operator-selected absolute bootstrap directory.
	if err != nil || !info.IsDir() {
		return errors.New("bootstrap directory is invalid")
	}
	world, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		return errors.New("bootstrap directory is invalid")
	}
	authenticated, err := windows.CreateWellKnownSid(windows.WinAuthenticatedUserSid)
	if err != nil {
		return errors.New("bootstrap directory is invalid")
	}
	current := filepath.Clean(path)
	for {
		attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(current))
		if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || attributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return errors.New("bootstrap directory is invalid")
		}
		if ancestorWritableByBroadSID(current, world, authenticated) {
			return errors.New("bootstrap directory is invalid")
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func ancestorWritableByBroadSID(path string, world, authenticated *windows.SID) bool {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return true
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return true
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, i, &ace) != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		if ace.Mask&windows.ACCESS_MASK(windowsAncestorWriteMask) == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) // #nosec G103 -- documented flexible-array start of this ACE SID.
		if sid.Equals(world) || sid.Equals(authenticated) {
			return true
		}
	}
	return false
}
