//go:build windows

package canopi

import (
	"os"

	"golang.org/x/sys/windows"
)

func openPinnedStateDirectory(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0) // #nosec G304 -- the canonical state directory is validated before it is opened.
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil // #nosec G115 -- successful Win32 handles are nonnegative.
}
