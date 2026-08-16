//go:build windows

package bootstrap

import (
	"os"

	"golang.org/x/sys/windows"
)

func lockDirectoryFile(file *os.File) error {
	overlapped := new(windows.Overlapped)
	return windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, overlapped)
}

func unlockDirectoryFile(file *os.File) {
	overlapped := new(windows.Overlapped)
	_ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, overlapped)
}
