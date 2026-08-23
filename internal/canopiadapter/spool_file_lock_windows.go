//go:build windows

package canopiadapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

func withSpoolRepairLock(ctx context.Context, path string, repair func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	digest := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(path))))
	name, err := windows.UTF16PtrFromString("Local\\CanopiSpoolRepair-" + hex.EncodeToString(digest[:]))
	if err != nil {
		return err
	}
	mutex, err := windows.CreateMutex(nil, false, name)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	defer func() { _ = windows.CloseHandle(mutex) }()
	waitTimeout := uint32(windows.INFINITE)
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return ctx.Err()
		}
		milliseconds := (remaining + time.Millisecond - 1) / time.Millisecond
		if milliseconds < time.Duration(windows.INFINITE) {
			waitTimeout = uint32(milliseconds) // #nosec G115 -- value is bounded below INFINITE.
		}
	}
	wait, err := windows.WaitForSingleObject(mutex, waitTimeout)
	if wait == uint32(windows.WAIT_TIMEOUT) {
		return context.DeadlineExceeded
	}
	if err != nil || (wait != windows.WAIT_OBJECT_0 && wait != windows.WAIT_ABANDONED) {
		if err != nil {
			return err
		}
		return os.ErrInvalid
	}
	defer func() { _ = windows.ReleaseMutex(mutex) }()
	return repair()
}

func tryLockSpoolFile(file *os.File) (bool, error) {
	var overlapped windows.Overlapped
	err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return false, nil
	}
	return err == nil, err
}

func lockSpoolFile(file *os.File) error {
	var overlapped windows.Overlapped
	return windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlapped)
}

func createSpoolLockFile(path string) (*os.File, error) {
	return openWindowsSpoolLockFile(path, windows.CREATE_NEW)
}

func openExistingSpoolLockFile(path string) (*os.File, error) {
	return openWindowsSpoolLockFile(path, windows.OPEN_EXISTING)
}

func openWindowsSpoolLockFile(path string, disposition uint32) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, disposition, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0) // #nosec G304 -- fixed lock name is inside the validated private spool and opened without following reparse points.
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	var details windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &details); err != nil || details.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || details.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		_ = windows.CloseHandle(handle)
		if err != nil {
			return nil, err
		}
		return nil, os.ErrInvalid
	}
	return os.NewFile(uintptr(handle), path), nil // #nosec G115 -- successful Win32 handles are nonnegative.
}

func unlockSpoolFile(file *os.File) error {
	var overlapped windows.Overlapped
	return windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlapped)
}
