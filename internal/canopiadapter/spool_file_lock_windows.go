//go:build windows

package canopiadapter

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func withSpoolRepairLock(ctx context.Context, path string, repair func() error) error {
	coordinatorPath := filepath.Join(filepath.Dir(path), ".canopi-spool-repair.lock")
	file, err := openSpoolRepairCoordinator(coordinatorPath)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	for {
		acquired, err := tryLockSpoolFile(file)
		if err != nil {
			return err
		}
		if acquired {
			break
		}
		timer := time.NewTimer(enqueueLockPoll)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
	defer func() { _ = unlockSpoolFile(file) }()
	return repair()
}

func openSpoolRepairCoordinator(path string) (*os.File, error) {
	for range 4 {
		file, err := createSpoolLockFile(path)
		if err == nil {
			if err := protectSpoolFile(path, file); err != nil {
				_ = file.Close()
				_ = os.Remove(path)
				return nil, err
			}
			if err := syncDirectory(filepath.Dir(path)); err != nil {
				_ = file.Close()
				return nil, err
			}
			return file, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		before, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !privateSpoolFile(path, before) {
			return nil, errors.New("canopi spool repair coordinator is unsafe; remove it during preflight")
		}
		file, err = openExistingSpoolLockFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		after, err := file.Stat()
		if err == nil && os.SameFile(before, after) && privateSpoolFile(path, after) {
			return file, nil
		}
		_ = file.Close()
		if err != nil {
			return nil, err
		}
	}
	return nil, errors.New("cannot replace unprotected Canopi spool repair coordinator")
}

func finalWindowsSpoolPath(path string) (string, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	handle, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return "", err
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	const maxFinalPathCharacters = 32_768
	buffer := make([]uint16, maxFinalPathCharacters)
	length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], maxFinalPathCharacters, 0)
	if err != nil {
		return "", err
	}
	if length >= maxFinalPathCharacters {
		return "", errors.New("canonical Windows spool path exceeds limit")
	}
	return windows.UTF16ToString(buffer[:length]), nil
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
	var security *windows.SecurityAttributes
	if disposition == windows.CREATE_NEW {
		sid := currentWindowsSpoolSID()
		if sid == nil {
			return nil, errors.New("cannot identify the current user for a Canopi spool lock")
		}
		descriptor, descriptorErr := windows.SecurityDescriptorFromString("O:" + sid.String() + "D:P(A;;FA;;;" + sid.String() + ")")
		if descriptorErr != nil {
			return nil, descriptorErr
		}
		security = &windows.SecurityAttributes{
			Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})), // #nosec G115 -- Windows ABI structure size fits DWORD.
			SecurityDescriptor: descriptor,
		}
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, security, disposition, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0) // #nosec G304 -- fixed lock name is inside the validated private spool and opened without following reparse points.
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
