//go:build windows

package canopi

import (
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func withStateRepairLock(path string, repair func() error) error {
	coordinatorPath := filepath.Join(filepath.Dir(path), ".canopi-state-repair.lock")
	file, err := openStateRepairCoordinator(coordinatorPath)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	if err := lockStateFile(file); err != nil {
		return err
	}
	defer func() { _ = unlockStateFile(file) }()
	return repair()
}

func openStateRepairCoordinator(path string) (*os.File, error) {
	for range 4 {
		file, err := createStateLockFile(path)
		if err == nil {
			if err := protectStateFile(path, file); err != nil {
				_ = file.Close()
				_ = os.Remove(path)
				return nil, err
			}
			if err := syncStateDirectory(filepath.Dir(path)); err != nil {
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
		if !privateStateFile(path, before) {
			removed, err := removeStateLockIfSame(path, before)
			if err != nil {
				return nil, err
			}
			if removed {
				if err := syncStateDirectory(filepath.Dir(path)); err != nil {
					return nil, err
				}
			}
			continue
		}
		file, err = openExistingStateLockFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		after, err := file.Stat()
		if err == nil && os.SameFile(before, after) && privateStateFile(path, after) {
			return file, nil
		}
		_ = file.Close()
		if err != nil {
			return nil, err
		}
	}
	return nil, errors.New("cannot replace unprotected Canopi state repair coordinator")
}

func tryLockStateFile(file *os.File) (bool, error) {
	var overlapped windows.Overlapped
	err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return false, nil
	}
	return err == nil, err
}

func lockStateFile(file *os.File) error {
	var overlapped windows.Overlapped
	return windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlapped)
}

func createStateLockFile(path string) (*os.File, error) {
	return openWindowsStateLockFile(path, windows.CREATE_NEW)
}

func openExistingStateLockFile(path string) (*os.File, error) {
	return openWindowsStateLockFile(path, windows.OPEN_EXISTING)
}

func openWindowsStateLockFile(path string, disposition uint32) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var security *windows.SecurityAttributes
	if disposition == windows.CREATE_NEW {
		user, userErr := windows.GetCurrentProcessToken().GetTokenUser()
		if userErr != nil || user.User.Sid == nil {
			return nil, errors.New("cannot identify the current user for a Canopi state lock")
		}
		descriptor, descriptorErr := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")")
		if descriptorErr != nil {
			return nil, descriptorErr
		}
		security = &windows.SecurityAttributes{
			Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})), // #nosec G115 -- Windows ABI structure size fits DWORD.
			SecurityDescriptor: descriptor,
		}
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, security, disposition, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0) // #nosec G304 -- fixed lock name is inside the validated private state directory and opened without following reparse points.
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

func unlockStateFile(file *os.File) error {
	var overlapped windows.Overlapped
	return windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlapped)
}
