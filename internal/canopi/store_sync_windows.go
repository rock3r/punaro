//go:build windows

package canopi

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func stateReplacementBackup(path string) string {
	return filepath.Join(filepath.Dir(path), stateTemporaryPrefix(path)+"backup")
}

// recoverStateReplacement removes the old hard-link backup when the target is
// present, or durably restores it when a crash interrupted replacement.
func recoverStateReplacement(path string) error {
	backup := stateReplacementBackup(path)
	if _, err := os.Lstat(backup); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		if err := os.Remove(backup); err != nil {
			return err
		}
		return syncStateDirectory(filepath.Dir(path))
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := moveStateFile(backup, path, windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return err
	}
	return syncStateDirectory(filepath.Dir(path))
}

func replaceStateFile(temporary, target string) error {
	backup := stateReplacementBackup(target)
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if _, err := os.Lstat(target); err == nil {
		if err := os.Link(target, backup); err != nil {
			return err
		}
		if err := syncStateDirectory(filepath.Dir(target)); err != nil {
			return err
		}
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := moveStateFile(temporary, target, flags); err != nil {
		_ = recoverStateReplacement(target)
		return err
	}
	if flags&windows.MOVEFILE_REPLACE_EXISTING != 0 {
		if err := os.Remove(backup); err != nil {
			return err
		}
	}
	return syncStateDirectory(filepath.Dir(target))
}

func moveStateFile(source, target string, flags uint32) error {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, flags)
}

func syncStateDirectory(path string) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	return windows.FlushFileBuffers(handle)
}
