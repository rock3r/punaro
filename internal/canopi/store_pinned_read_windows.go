//go:build windows

package canopi

import (
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func recoverPinnedStateReplacement(directory *os.File, targetName string) error {
	backupName := stateTemporaryPrefix(targetName) + "backup"
	backup, err := openPrivateStateFileInPinnedDirectory(directory, backupName)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return err
	}
	target, targetErr := openPrivateStateFileInPinnedDirectory(directory, targetName)
	if targetErr == nil {
		_ = target.Close()
		if err := discardPinnedWindowsStateFile(backup); err != nil {
			return err
		}
		return windows.FlushFileBuffers(windows.Handle(directory.Fd()))
	}
	if !errors.Is(targetErr, windows.ERROR_FILE_NOT_FOUND) && !errors.Is(targetErr, windows.ERROR_PATH_NOT_FOUND) {
		_ = backup.Close()
		return targetErr
	}
	if err := renamePinnedWindowsStateFile(directory, backup, targetName); err != nil {
		_ = backup.Close()
		return err
	}
	if err := backup.Close(); err != nil {
		return err
	}
	return windows.FlushFileBuffers(windows.Handle(directory.Fd()))
}

func openPrivateStateFileInPinnedDirectory(directory *os.File, targetName string) (*os.File, error) {
	objectName, err := windows.NewNTUnicodeString(targetName)
	if err != nil {
		return nil, err
	}
	oa := &windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), RootDirectory: windows.Handle(directory.Fd()), ObjectName: objectName, Attributes: windows.OBJ_DONT_REPARSE}
	var iosb windows.IO_STATUS_BLOCK
	var handle windows.Handle
	if err := windows.NtCreateFile(&handle, windows.FILE_GENERIC_READ|windows.DELETE, oa, &iosb, nil, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0); err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), targetName) // #nosec G115 -- successful Win32 handles are nonnegative.
	var details windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &details); err != nil || details.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || details.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || !privateStateWindowsACLHandle(file) {
		_ = file.Close()
		if err != nil {
			return nil, err
		}
		return nil, os.ErrInvalid
	}
	return file, nil
}
