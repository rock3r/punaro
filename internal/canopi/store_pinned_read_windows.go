//go:build windows

package canopi

import (
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func pinnedWindowsStateDirectoryPath(directory *os.File) (string, error) {
	const maxFinalPathCharacters = 32_768
	buffer := make([]uint16, maxFinalPathCharacters)
	length, err := windows.GetFinalPathNameByHandle(windows.Handle(directory.Fd()), &buffer[0], maxFinalPathCharacters, 0)
	if err != nil || length >= maxFinalPathCharacters {
		return "", errors.New("resolve pinned Canopi state directory")
	}
	return windows.UTF16ToString(buffer[:length]), nil
}

func recoverPinnedStateReplacement(directory *os.File, targetName string) error {
	path, err := pinnedWindowsStateDirectoryPath(directory)
	if err != nil {
		return err
	}
	return recoverStateReplacement(filepath.Join(path, targetName))
}

func openPrivateStateFileInPinnedDirectory(directory *os.File, targetName string) (*os.File, error) {
	objectName, err := windows.NewNTUnicodeString(targetName)
	if err != nil {
		return nil, err
	}
	oa := &windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), RootDirectory: windows.Handle(directory.Fd()), ObjectName: objectName, Attributes: windows.OBJ_DONT_REPARSE}
	var iosb windows.IO_STATUS_BLOCK
	var handle windows.Handle
	if err := windows.NtCreateFile(&handle, windows.FILE_GENERIC_READ, oa, &iosb, nil, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0); err != nil {
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
