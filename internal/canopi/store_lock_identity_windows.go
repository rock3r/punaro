//go:build windows

package canopi

import (
	"errors"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func canonicalStateLockIdentity(path string) (string, error) {
	canonical, err := canonicalStatePath(path)
	if err != nil {
		return "", err
	}
	return strings.ToLower(canonical), nil
}

func canonicalStatePath(path string) (string, error) {
	parent, err := finalWindowsPath(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, filepath.Base(path)), nil
}

func finalWindowsPath(path string) (string, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	handle, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
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
		return "", errors.New("canonical Windows state path exceeds limit")
	}
	return windows.UTF16ToString(buffer[:length]), nil
}
