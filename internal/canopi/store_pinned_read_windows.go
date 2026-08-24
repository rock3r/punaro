//go:build windows

package canopi

import (
	"errors"
	"os"
	"path/filepath"

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
	path, err := pinnedWindowsStateDirectoryPath(directory)
	if err != nil {
		return nil, err
	}
	return openPrivateStateFile(filepath.Join(path, targetName))
}
