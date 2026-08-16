//go:build windows

package bootstrap

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func requireTrustedBootstrapDirectory(path string) error {
	info, err := os.Lstat(path) // #nosec G703 -- operator-selected absolute bootstrap directory.
	if err != nil || !info.IsDir() {
		return errors.New("bootstrap directory is invalid")
	}
	current := filepath.Clean(path)
	for {
		attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(current))
		if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || attributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return errors.New("bootstrap directory is invalid")
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}
