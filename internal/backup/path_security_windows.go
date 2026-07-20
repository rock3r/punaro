//go:build windows

package backup

import (
	"errors"
	"os"
)

func trustedPrivateDirectory(path string) error { return privateDirectory(path) }

func trustedProtectedFile(path string, maximum int64) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maximum {
		return errors.New("protected file is unsafe")
	}
	return nil
}
