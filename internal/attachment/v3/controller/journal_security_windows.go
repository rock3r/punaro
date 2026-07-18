//go:build windows

package controller

import (
	"errors"
	"os"
)

// The Windows installer applies an exclusive current-user ACL to the local
// Punaro state directory. Go's FileMode cannot represent that ACL, so retain
// the type and no-reparse-point boundary here rather than interpreting POSIX
// permission bits that Windows does not provide.
func validateJournalParent(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("controller journal parent must be private and non-symlinked")
	}
	return nil
}

func validateJournalFile(path, message string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New(message)
	}
	return nil
}
