//go:build windows

package v3

import (
	"errors"
	"os"
)

// The Windows installer applies an exclusive current-user ACL to the source
// store directory. Go's FileMode cannot represent that ACL; preserve the
// type and no-reparse-point checks without reinterpreting Unix mode bits.
func validateSourceStoreParent(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("unsafe source store parent")
	}
	return nil
}

func validateSourceStoreFile(path, message string) error {
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
