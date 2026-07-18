//go:build !windows

package controller

import "os"

func syncReceiptOutputParent(parent string) error {
	// #nosec G304 -- parent was absolute, lstat-validated, and used for the
	// no-replace write boundary above.
	dir, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}

func safeCompletedReceiptOutput(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == 0o600
}
