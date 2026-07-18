//go:build windows

package v2

import "os"

// The installer owns the Windows ACL for the configured key directory. These
// guards preserve the no-reparse-point/type boundary that Go can verify.
func safePrivateKeyParent(info os.FileInfo) bool {
	return info.IsDir() && info.Mode()&os.ModeSymlink == 0
}

func safePrivateKeyFile(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}
