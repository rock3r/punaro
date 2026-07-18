//go:build windows

package main

import "os"

// The Windows installer gives the config directory an exclusive current-user
// ACL. Go does not surface that ACL in FileMode, so keep only the type and
// no-reparse-point checks at this boundary.
func safeX25519KeyParent(info os.FileInfo) bool {
	return info.IsDir() && info.Mode()&os.ModeSymlink == 0
}

func safeX25519KeyFile(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}
