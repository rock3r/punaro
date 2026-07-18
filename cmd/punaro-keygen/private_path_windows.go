//go:build windows

package main

import "os"

// Windows ownership is represented by ACLs rather than POSIX mode/UID bits.
// The Windows client installer applies an exclusive current-user ACL before
// generating material; these checks retain the non-symlink file-type guard.
func isPrivateOwnedDirectory(info os.FileInfo) bool {
	return info.IsDir() && info.Mode()&os.ModeSymlink == 0
}

func isPrivateOwnedRegularFile(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}
