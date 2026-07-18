//go:build windows

package v2

import "os"

// Windows clients place durable state below the installer-created, exclusive
// current-user ACL. FileMode does not expose that ACL, so retain the type and
// no-reparse-point checks without applying POSIX permission-bit semantics.
func isPrivateStateParent(info os.FileInfo) bool {
	return info.IsDir() && info.Mode()&os.ModeSymlink == 0
}

func isPrivateStateFile(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}
