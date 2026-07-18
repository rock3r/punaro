//go:build windows

package v2

import "os"

// The installer owns the ACL for configured Windows state. Retain the
// no-reparse-point/type boundary without treating POSIX mode bits as ACLs.
func safeDirectorySnapshotParent(info os.FileInfo) bool {
	return info.IsDir() && info.Mode()&os.ModeSymlink == 0
}

func safeDirectorySnapshotFile(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}
