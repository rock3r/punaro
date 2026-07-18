//go:build windows

package controller

import "os"

// Windows does not support flushing a directory handle with the Unix fsync
// contract. The receipt file itself was flushed before the no-replace link;
// NTFS commits the metadata operation. The installer-owned ACL remains the
// privacy boundary for completed receipt paths.
func syncReceiptOutputParent(string) error { return nil }

func safeCompletedReceiptOutput(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}
