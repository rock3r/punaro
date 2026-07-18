//go:build !windows

package v2

import "os"

func safePrivateKeyParent(info os.FileInfo) bool {
	return info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o027 == 0 && rootOwnsGroupAccessiblePath(info)
}

func safePrivateKeyFile(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o077 == 0
}
