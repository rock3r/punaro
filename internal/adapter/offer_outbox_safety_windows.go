//go:build windows

package adapter

import "os"

// The Windows installer grants an exclusive current-user ACL to the state
// root. FileMode cannot represent that ACL, so retain only type and
// no-reparse-point checks here.
func isPrivateOfferOutboxParent(info os.FileInfo) bool {
	return info.IsDir() && info.Mode()&os.ModeSymlink == 0
}

func isPrivateOfferOutboxFile(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}
