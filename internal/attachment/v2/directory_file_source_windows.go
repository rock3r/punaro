//go:build windows

package v2

import "os"

// Punaro's relay is supported only on hardened Linux service hosts. A Windows
// build must therefore fail closed for group-readable snapshot paths, whose
// ACL ownership cannot be represented safely by POSIX mode bits.
func rootOwnsGroupAccessiblePath(info os.FileInfo) bool { return info.Mode().Perm()&0o070 == 0 }
