//go:build !windows

package v2

import (
	"os"
	"syscall"
)

// A path that grants any group access must be owned by the privileged
// publisher, not by the relay process that consumes it. Paths with no group
// access retain the conventional single-service owner-only deployment model.
func rootOwnsGroupAccessiblePath(info os.FileInfo) bool {
	if info.Mode().Perm()&0o070 == 0 {
		return true
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0
}

// A separately privileged publisher may own the path while the relay runs in
// its non-writable service group. Group read/execute on the directory and
// group read on the snapshot are therefore safe; writes and all world access
// would let an untrusted account replace or probe the configured authority.
func safeDirectorySnapshotParent(info os.FileInfo) bool {
	return info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o027 == 0 && rootOwnsGroupAccessiblePath(info)
}

func safeDirectorySnapshotFile(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o037 == 0 && rootOwnsGroupAccessiblePath(info)
}
