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
