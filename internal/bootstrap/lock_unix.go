//go:build !windows

package bootstrap

import (
	"os"
	"syscall"
)

func lockDirectoryFile(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) // #nosec G115 -- os.File descriptors are platform ints.
}

func unlockDirectoryFile(file *os.File) {
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN) // #nosec G115 -- os.File descriptors are platform ints.
}
