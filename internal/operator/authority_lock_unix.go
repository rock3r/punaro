//go:build !windows

package operator

import (
	"os"
	"syscall"
)

func lockRelayAuthorityFile(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) // #nosec G115 -- os.File descriptors are platform ints.
}

func unlockRelayAuthorityFile(file *os.File) {
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN) // #nosec G115 -- os.File descriptors are platform ints.
}
