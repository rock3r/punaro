//go:build !windows

package backup

import (
	"os"
	"syscall"
)

func lockRestoreJournal(path string) (func(), error) {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- fixed private restore-journal child.
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { // #nosec G115 -- os.File descriptors are platform ints.
		_ = file.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN) // #nosec G115 -- os.File descriptors are platform ints.
		_ = file.Close()
	}, nil
}
