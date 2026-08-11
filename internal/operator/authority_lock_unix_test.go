//go:build !windows

package operator

import (
	"os"
	"syscall"
	"testing"
)

func holdRelayAuthorityTestLock(t *testing.T, path string) func() {
	t.Helper()
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- fixed private test-installation child.
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { // #nosec G115 -- os.File descriptors are platform ints.
		_ = file.Close()
		t.Fatal(err)
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN) // #nosec G115 -- os.File descriptors are platform ints.
		_ = file.Close()
	}
}
