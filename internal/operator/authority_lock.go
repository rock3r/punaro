package operator

import (
	"fmt"
	"os"
	"path/filepath"
)

func acquireRelayAuthorityLock(directory string) (func(), error) {
	return acquireOperatorFileLock(directory, ".relay-authority.lock", "relay authority publication")
}

func acquireCatalogAcceptanceLock(directory string) (func(), error) {
	return acquireOperatorFileLock(directory, ".catalog-acceptance.lock", "catalog acceptance")
}

func acquireOperatorFileLock(directory, name, label string) (func(), error) {
	if requireTrustedPrivateDirectory(directory) != nil {
		return nil, fmt.Errorf("%s lock is unavailable", label)
	}
	path := filepath.Join(directory, name)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- fixed child of the validated private installation directory.
	if err != nil {
		return nil, fmt.Errorf("%s lock is unavailable", label)
	}
	fail := func() (func(), error) {
		_ = file.Close()
		return nil, fmt.Errorf("%s lock is unavailable", label)
	}
	opened, err := file.Stat()
	if err != nil || requireTrustedProtectedFile(path, 0) != nil {
		return fail()
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, current) {
		return fail()
	}
	if err := lockRelayAuthorityFile(file); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("another %s is already in progress", label)
	}
	return func() {
		unlockRelayAuthorityFile(file)
		_ = file.Close()
	}, nil
}
