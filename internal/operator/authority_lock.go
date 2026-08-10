package operator

import (
	"errors"
	"os"
	"path/filepath"
)

func acquireRelayAuthorityLock(directory string) (func(), error) {
	if requireTrustedPrivateDirectory(directory) != nil {
		return nil, errors.New("relay authority publication lock is unavailable")
	}
	path := filepath.Join(directory, ".relay-authority.lock")
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- fixed child of the validated private installation directory.
	if err != nil {
		return nil, errors.New("relay authority publication lock is unavailable")
	}
	fail := func() (func(), error) {
		_ = file.Close()
		return nil, errors.New("relay authority publication lock is unavailable")
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
		return nil, errors.New("another relay authority publication is already in progress")
	}
	return func() {
		unlockRelayAuthorityFile(file)
		_ = file.Close()
	}, nil
}
