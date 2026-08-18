package bootstrap

import (
	"errors"
	"os"
	"path/filepath"
)

func lockDirectory(directory string) (func(), error) {
	return lockNamedFile(directory, lockFile, "bootstrap directory is busy")
}

func acquireRunLease(directory string) (func(), error) {
	unlock, err := lockNamedFile(directory, runLeaseFile, "bootstrap run is already active")
	if err != nil {
		return nil, err
	}
	if err := terminateStaleRun(directory); err != nil {
		unlock()
		return nil, err
	}
	return unlock, nil
}

func lockNamedFile(directory, name, busy string) (func(), error) {
	if err := requireRealDir(directory); err != nil {
		return nil, errors.New("bootstrap directory is invalid")
	}
	path := filepath.Join(directory, name)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304,G703 -- fixed lock child of the bootstrap directory.
	if err != nil {
		return nil, errors.New(busy)
	}
	if err := lockDirectoryFile(file); err != nil {
		_ = file.Close()
		return nil, errors.New(busy)
	}
	return func() {
		unlockDirectoryFile(file)
		_ = file.Close()
	}, nil
}
