package bootstrap

import (
	"errors"
	"os"
	"path/filepath"
)

func lockDirectory(directory string) (func(), error) {
	if err := requireRealDir(directory); err != nil {
		return nil, errors.New("bootstrap directory is invalid")
	}
	path := filepath.Join(directory, lockFile)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304,G703 -- fixed lock child of the bootstrap directory.
	if err != nil {
		return nil, errors.New("bootstrap directory is busy")
	}
	if err := lockDirectoryFile(file); err != nil {
		_ = file.Close()
		return nil, errors.New("bootstrap directory is busy")
	}
	return func() {
		unlockDirectoryFile(file)
		_ = file.Close()
	}, nil
}
