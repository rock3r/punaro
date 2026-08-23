package canopi

import (
	"errors"
	"os"
)

func prepareStateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("canopi state parent must be a private real directory")
	}
	return secureStateDirectory(path, info)
}

func openPrivateStateFile(path string) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !privateStateFile(path, before) {
		return nil, errors.New("canopi state must be a private current-user-owned regular file")
	}
	file, err := openStateFile(path)
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !privateStateFile(path, after) {
		_ = file.Close()
		return nil, errors.New("canopi state changed while opening")
	}
	return file, nil
}
