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

// stateDirectoryIdentity records the already-validated directory that owns a
// persistent store's lifetime lock. Persisting through a path that has since
// been replaced would otherwise write alongside a different collector lock.
func stateDirectoryIdentity(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("canopi state parent must be a real directory")
	}
	return info, nil
}

func validateStateDirectoryIdentity(path string, expected os.FileInfo) error {
	current, err := stateDirectoryIdentity(path)
	if err != nil {
		return err
	}
	if !os.SameFile(expected, current) {
		return errors.New("canopi state parent changed while store was open")
	}
	return nil
}
