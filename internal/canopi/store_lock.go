package canopi

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

func acquireStateStoreLock(statePath string) (func() error, error) {
	path, err := stateStoreLockPath(statePath)
	if err != nil {
		return nil, err
	}
	file, err := openStateLockFile(path)
	if err != nil {
		return nil, err
	}
	acquired, err := tryLockStateFile(file)
	if err != nil || !acquired {
		_ = file.Close()
		if err != nil {
			return nil, err
		}
		return nil, ErrStateStoreLocked
	}
	var once sync.Once
	var releaseErr error
	return func() error {
		once.Do(func() {
			if err := unlockStateFile(file); err != nil {
				releaseErr = err
			}
			if err := file.Close(); releaseErr == nil && err != nil {
				releaseErr = err
			}
		})
		return releaseErr
	}, nil
}

func openStateLockFile(path string) (*os.File, error) {
	for range 2 {
		file, err := createStateLockFile(path)
		if err == nil {
			if err := protectStateFile(path, file); err != nil {
				_ = file.Close()
				_ = os.Remove(path)
				return nil, err
			}
			return file, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		before, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !privateStateFile(path, before) {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
			if err := syncStateDirectory(filepath.Dir(path)); err != nil {
				return nil, err
			}
			continue
		}
		file, err = openExistingStateLockFile(path)
		if err != nil {
			return nil, err
		}
		after, err := file.Stat()
		if err != nil || !os.SameFile(before, after) || !privateStateFile(path, after) {
			_ = file.Close()
			return nil, errors.New("canopi state lock changed while opening")
		}
		return file, nil
	}
	return nil, errors.New("cannot replace unprotected Canopi state lock")
}

func stateStoreLockPath(statePath string) (string, error) {
	identity, err := canonicalStateLockIdentity(statePath)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(identity))
	return filepath.Join(filepath.Dir(identity), ".canopi-lock-"+hex.EncodeToString(digest[:8])), nil
}
