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
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- path is derived inside the protected state directory.
	if err != nil {
		return nil, err
	}
	named, err := os.Lstat(path)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || named.Mode()&os.ModeSymlink != 0 || !os.SameFile(named, opened) {
		_ = file.Close()
		return nil, errors.New("canopi state lock changed while opening")
	}
	if err := protectStateFile(path, file); err != nil {
		_ = file.Close()
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

func stateStoreLockPath(statePath string) (string, error) {
	identity, err := canonicalStateLockIdentity(statePath)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(identity))
	return filepath.Join(filepath.Dir(identity), ".canopi-lock-"+hex.EncodeToString(digest[:8])), nil
}
