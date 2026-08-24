//go:build !windows

package canopi

import (
	"path/filepath"
)

func canonicalStatePath(path string) (string, error) {
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, filepath.Base(path)), nil
}

func canonicalStateLockIdentity(path string) (string, error) {
	return canonicalStatePath(path)
}
