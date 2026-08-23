//go:build !windows

package canopi

import (
	"path/filepath"
)

func canonicalStateLockIdentity(path string) (string, error) {
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, filepath.Base(path)), nil
}
