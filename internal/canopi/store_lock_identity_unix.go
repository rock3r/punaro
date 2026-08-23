//go:build !windows

package canopi

import "path/filepath"

func canonicalStateLockIdentity(path string) (string, error) {
	return filepath.Clean(path), nil
}
