//go:build !windows

package canopi

import "path/filepath"

func canonicalStateLockIdentity(path string) string {
	return filepath.Clean(path)
}
