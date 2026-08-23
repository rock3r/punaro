//go:build windows

package canopi

import (
	"path/filepath"
	"strings"
)

func canonicalStateLockIdentity(path string) string {
	return strings.ToLower(filepath.Clean(path))
}
