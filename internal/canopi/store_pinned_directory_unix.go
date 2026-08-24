//go:build !windows

package canopi

import "os"

func openPinnedStateDirectory(path string) (*os.File, error) {
	return os.Open(path) // #nosec G304 -- the canonical state directory is validated before it is opened.
}
