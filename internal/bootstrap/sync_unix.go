//go:build !windows

package bootstrap

import "os"

func syncDir(path string) error {
	dir, err := os.Open(path) // #nosec G304 -- parent of a bootstrap-owned path.
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}
