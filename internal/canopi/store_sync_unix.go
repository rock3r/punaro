//go:build !windows

package canopi

import (
	"fmt"
	"os"
	"path/filepath"
)

func syncStateDirectory(path string) error {
	directory, err := os.Open(path) // #nosec G304 -- path is derived from the operator-selected state file.
	if err != nil {
		return fmt.Errorf("open Canopi state directory: %w", err)
	}
	defer func() { _ = directory.Close() }()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync Canopi state directory: %w", err)
	}
	return nil
}

func replaceStateFile(temporary, target string) error {
	if err := os.Rename(temporary, target); err != nil {
		return err
	}
	return syncStateDirectory(filepath.Dir(target))
}
