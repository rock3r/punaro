//go:build !windows

package canopiadapter

import (
	"fmt"
	"os"
)

func syncDirectory(path string) error {
	directory, err := os.Open(path) // #nosec G304 -- path is the configured private spool directory.
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync Canopi spool: %w", err)
	}
	return nil
}
