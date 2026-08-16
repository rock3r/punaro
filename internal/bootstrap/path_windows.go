//go:build windows

package bootstrap

import (
	"errors"
	"os"
)

func requireTrustedBootstrapDirectory(path string) error {
	info, err := os.Lstat(path) // #nosec G703 -- operator-selected absolute bootstrap directory.
	if err != nil || !info.IsDir() {
		return errors.New("bootstrap directory is invalid")
	}
	return nil
}
