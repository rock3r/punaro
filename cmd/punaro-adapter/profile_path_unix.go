//go:build !windows

package main

import (
	"os"
	"path/filepath"
)

func installedAdapterProfilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "punaro", "adapter.env"), nil
}
