//go:build !windows

package main

import (
	"os"
	"path/filepath"
)

func installedAdapterProfilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "punaro", "adapter.env")
}
