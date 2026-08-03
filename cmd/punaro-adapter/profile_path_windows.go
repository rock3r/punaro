//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
)

func installedAdapterProfilePath() string {
	root := strings.TrimSpace(os.Getenv("LOCALAPPDATA"))
	if root == "" {
		return ""
	}
	return filepath.Join(root, "Punaro", "config", "adapter.env")
}
