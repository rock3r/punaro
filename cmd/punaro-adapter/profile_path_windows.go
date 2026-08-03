//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func installedAdapterProfilePath() (string, error) {
	root := strings.TrimSpace(os.Getenv("LOCALAPPDATA"))
	if root == "" {
		return "", errors.New("LOCALAPPDATA is unavailable")
	}
	return filepath.Join(root, "Punaro", "config", "adapter.env"), nil
}
