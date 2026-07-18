//go:build windows

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func readPrivateFile(path, label string, maximum int) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%s file must be a private regular file", label)
	}
	// #nosec G703 -- path is a local operator configuration path, constrained to
	// an absolute, non-reparse regular file under the installer-owned ACL.
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s file must be a private regular file", label)
	}
	// #nosec G304,G703 -- validated absolute local configuration path; remote data
	// never selects this file.
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s file must be a private regular file", label)
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, fmt.Errorf("%s file must be a private regular file", label)
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil {
		return nil, fmt.Errorf("read %s file: %w", label, err)
	}
	if len(raw) == 0 || len(raw) > maximum {
		return nil, fmt.Errorf("invalid %s file", label)
	}
	return raw, nil
}
