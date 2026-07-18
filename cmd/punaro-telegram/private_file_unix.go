//go:build !windows

package main

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func readPrivateFile(path, label string, maximum int) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("%s file must be a private regular file", label)
	}
	file := os.NewFile(uintptr(fd), path) // #nosec G115 -- unix.Open returns a non-negative descriptor.
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
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
