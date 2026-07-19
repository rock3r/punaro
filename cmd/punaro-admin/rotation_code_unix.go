//go:build !windows

package main

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func readProtectedRotationCodeFile(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0) // #nosec G304 -- explicit host-local operator path opened without symlink traversal.
	if err != nil {
		return nil, errors.New("rotation code file is not protected")
	}
	file := os.NewFile(uintptr(fd), path) // #nosec G115 -- unix.Open returned a valid nonnegative file descriptor.
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("rotation code file is not protected")
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, errors.New("rotation code file is not protected")
	}
	return io.ReadAll(io.LimitReader(file, 44))
}
