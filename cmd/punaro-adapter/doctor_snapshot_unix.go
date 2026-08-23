//go:build !windows

package main

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func openMailboxDoctorSnapshotFile(path string, expected os.FileInfo) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0) // #nosec G304,G703 -- bounded local mailbox snapshot with no symlink traversal.
	if err != nil {
		return nil, errors.New("mailbox state entry is unsafe")
	}
	// #nosec G115 -- unix.Open returned a non-negative descriptor.
	file := os.NewFile(uintptr(fd), path)
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(expected, opened) {
		_ = file.Close()
		return nil, errors.New("mailbox state entry is unsafe")
	}
	return file, nil
}
