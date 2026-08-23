//go:build windows

package main

import (
	"errors"
	"os"
)

func openMailboxDoctorSnapshotFile(path string, expected os.FileInfo) (*os.File, error) {
	file, err := os.Open(path) // #nosec G304,G703 -- bounded installer-selected mailbox snapshot.
	if err != nil {
		return nil, errors.New("mailbox state entry is unsafe")
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Mode()&os.ModeSymlink != 0 || !os.SameFile(expected, opened) {
		_ = file.Close()
		return nil, errors.New("mailbox state entry is unsafe")
	}
	return file, nil
}
