//go:build !windows

package canopiadapter

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func tryLockSpoolFile(file *os.File) (bool, error) {
	fd, err := spoolFileDescriptor(file)
	if err != nil {
		return false, err
	}
	err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) {
		return false, nil
	}
	return err == nil, err
}

func unlockSpoolFile(file *os.File) error {
	fd, err := spoolFileDescriptor(file)
	if err != nil {
		return err
	}
	return unix.Flock(fd, unix.LOCK_UN)
}

func spoolFileDescriptor(file *os.File) (int, error) {
	fd := file.Fd()
	if fd > uintptr(^uint(0)>>1) {
		return 0, fmt.Errorf("file descriptor %d exceeds int range", fd)
	}
	return int(fd), nil
}
