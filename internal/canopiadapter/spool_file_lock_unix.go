//go:build !windows

package canopiadapter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

func withSpoolRepairLock(ctx context.Context, path string, repair func() error) error {
	descriptor, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0) // #nosec G304 -- parent is the validated private spool directory.
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(descriptor), filepath.Dir(path)) // #nosec G115 -- successful descriptors are nonnegative.
	defer func() { _ = directory.Close() }()
	for {
		err := unix.Flock(descriptor, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			return err
		}
		timer := time.NewTimer(enqueueLockPoll)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
	defer func() { _ = unix.Flock(descriptor, unix.LOCK_UN) }()
	return repair()
}

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

func lockSpoolFile(file *os.File) error {
	fd, err := spoolFileDescriptor(file)
	if err != nil {
		return err
	}
	return unix.Flock(fd, unix.LOCK_EX)
}

func createSpoolLockFile(path string) (*os.File, error) {
	descriptor, err := unix.Open(path, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600) // #nosec G304 -- fixed lock name is inside the validated private spool.
	if err != nil {
		return nil, &os.PathError{Op: "create", Path: path, Err: err}
	}
	return os.NewFile(uintptr(descriptor), path), nil // #nosec G115 -- successful descriptors are nonnegative.
}

func openExistingSpoolLockFile(path string) (*os.File, error) {
	descriptor, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0) // #nosec G304 -- fixed lock name is validated before and after this no-follow open.
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(descriptor), path), nil // #nosec G115 -- successful descriptors are nonnegative.
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
