//go:build !windows

package canopi

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func recoverPinnedStateReplacement(*os.File, string) error { return nil }

func openPrivateStateFileInPinnedDirectory(directory *os.File, targetName string) (*os.File, error) {
	fd, err := stateFileDescriptor(directory)
	if err != nil {
		return nil, err
	}
	descriptor, err := unix.Openat(fd, targetName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), targetName) // #nosec G115 -- successful descriptors are nonnegative.
	info, err := file.Stat()
	if err != nil || !privateStateFile(targetName, info) {
		_ = file.Close()
		if err != nil {
			return nil, err
		}
		return nil, errors.New("canopi state must be a private current-user-owned regular file")
	}
	return file, nil
}
