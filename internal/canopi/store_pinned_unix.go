//go:build !windows

package canopi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// persistStoreInPinnedDirectory writes relative to the directory descriptor
// retained alongside the store lock. Renaming its pathname cannot redirect a
// running collector into a replacement directory.
func persistStoreInPinnedDirectory(directory *os.File, targetName string, state persistedStore, maxBytes int64) error {
	if err := ensurePersistedStateWithinBudget(state, maxBytes); err != nil {
		return err
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode Canopi state: %w", err)
	}
	if int64(len(payload)) > maxBytes {
		return ErrStateByteLimit
	}
	fd, err := stateFileDescriptor(directory)
	if err != nil {
		return err
	}
	for range 8 {
		var suffix [12]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return fmt.Errorf("random Canopi state temporary name: %w", err)
		}
		temporaryName := ".canopi-state-" + hex.EncodeToString(suffix[:]) + ".tmp"
		temporaryFD, err := unix.Openat(fd, temporaryName, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC, 0o600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return fmt.Errorf("create Canopi state file: %w", err)
		}
		temporary := os.NewFile(uintptr(temporaryFD), temporaryName) // #nosec G115 -- successful descriptors are nonnegative.
		defer func() { _ = unix.Unlinkat(fd, temporaryName, 0) }()
		if err := protectStateFile(temporaryName, temporary); err != nil {
			_ = temporary.Close()
			return fmt.Errorf("protect Canopi state file: %w", err)
		}
		if _, err := temporary.Write(payload); err != nil {
			_ = temporary.Close()
			return fmt.Errorf("write Canopi state: %w", err)
		}
		if err := temporary.Sync(); err != nil {
			_ = temporary.Close()
			return fmt.Errorf("sync Canopi state: %w", err)
		}
		if err := temporary.Close(); err != nil {
			return fmt.Errorf("close Canopi state: %w", err)
		}
		if err := unix.Renameat(fd, temporaryName, fd, targetName); err != nil {
			return fmt.Errorf("replace Canopi state: %w", err)
		}
		if err := directory.Sync(); err != nil {
			return fmt.Errorf("sync Canopi state directory: %w", err)
		}
		return nil
	}
	return errors.New("cannot allocate Canopi state temporary")
}
