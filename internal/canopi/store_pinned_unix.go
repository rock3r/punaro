//go:build !windows

package canopi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

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
	if err := reclaimPinnedStateTemporaries(directory, fd); err != nil {
		return fmt.Errorf("reclaim Canopi state temporaries: %w", err)
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

func reclaimPinnedStateTemporaries(directory *os.File, fd int) error {
	if _, err := directory.Seek(0, io.SeekStart); err != nil {
		return err
	}
	for {
		names, readErr := directory.Readdirnames(128)
		for _, name := range names {
			if !pinnedStateTemporaryName(name) {
				continue
			}
			var info unix.Stat_t
			if err := unix.Fstatat(fd, name, &info, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
				continue
			} else if err != nil {
				return err
			}
			if info.Mode&unix.S_IFMT != unix.S_IFREG {
				continue
			}
			if err := unix.Unlinkat(fd, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

func pinnedStateTemporaryName(name string) bool {
	const prefix = ".canopi-state-"
	const suffix = ".tmp"
	value := strings.TrimSuffix(strings.TrimPrefix(name, prefix), suffix)
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) || len(value) != 24 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
