//go:build windows

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
	"unsafe"

	"golang.org/x/sys/windows"
)

type pinnedWindowsFileRenameInformation struct {
	ReplaceIfExists uint32
	RootDirectory   windows.Handle
	FileNameLength  uint32
	FileName        [1]uint16
}

// persistStoreInPinnedDirectory performs every state publication operation
// relative to the directory handle retained for the lifetime of the store.
// A later directory rename therefore cannot redirect a running collector to a
// replacement at the former pathname.
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
	if err := reclaimPinnedWindowsStateTemporaries(directory, targetName); err != nil {
		return fmt.Errorf("reclaim Canopi state temporaries: %w", err)
	}
	for range 8 {
		var suffix [12]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return fmt.Errorf("random Canopi state temporary name: %w", err)
		}
		temporaryName := stateTemporaryPrefix(targetName) + hex.EncodeToString(suffix[:]) + ".tmp"
		temporary, err := createPinnedWindowsStateFile(directory, temporaryName)
		if errors.Is(err, windows.ERROR_FILE_EXISTS) {
			continue
		}
		if err != nil {
			return fmt.Errorf("create Canopi state file: %w", err)
		}
		published := false
		defer func() {
			if !published {
				_ = discardPinnedWindowsStateFile(temporary)
			}
		}()
		if err := protectStateFileHandle(temporary); err != nil {
			return fmt.Errorf("protect Canopi state file: %w", err)
		}
		if _, err := temporary.Write(payload); err != nil {
			return fmt.Errorf("write Canopi state: %w", err)
		}
		if err := temporary.Sync(); err != nil {
			return fmt.Errorf("sync Canopi state: %w", err)
		}
		if err := renamePinnedWindowsStateFile(directory, temporary, targetName); err != nil {
			return fmt.Errorf("replace Canopi state: %w", err)
		}
		published = true
		if err := temporary.Close(); err != nil {
			return fmt.Errorf("close Canopi state: %w", err)
		}
		if err := windows.FlushFileBuffers(windows.Handle(directory.Fd())); err != nil {
			return fmt.Errorf("sync Canopi state directory: %w", err)
		}
		return nil
	}
	return errors.New("cannot allocate Canopi state temporary")
}

func reclaimPinnedWindowsStateTemporaries(directory *os.File, targetName string) error {
	if _, err := directory.Seek(0, io.SeekStart); err != nil {
		return err
	}
	for {
		names, readErr := directory.Readdirnames(128)
		for _, name := range names {
			if !pinnedWindowsStateTemporaryName(targetName, name) {
				continue
			}
			file, err := openPrivateStateFileInPinnedDirectory(directory, name)
			if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
				continue
			}
			if err != nil {
				continue
			}
			if err := discardPinnedWindowsStateFile(file); err != nil {
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

func pinnedWindowsStateTemporaryName(targetName, name string) bool {
	prefix := stateTemporaryPrefix(targetName)
	value := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".tmp")
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".tmp") || len(value) != 24 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func createPinnedWindowsStateFile(directory *os.File, name string) (*os.File, error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, err
	}
	oa := &windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), RootDirectory: windows.Handle(directory.Fd()), ObjectName: objectName, Attributes: windows.OBJ_DONT_REPARSE}
	var iosb windows.IO_STATUS_BLOCK
	var handle windows.Handle
	err = windows.NtCreateFile(&handle, windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.DELETE|windows.WRITE_DAC, oa, &iosb, nil, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_CREATE, windows.FILE_NON_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_WRITE_THROUGH, 0, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), name), nil // #nosec G115 -- successful Win32 handles are nonnegative.
}

func renamePinnedWindowsStateFile(directory *os.File, file *os.File, targetName string) error {
	name, err := windows.UTF16FromString(targetName)
	if err != nil {
		return err
	}
	nameBytes := (len(name) - 1) * 2
	var information pinnedWindowsFileRenameInformation
	buffer := make([]byte, int(unsafe.Offsetof(information.FileName))+nameBytes)
	typed := (*pinnedWindowsFileRenameInformation)(unsafe.Pointer(&buffer[0]))
	typed.ReplaceIfExists = windows.FILE_RENAME_REPLACE_IF_EXISTS | windows.FILE_RENAME_POSIX_SEMANTICS
	typed.RootDirectory = windows.Handle(directory.Fd())
	typed.FileNameLength = uint32(nameBytes)
	copy((*[windows.MAX_LONG_PATH]uint16)(unsafe.Pointer(&typed.FileName[0]))[:nameBytes/2:nameBytes/2], name)
	var iosb windows.IO_STATUS_BLOCK
	return windows.NtSetInformationFile(windows.Handle(file.Fd()), &iosb, &buffer[0], uint32(len(buffer)), windows.FileRenameInformation)
}

func discardPinnedWindowsStateFile(file *os.File) error {
	var iosb windows.IO_STATUS_BLOCK
	deleteFile := []byte{1}
	err := windows.NtSetInformationFile(windows.Handle(file.Fd()), &iosb, &deleteFile[0], uint32(len(deleteFile)), windows.FileDispositionInformation)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}
