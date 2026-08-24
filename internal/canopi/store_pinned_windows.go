//go:build windows

package canopi

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// Windows resolves the current name from the retained directory handle, so a
// rename cannot redirect this store to a replacement at its former pathname.
func persistStoreInPinnedDirectory(directory *os.File, targetName string, state persistedStore, maxBytes int64) error {
	info, err := directory.Stat()
	if err != nil || !info.IsDir() {
		return errors.New("pinned Canopi state directory is unavailable")
	}
	const maxFinalPathCharacters = 32_768
	buffer := make([]uint16, maxFinalPathCharacters)
	length, err := windows.GetFinalPathNameByHandle(windows.Handle(directory.Fd()), &buffer[0], maxFinalPathCharacters, 0)
	if err != nil || length >= maxFinalPathCharacters {
		return errors.New("resolve pinned Canopi state directory")
	}
	return persistStore(filepath.Join(windows.UTF16ToString(buffer[:length]), targetName), state, maxBytes)
}
