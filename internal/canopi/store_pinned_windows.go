//go:build windows

package canopi

import (
	"errors"
	"os"
	"path/filepath"
)

// Windows resolves the current name from the retained directory handle, so a
// rename cannot redirect this store to a replacement at its former pathname.
func persistStoreInPinnedDirectory(directory *os.File, targetName string, state persistedStore, maxBytes int64) error {
	info, err := directory.Stat()
	if err != nil || !info.IsDir() {
		return errors.New("pinned Canopi state directory is unavailable")
	}
	path, err := pinnedWindowsStateDirectoryPath(directory)
	if err != nil {
		return err
	}
	return persistStore(filepath.Join(path, targetName), state, maxBytes)
}
