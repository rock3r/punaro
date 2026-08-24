// Package incrementalfs provides bounded, cancellation-aware filesystem traversal.
package incrementalfs

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
)

const directoryBatchSize = 32

// Walk visits root and its descendants without eagerly loading or sorting an
// entire directory. maximumEntries includes root.
func Walk(ctx context.Context, root string, maximumEntries int, visit func(path, relative string, info os.FileInfo) error) error {
	if ctx == nil || ctx.Err() != nil || maximumEntries < 1 || visit == nil {
		return errors.New("incremental filesystem walk is unavailable")
	}
	rootInfo, err := os.Lstat(root) // #nosec G703 -- caller-selected local diagnostic root.
	if err != nil {
		return err
	}
	if err := visit(root, ".", rootInfo); err != nil {
		return err
	}
	entries := 1
	directories := []walkDirectory{{path: root, info: rootInfo}}
	for len(directories) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		current := directories[len(directories)-1]
		directories = directories[:len(directories)-1]
		if !current.info.IsDir() || current.info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		handle, err := os.Open(current.path) // #nosec G304,G703 -- incrementally opens a validated walked directory.
		if err != nil {
			return err
		}
		opened, statErr := handle.Stat()
		if statErr != nil || !opened.IsDir() || !os.SameFile(current.info, opened) {
			_ = handle.Close()
			return errors.New("walked directory changed during open")
		}
		for {
			batch, readErr := handle.ReadDir(directoryBatchSize)
			for _, entry := range batch {
				if err := ctx.Err(); err != nil {
					_ = handle.Close()
					return err
				}
				entries++
				if entries > maximumEntries {
					_ = handle.Close()
					return errors.New("filesystem walk has too many entries")
				}
				path := filepath.Join(current.path, entry.Name())
				relative, relErr := filepath.Rel(root, path)
				info, infoErr := entry.Info()
				if relErr != nil || relative == "." || filepath.IsAbs(relative) || relative == ".." || infoErr != nil {
					_ = handle.Close()
					return errors.New("filesystem walk entry is invalid")
				}
				if err := visit(path, relative, info); err != nil {
					_ = handle.Close()
					return err
				}
				if info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
					directories = append(directories, walkDirectory{path: path, info: info})
				}
			}
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				_ = handle.Close()
				return readErr
			}
		}
		if err := handle.Close(); err != nil {
			return err
		}
	}
	return ctx.Err()
}

type walkDirectory struct {
	path string
	info os.FileInfo
}
