package fleetconfig

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// InspectRoot reads a source checkout using Lstat and never follows links.
func InspectRoot(root string) (Tree, error) {
	if root == "" {
		return Tree{}, errors.New("fleet-config source root is required")
	}
	info, err := os.Lstat(root)
	if err != nil {
		return Tree{}, errors.New("fleet-config source root is unavailable")
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return Tree{}, errors.New("fleet-config source root must be a directory")
	}
	var files []File
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("fleet-config source walk failed")
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return errors.New("fleet-config source path is invalid")
		}
		if rel == "." {
			return nil
		}
		slash, pathErr := canonicalPath(filepath.ToSlash(rel))
		if pathErr != nil {
			return pathErr
		}
		info, err := entry.Info()
		if err != nil {
			return errors.New("fleet-config source walk failed")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("fleet-config source must not contain links")
		}
		if entry.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return errors.New("fleet-config source contains a special file")
		}
		if extraHardLink(info) {
			return errors.New("fleet-config source contains a special file")
		}
		if info.Size() > MaxFileBytes {
			return errors.New("fleet-config file is too large")
		}
		data, err := os.ReadFile(path) // #nosec G304 -- bounded walk of a caller-selected source tree.
		if err != nil {
			return errors.New("fleet-config source walk failed")
		}
		if int64(len(data)) != info.Size() {
			return errors.New("fleet-config source file changed during read")
		}
		files = append(files, File{Path: slash, Data: data})
		if len(files) > MaxFiles {
			return errors.New("fleet-config source has too many files")
		}
		return nil
	})
	if err != nil {
		return Tree{}, err
	}
	return Tree{Files: files}, nil
}

func canonicalPath(path string) (string, error) {
	if path == "" || strings.Contains(path, "\\") || strings.ContainsRune(path, 0) || strings.HasPrefix(path, "/") {
		return "", errors.New("fleet-config path is invalid")
	}
	parts := strings.Split(path, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", errors.New("fleet-config path is invalid")
		}
	}
	return path, nil
}
