package fleetconfig

import (
	"errors"
	"io"
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
	scoped, err := os.OpenRoot(root)
	if err != nil {
		return Tree{}, errors.New("fleet-config source root is unavailable")
	}
	defer func() { _ = scoped.Close() }()
	var files []File
	err = fs.WalkDir(scoped.FS(), ".", func(rel string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("fleet-config source walk failed")
		}
		if rel == "." {
			return nil
		}
		slash, pathErr := canonicalPath(filepath.ToSlash(rel))
		if pathErr != nil {
			return pathErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("fleet-config source must not contain links")
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
		file, err := scoped.OpenFile(rel, os.O_RDONLY, 0)
		if err != nil {
			return errors.New("fleet-config source walk failed")
		}
		opened, statErr := file.Stat()
		if statErr != nil || !opened.Mode().IsRegular() || opened.Mode()&os.ModeSymlink != 0 {
			_ = file.Close()
			return errors.New("fleet-config source contains a special file")
		}
		data, readErr := io.ReadAll(io.LimitReader(file, MaxFileBytes+1))
		_ = file.Close()
		if readErr != nil {
			return errors.New("fleet-config source walk failed")
		}
		if int64(len(data)) != info.Size() || int64(len(data)) != opened.Size() {
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
