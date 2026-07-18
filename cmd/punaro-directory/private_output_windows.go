//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
)

// Windows client installation applies an exclusive current-user ACL to the
// output directory. This check preserves the type and reparse-point boundary;
// Windows ACL ownership is not represented by POSIX mode bits.
func requirePrivateParent(path string) (os.FileInfo, error) {
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("output parent must be an existing private directory owned by the invoking user")
	}
	return info, nil
}

func sameDirectory(a, b os.FileInfo) bool { return os.SameFile(a, b) }
