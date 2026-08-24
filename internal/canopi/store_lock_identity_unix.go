//go:build !windows

package canopi

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func canonicalStatePath(path string) (string, error) {
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, filepath.Base(path)), nil
}

func canonicalStateLockIdentity(path string) (string, error) {
	directory, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	stat, ok := directory.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("inspect Canopi state directory identity")
	}
	return fmt.Sprintf("%d:%d:%s", stat.Dev, stat.Ino, filepath.Base(path)), nil
}
