//go:build !windows

package bootstrap

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func requireTrustedBootstrapDirectory(path string) error {
	info, err := os.Lstat(path) // #nosec G703 -- operator-selected absolute bootstrap directory.
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("bootstrap directory is invalid")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return errors.New("bootstrap directory is invalid")
	}
	return requireTrustedAncestors(filepath.Dir(filepath.Clean(path)))
}

func requireTrustedAncestors(path string) error {
	current := filepath.Clean(path)
	for {
		info, err := os.Lstat(current) // #nosec G703 -- ancestor of the operator-selected bootstrap directory.
		if err != nil {
			return errors.New("bootstrap directory is invalid")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != 0 {
				return errors.New("bootstrap directory is invalid")
			}
			if err := requireTrustedAncestors(filepath.Dir(current)); err != nil {
				return err
			}
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil {
				return errors.New("bootstrap directory is invalid")
			}
			return requireResolvedAncestors(resolved)
		}
		if err := requireTrustedAncestorDir(info); err != nil {
			return err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func requireResolvedAncestors(path string) error {
	current := filepath.Clean(path)
	for {
		info, err := os.Lstat(current) // #nosec G703 -- resolved ancestor of the bootstrap directory.
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("bootstrap directory is invalid")
		}
		if err := requireTrustedAncestorDir(info); err != nil {
			return err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func requireTrustedAncestorDir(info os.FileInfo) error {
	if !info.IsDir() {
		return errors.New("bootstrap directory is invalid")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (int(stat.Uid) != 0 && int(stat.Uid) != os.Getuid()) {
		return errors.New("bootstrap directory is invalid")
	}
	if info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
		return errors.New("bootstrap directory is invalid")
	}
	return nil
}
