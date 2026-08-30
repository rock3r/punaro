package fleetconfig

import (
	"errors"
	"os"
	"path/filepath"
)

// AliasResult is the content-free Claude alias outcome.
type AliasResult struct {
	State string
}

// CreateAlias points linkPath at targetPath without copying contents.
func CreateAlias(targetPath, linkPath string, enabled bool) (AliasResult, error) {
	if !enabled {
		info, err := os.Lstat(linkPath)
		if errors.Is(err, os.ErrNotExist) {
			return AliasResult{State: "disabled"}, nil
		}
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			got, readErr := os.Readlink(linkPath)
			if readErr == nil && filepath.Clean(got) == filepath.Clean(targetPath) {
				if removeErr := os.Remove(linkPath); removeErr != nil {
					return AliasResult{State: "unsupported"}, removeErr
				}
			}
		}
		return AliasResult{State: "disabled"}, nil
	}
	if !filepath.IsAbs(targetPath) || !filepath.IsAbs(linkPath) {
		return AliasResult{State: "unsupported"}, errors.New("alias paths must be absolute")
	}
	info, err := os.Lstat(linkPath)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			got, readErr := os.Readlink(linkPath)
			if readErr == nil && filepath.Clean(got) == filepath.Clean(targetPath) {
				return AliasResult{State: "linked"}, nil
			}
			return AliasResult{State: "collision"}, nil
		}
		if info.Mode().IsRegular() || info.IsDir() {
			return AliasResult{State: "collision"}, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return AliasResult{State: "unsupported"}, err
	}
	if err := createAliasLink(targetPath, linkPath); err != nil {
		return AliasResult{State: "unsupported"}, err
	}
	return AliasResult{State: "linked"}, nil
}
