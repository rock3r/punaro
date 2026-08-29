//go:build windows

package fleetconfig

import "os"

func createAliasLink(targetPath, linkPath string) error {
	if err := os.Symlink(targetPath, linkPath); err != nil {
		return err
	}
	return nil
}
