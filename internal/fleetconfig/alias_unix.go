//go:build unix

package fleetconfig

import "os"

func createAliasLink(targetPath, linkPath string) error {
	return os.Symlink(targetPath, linkPath)
}
