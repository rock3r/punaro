//go:build !windows

package fleetconfig

import "os"

func destIsJunctionOrReparse(info os.FileInfo) bool {
	return info != nil && info.Mode()&os.ModeSymlink != 0
}
