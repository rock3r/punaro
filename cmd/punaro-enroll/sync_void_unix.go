//go:build aix || linux || zos

package main

import "golang.org/x/sys/unix"

func syncAllFilesystems() error {
	unix.Sync()
	return nil
}
