//go:build !unix

package fleetconfig

import "io/fs"

func extraHardLink(fs.FileInfo) bool { return false }
