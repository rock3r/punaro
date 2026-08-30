//go:build !unix && !windows

package fleetconfig

import (
	"io/fs"
	"os"
)

func extraHardLink(fs.FileInfo) bool { return false }

func extraHardLinkFile(*os.File) bool { return false }
