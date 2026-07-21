//go:build !windows

package main

import "os"

func privateCredentialFile(info os.FileInfo) bool {
	return info.Mode().Perm()&0o077 == 0 && info.Mode().Perm()&0o400 != 0
}
