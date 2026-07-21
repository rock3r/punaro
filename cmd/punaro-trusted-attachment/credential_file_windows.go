//go:build windows

package main

import "os"

// Windows file confidentiality is enforced by the provisioned user ACL. The
// common loader still rejects links, non-regular files, swaps, and oversized or
// malformed contents.
func privateCredentialFile(os.FileInfo) bool { return true }
