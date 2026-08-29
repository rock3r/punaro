//go:build !windows

package main

import (
	"net/url"
	"os"
)

func protectMailboxDoctorSnapshot(path string) error {
	return os.Chmod(path, 0o700) // #nosec G302 -- snapshot directory must be owner-only and traversable.
}

func mailboxDoctorReadOnlyURI(path string) string {
	return (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}).String()
}
