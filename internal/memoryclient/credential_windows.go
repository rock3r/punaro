//go:build windows

package memoryclient

import (
	"errors"
	"os"
)

// Strong DACL/reparse verification is delivered with the persisted Windows profile in M17C2.
// Until then the stateless CLI fails closed rather than trusting POSIX mode bits on Windows.
func privateCredentialPath(string) bool              { return false }
func privateCredentialFile(string, os.FileInfo) bool { return false }

func openCredential(string) (*os.File, error) {
	return nil, errors.New("protected credential loading is unavailable on Windows")
}
