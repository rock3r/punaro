//go:build windows

package embeddingprovider

import (
	"errors"
	"os"
)

// Windows ACL verification is not implemented yet, so provider credentials
// fail closed rather than accepting an unverified file.
func privateAPIKeyFile(os.FileInfo) bool { return false }

func privateAPIKeyPath(string) bool { return false }

func openAPIKeyFile(string) (*os.File, error) {
	return nil, errors.New("protected provider credential loading is unavailable on Windows")
}
