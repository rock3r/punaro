// Package canopicredential reads Canopi bearer tokens from protected local
// files without following links or accepting shared credentials.
package canopicredential

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ReadToken returns one bounded token from an absolute, clean, current-user
// owned private regular file whose identity remains stable across open.
func ReadToken(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("token file path must be absolute and clean")
	}
	before, err := os.Lstat(path)
	if err != nil || !privateTokenFile(path, before) {
		return "", errors.New("token file must be a private current-user-owned regular file")
	}
	file, err := openTokenFile(path)
	if err != nil {
		return "", errors.New("token file must be a private current-user-owned regular file")
	}
	defer func() { _ = file.Close() }()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !privateTokenFile(path, after) {
		return "", errors.New("token file changed while opening")
	}
	payload, err := io.ReadAll(io.LimitReader(file, 4097))
	token := strings.TrimSpace(string(payload))
	if err != nil || len(payload) > 4096 || len(token) < 16 {
		return "", errors.New("invalid token file")
	}
	return token, nil
}
