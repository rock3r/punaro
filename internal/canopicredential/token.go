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

// ReadPrivateFile returns bounded bytes from an absolute, clean, current-user
// owned private regular file whose identity remains stable across open.
func ReadPrivateFile(path string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, errors.New("private file byte limit must be positive")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("private file path must be absolute and clean")
	}
	before, err := os.Lstat(path)
	if err != nil || !privateTokenFile(path, before) {
		return nil, errors.New("file must be a private current-user-owned regular file")
	}
	file, err := openTokenFile(path)
	if err != nil {
		return nil, errors.New("file must be a private current-user-owned regular file")
	}
	defer func() { _ = file.Close() }()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !privateTokenFile(path, after) {
		return nil, errors.New("private file changed while opening")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil || int64(len(payload)) > maxBytes {
		return nil, errors.New("invalid private file")
	}
	return payload, nil
}

// ReadToken returns one bounded bearer token from a protected file.
func ReadToken(path string) (string, error) {
	payload, err := ReadPrivateFile(path, 4096)
	token := strings.TrimSpace(string(payload))
	if err != nil || len(token) < 16 {
		return "", errors.New("invalid token file")
	}
	return token, nil
}
