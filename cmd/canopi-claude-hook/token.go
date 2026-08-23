package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func readProtectedToken(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("token file path must be absolute and clean")
	}
	before, err := os.Lstat(path)
	if err != nil || !privateHookTokenFile(path, before) {
		return nil, errors.New("token file must be a private current-user-owned regular file")
	}
	file, err := openHookTokenFile(path)
	if err != nil {
		return nil, errors.New("token file must be a private current-user-owned regular file")
	}
	defer func() { _ = file.Close() }()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !privateHookTokenFile(path, after) {
		return nil, errors.New("token file changed while opening")
	}
	payload, err := io.ReadAll(io.LimitReader(file, 4097))
	token := strings.TrimSpace(string(payload))
	if err != nil || len(payload) > 4096 || len(token) < 16 {
		return nil, errors.New("invalid token file")
	}
	return []byte(token), nil
}
