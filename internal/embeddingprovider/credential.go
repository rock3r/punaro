package embeddingprovider

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxAPIKeyFileBytes = 512

// ReadAPIKeyFile loads one non-empty, owner-protected provider API key without
// exposing its contents through errors.
func ReadAPIKeyFile(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !privateAPIKeyPath(path) {
		return "", errors.New("provider API key file is unsafe")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || !privateAPIKeyFile(info) {
		return "", errors.New("provider API key file is unsafe")
	}
	file, err := openAPIKeyFile(path)
	if err != nil {
		return "", errors.New("provider API key file is unavailable")
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !privateAPIKeyFile(opened) || !os.SameFile(info, opened) {
		return "", errors.New("provider API key file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxAPIKeyFileBytes+1))
	key := strings.TrimSuffix(string(raw), "\n")
	if err != nil || len(raw) == 0 || len(raw) > maxAPIKeyFileBytes || key == "" || invalidAPIKey(key) {
		return "", errors.New("provider API key file is invalid")
	}
	return key, nil
}

func invalidAPIKey(key string) bool {
	for _, value := range []byte(key) {
		if value <= 0x20 || value == 0x7f {
			return true
		}
	}
	return false
}
