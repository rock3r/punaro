package postgres

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const maxDSNFileBytes = 16 << 10

// ReadDSNFile reads a bounded DSN from an absolute, private, non-symlink file.
func ReadDSNFile(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", errors.New("PostgreSQL DSN file must be an absolute path")
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
		return "", errors.New("PostgreSQL DSN path must identify a regular non-symlink file")
	}
	// #nosec G304 -- the operator supplies an absolute local secret path; Lstat,
	// non-symlink/regular-file checks, SameFile, strict modes, and a size bound
	// fence the read without constraining service-manager secret locations.
	file, err := os.Open(path)
	if err != nil {
		return "", errors.New("PostgreSQL DSN file cannot be opened")
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(pathInfo, info) {
		return "", errors.New("PostgreSQL DSN path must identify a stable regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("PostgreSQL DSN file permissions are too broad")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxDSNFileBytes+1))
	if err != nil || len(data) > maxDSNFileBytes {
		return "", errors.New("PostgreSQL DSN file is unreadable or too large")
	}
	dsn := strings.TrimSpace(string(data))
	if dsn == "" {
		return "", errors.New("PostgreSQL DSN file is empty")
	}
	return dsn, nil
}
