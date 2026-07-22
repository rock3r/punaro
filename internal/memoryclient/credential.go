package memoryclient

import (
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

// LoadCredential reads one absolute protected credential without following a symlink or replacement.
func LoadCredential(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !privateCredentialPath(path) {
		return "", errors.New("device credential file is unsafe")
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || !privateCredentialFile(path, before) {
		return "", errors.New("device credential file is unsafe")
	}
	file, err := openCredential(path)
	if err != nil {
		return "", errors.New("device credential file is unavailable")
	}
	defer func() { _ = file.Close() }()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) || !privateCredentialFile(path, after) {
		return "", errors.New("device credential file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 513))
	credential := strings.TrimSuffix(string(raw), "\n")
	if err != nil || len(raw) == 0 || len(raw) > 512 || !validCredential(credential) {
		return "", errors.New("device credential file is invalid")
	}
	return credential, nil
}

func validCredential(value string) bool {
	lookupID, secretText, found := strings.Cut(value, ".")
	parsed, err := uuid.Parse(lookupID)
	if !found || err != nil || parsed == uuid.Nil || parsed.String() != lookupID || strings.Contains(secretText, "=") {
		return false
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(secretText)
	return err == nil && len(secret) == 32 && base64.RawURLEncoding.EncodeToString(secret) == secretText
}
