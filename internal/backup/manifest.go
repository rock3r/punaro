// Package backup implements Punaro's versioned, content-free backup format.
package backup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	manifestName     = "manifest.json"
	maximumManifest  = 1 << 20
	maximumFileCount = 100_000
	maximumDumpSize  = 1 << 40
	maximumTotalSize = 4 << 40
)

var requiredFiles = []string{
	"database.dump",
	"config/installation.json",
	"config/punarod.env",
	"config/compose.operator.yaml",
	"credentials/owner.dsn",
	"credentials/app.dsn",
}

// State identifies the exact logical restore point captured by a backup.
type State struct {
	InstallationID string `json:"installation_id"`
	TimelineID     string `json:"timeline_id"`
	ChangeSequence int64  `json:"change_sequence"`
}

// File binds one regular backup file to its exact length and digest.
type File struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Manifest is the single authoritative index for a published backup.
type Manifest struct {
	Version              int       `json:"version"`
	BackupID             string    `json:"backup_id"`
	CreatedAt            time.Time `json:"created_at"`
	SnapshotID           string    `json:"snapshot_id"`
	SchemaVersion        int64     `json:"schema_version"`
	State                State     `json:"state"`
	Files                []File    `json:"files"`
	ExternalDependencies []string  `json:"external_dependencies"`
}

// Summary is safe, content-free metadata returned by backup list.
type Summary struct {
	Directory     string    `json:"directory"`
	BackupID      string    `json:"backup_id"`
	CreatedAt     time.Time `json:"created_at"`
	SchemaVersion int64     `json:"schema_version"`
	State         State     `json:"state"`
}

// Verify strictly validates the manifest and every declared file without
// following links. Undeclared regular files are rejected.
func Verify(directory string) (Manifest, error) {
	if err := trustedPrivateDirectory(directory); err != nil {
		return Manifest{}, errors.New("backup directory is unavailable or unsafe")
	}
	manifest, err := readManifest(filepath.Join(directory, manifestName))
	if err != nil {
		return Manifest{}, errors.New("backup manifest is unavailable or invalid")
	}
	if err := validateManifest(manifest); err != nil {
		return Manifest{}, err
	}
	declared := make(map[string]File, len(manifest.Files))
	for _, entry := range manifest.Files {
		if _, exists := declared[entry.Path]; exists {
			return Manifest{}, errors.New("backup manifest contains duplicate files")
		}
		declared[entry.Path] = entry
		if err := verifyFile(directory, entry); err != nil {
			return Manifest{}, fmt.Errorf("backup file %q failed verification", entry.Path)
		}
	}
	for _, path := range requiredFiles {
		if _, ok := declared[path]; !ok {
			return Manifest{}, errors.New("backup manifest is missing required files")
		}
	}
	seen := map[string]bool{manifestName: true}
	allowedDirectories := map[string]bool{".": true}
	for path := range declared {
		filesystemPath := filepath.FromSlash(path)
		seen[filesystemPath] = true
		for directory := filepath.Dir(filesystemPath); directory != "."; directory = filepath.Dir(directory) {
			allowedDirectories[directory] = true
		}
	}
	err = filepath.WalkDir(directory, func(path string, _ os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == directory {
			return nil
		}
		relative, relErr := filepath.Rel(directory, path)
		if relErr != nil || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("backup path escapes its directory")
		}
		info, infoErr := os.Lstat(path)
		if infoErr != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("backup contains an unsafe filesystem entry")
		}
		if info.IsDir() {
			if !allowedDirectories[relative] || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
				return errors.New("backup directory permissions are unsafe")
			}
			return nil
		}
		if !info.Mode().IsRegular() || !seen[relative] {
			return errors.New("backup contains an undeclared or unsafe file")
		}
		return nil
	})
	if err != nil {
		return Manifest{}, errors.New("backup filesystem contents are invalid")
	}
	return manifest, nil
}

// List returns only fully verified, non-symlink backup directories.
func List(root string) ([]Summary, error) {
	if err := trustedPrivateDirectory(root); err != nil {
		return nil, errors.New("backup root is unavailable or unsafe")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, errors.New("backup root cannot be listed")
	}
	result := make([]Summary, 0, len(entries))
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") || entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() {
			continue
		}
		directory := filepath.Join(root, entry.Name())
		manifest, verifyErr := Verify(directory)
		if verifyErr != nil {
			continue
		}
		result = append(result, Summary{Directory: directory, BackupID: manifest.BackupID, CreatedAt: manifest.CreatedAt, SchemaVersion: manifest.SchemaVersion, State: manifest.State})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].BackupID < result[j].BackupID
		}
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})
	return result, nil
}

func readManifest(path string) (Manifest, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maximumManifest || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) || trustedProtectedFile(path, maximumManifest) != nil {
		return Manifest{}, errors.New("manifest file is unsafe")
	}
	file, err := os.Open(path) // #nosec G304 -- child of an explicit private backup directory.
	if err != nil {
		return Manifest{}, err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return Manifest{}, errors.New("manifest changed during open")
	}
	defer func() { _ = file.Close() }()
	body, err := io.ReadAll(io.LimitReader(file, maximumManifest+1))
	if err != nil || len(body) > maximumManifest || rejectDuplicateJSONKeys(body) != nil {
		return Manifest{}, errors.New("manifest JSON is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Manifest{}, errors.New("manifest has trailing JSON")
	}
	return manifest, nil
}

func rejectDuplicateJSONKeys(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	var walkValue func() error
	walkValue = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				keyToken, keyErr := decoder.Token()
				key, keyOK := keyToken.(string)
				if keyErr != nil || !keyOK || seen[key] {
					return errors.New("duplicate or invalid JSON object key")
				}
				seen[key] = true
				if err := walkValue(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("invalid JSON object")
			}
		case '[':
			for decoder.More() {
				if err := walkValue(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("invalid JSON array")
			}
		default:
			return errors.New("invalid JSON delimiter")
		}
		return nil
	}
	if err := walkValue(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func validateManifest(manifest Manifest) error {
	if manifest.Version != 1 || uuid.Validate(manifest.BackupID) != nil || manifest.CreatedAt.IsZero() || manifest.CreatedAt.Location() != time.UTC || manifest.SchemaVersion <= 0 || uuid.Validate(manifest.State.InstallationID) != nil || uuid.Validate(manifest.State.TimelineID) != nil || manifest.State.ChangeSequence < 0 || len(manifest.Files) == 0 || len(manifest.Files) > maximumFileCount {
		return errors.New("backup manifest metadata is invalid")
	}
	if !validSnapshotID(manifest.SnapshotID) {
		return errors.New("backup snapshot identity is invalid")
	}
	requiredDependencies := []string{"host-tls", "oauth", "reverse-proxy", "telegram", "tunnel"}
	if len(manifest.ExternalDependencies) != len(requiredDependencies) {
		return errors.New("backup external dependency declaration is incomplete")
	}
	approvedDependencies := map[string]bool{"host-tls": true, "reverse-proxy": true, "tunnel": true, "telegram": true, "oauth": true}
	seenDependencies := make(map[string]bool, len(manifest.ExternalDependencies))
	for index, dependency := range manifest.ExternalDependencies {
		if dependency != requiredDependencies[index] || !approvedDependencies[dependency] || seenDependencies[dependency] {
			return errors.New("backup external dependency declaration is invalid")
		}
		if index > 0 && manifest.ExternalDependencies[index-1] >= dependency {
			return errors.New("backup external dependencies are not canonical")
		}
		seenDependencies[dependency] = true
	}
	var totalSize int64
	for index, entry := range manifest.Files {
		if !validRelativePath(entry.Path) || entry.Size < 0 || len(entry.SHA256) != 64 {
			return errors.New("backup file declaration is invalid")
		}
		if index > 0 && manifest.Files[index-1].Path >= entry.Path {
			return errors.New("backup files are not in canonical order")
		}
		maximum, allowed := maximumForPath(entry.Path)
		if !allowed || entry.Size > maximum || entry.Size > maximumTotalSize-totalSize {
			return errors.New("backup file declaration exceeds its allowed namespace or size")
		}
		totalSize += entry.Size
		if _, err := hex.DecodeString(entry.SHA256); err != nil || strings.ToLower(entry.SHA256) != entry.SHA256 {
			return errors.New("backup file digest is invalid")
		}
	}
	return nil
}

func maximumForPath(path string) (int64, bool) {
	switch path {
	case "database.dump":
		return maximumDumpSize, true
	case "config/installation.json", "config/punarod.env", "config/compose.operator.yaml":
		return maximumManifest, true
	case "credentials/owner.dsn", "credentials/app.dsn":
		return 64 << 10, true
	default:
		if strings.HasPrefix(path, "blobs/") && validRelativePath(strings.TrimPrefix(path, "blobs/")) {
			return maximumBlobSize, true
		}
		return 0, false
	}
}

func validRelativePath(path string) bool {
	if path == "" || strings.Contains(path, "\\") || filepath.IsAbs(path) || filepath.ToSlash(filepath.Clean(filepath.FromSlash(path))) != path || path == "." || path == ".." || strings.HasPrefix(path, "../") || strings.ContainsRune(path, '\x00') {
		return false
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func validSnapshotID(value string) bool {
	if value == "" || len(value) > 200 || strings.ContainsAny(value, " \t\r\n/\\") {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'A' || character > 'Z') && character != '-' {
			return false
		}
	}
	return true
}

func verifyFile(directory string, entry File) error {
	file, err := openVerifiedFile(directory, entry)
	if err != nil {
		return err
	}
	return file.Close()
}

func openVerifiedFile(directory string, entry File) (*os.File, error) {
	path := filepath.Join(directory, filepath.FromSlash(entry.Path))
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() != entry.Size || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) || trustedProtectedFile(path, entry.Size) != nil {
		return nil, errors.New("file metadata mismatch")
	}
	file, err := os.Open(path) // #nosec G304 -- validated relative child of explicit backup directory.
	if err != nil {
		return nil, err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, errors.New("file changed during open")
	}
	hash := sha256.New()
	written, copyErr := io.Copy(hash, io.LimitReader(file, entry.Size+1))
	if copyErr != nil || written != entry.Size || hex.EncodeToString(hash.Sum(nil)) != entry.SHA256 {
		_ = file.Close()
		return nil, errors.New("file content mismatch")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, errors.New("file cannot be rewound")
	}
	return file, nil
}

// ReadVerifiedFile returns bytes from the same inode whose digest was verified.
func ReadVerifiedFile(directory string, manifest Manifest, relative string, maximum int64) ([]byte, error) {
	if maximum < 0 {
		return nil, errors.New("verified file size limit is invalid")
	}
	var entry File
	found := false
	for _, candidate := range manifest.Files {
		if candidate.Path == relative {
			entry, found = candidate, true
			break
		}
	}
	if !found || entry.Size > maximum {
		return nil, errors.New("verified file is unavailable")
	}
	file, err := openVerifiedFile(directory, entry)
	if err != nil {
		return nil, errors.New("verified file changed after manifest verification")
	}
	defer func() { _ = file.Close() }()
	body, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(body)) != entry.Size {
		return nil, errors.New("verified file could not be read")
	}
	return body, nil
}

func privateDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("directory path is not canonical")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return errors.New("directory is unsafe")
	}
	return nil
}
