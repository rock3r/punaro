// Package plugindiagnostic computes public release identities for the exact
// portable Punaro plugin and its three supported skill trees.
package plugindiagnostic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rock3r/punaro/internal/incrementalfs"
)

const (
	maximumManifestBytes = 64 << 10
	maximumSkillBytes    = 1 << 20
	maximumSkillEntries  = 64
)

var manifestPaths = []string{"plugin.json", ".codex-plugin/plugin.json", ".claude-plugin/plugin.json"}

// Version returns the exact shared version from all three plugin manifests.
func Version(root string) (string, error) {
	if !trustedDirectory(root) {
		return "", errors.New("plugin root is unsafe")
	}
	version := ""
	for _, relative := range manifestPaths {
		body, err := readFile(filepath.Join(root, filepath.FromSlash(relative)), maximumManifestBytes)
		if err != nil {
			return "", errors.New("plugin manifest is unavailable")
		}
		fields, err := decodeUniqueObject(body)
		if err != nil {
			return "", errors.New("plugin manifest is invalid")
		}
		var name, current string
		if json.Unmarshal(fields["name"], &name) != nil || json.Unmarshal(fields["version"], &current) != nil || name != "punaro" || current == "" || strings.ContainsAny(current, "\r\n\x00") {
			return "", errors.New("plugin manifest is invalid")
		}
		if version != "" && current != version {
			return "", errors.New("plugin versions do not match")
		}
		version = current
	}
	return version, nil
}

// SkillSetDigest hashes the exact sorted path and bytes of the three skills.
func SkillSetDigest(root string) (string, error) {
	return SkillSetDigestContext(context.Background(), root)
}

// SkillSetDigestContext hashes the skill set while honoring a diagnostic
// deadline between directory entries and bounded file reads.
func SkillSetDigestContext(ctx context.Context, root string) (string, error) {
	if ctx == nil || ctx.Err() != nil {
		return "", errors.New("skill set inspection canceled")
	}
	if !trustedDirectory(root) {
		return "", errors.New("skill root is unsafe")
	}
	directory, err := os.Open(root) // #nosec G304,G703 -- validated explicit local skill root.
	if err != nil {
		return "", errors.New("skill set is invalid")
	}
	defer func() { _ = directory.Close() }()
	top, readErr := directory.ReadDir(4)
	if ctx.Err() != nil {
		return "", errors.New("skill set inspection canceled")
	}
	if readErr != nil && !errors.Is(readErr, io.EOF) || len(top) != 3 {
		return "", errors.New("skill set is invalid")
	}
	expected := map[string]bool{"punaro-attachment": false, "punaro-mailbox": false, "punaro-reply": false}
	for _, entry := range top {
		if _, ok := expected[entry.Name()]; !ok || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return "", errors.New("skill set is invalid")
		}
		expected[entry.Name()] = true
	}
	var files []string
	total := int64(0)
	err = incrementalfs.Walk(ctx, root, maximumSkillEntries, func(path, _ string, info os.FileInfo) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("unsafe skill entry")
		}
		if path == root || info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return errors.New("unsafe skill entry")
		}
		if info.Size() < 1 || info.Size() > maximumSkillBytes || total+info.Size() > maximumSkillBytes {
			return errors.New("unsafe skill entry")
		}
		total += info.Size()
		files = append(files, path)
		return nil
	})
	if err != nil || len(files) == 0 {
		return "", errors.New("skill set is invalid")
	}
	sort.Strings(files)
	hash := sha256.New()
	for _, path := range files {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || strings.HasPrefix(relative, "..") {
			return "", errors.New("skill set is invalid")
		}
		body, err := readFileContext(ctx, path, maximumSkillBytes)
		if err != nil {
			return "", errors.New("skill set is invalid")
		}
		_, _ = hash.Write([]byte(filepath.ToSlash(relative)))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write(body)
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func trustedDirectory(path string) bool {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	info, err := os.Lstat(path) // #nosec G703 -- explicit local plugin root.
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0
}

func readFile(path string, maximum int64) ([]byte, error) {
	return readFileContext(context.Background(), path, maximum)
}

func readFileContext(ctx context.Context, path string, maximum int64) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("plugin file unavailable")
	}
	info, err := os.Lstat(path) // #nosec G703 -- fixed child of validated plugin root.
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > maximum {
		return nil, errors.New("plugin file unavailable")
	}
	file, err := os.Open(path) // #nosec G304,G703 -- validated plugin file.
	if err != nil {
		return nil, errors.New("plugin file unavailable")
	}
	defer func() { _ = file.Close() }()
	body, err := io.ReadAll(io.LimitReader(pluginContextReader{ctx: ctx, reader: file}, maximum+1))
	if err != nil || len(body) == 0 || int64(len(body)) > maximum {
		return nil, errors.New("plugin file unavailable")
	}
	return body, nil
}

type pluginContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader pluginContextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}

func decodeUniqueObject(body []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("invalid object")
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok {
			return nil, errors.New("invalid object")
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, errors.New("invalid object")
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, errors.New("invalid object")
		}
		fields[key] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("invalid object")
	}
	return fields, nil
}
