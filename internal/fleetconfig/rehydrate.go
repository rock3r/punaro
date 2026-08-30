package fleetconfig

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// DefaultAddendumRoot is the well-known machine-local addendum tree.
func DefaultAddendumRoot(home string) string {
	return filepath.Join(home, "punaro", "addendums")
}

// LoadAddendums reads a machine-local addendum tree. Missing roots are empty.
func LoadAddendums(root string) (map[string][]byte, error) {
	if root == "" {
		return map[string][]byte{}, nil
	}
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return map[string][]byte{}, nil
	}
	if err != nil {
		return nil, errors.New("fleet-config addendum root is unavailable")
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("fleet-config addendum root must be a directory")
	}
	files := map[string][]byte{}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("fleet-config addendum walk failed")
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return errors.New("fleet-config addendum path is invalid")
		}
		if rel == "." {
			return nil
		}
		slash, pathErr := canonicalPath(filepath.ToSlash(rel))
		if pathErr != nil {
			return pathErr
		}
		info, err := entry.Info()
		if err != nil {
			return errors.New("fleet-config addendum walk failed")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("fleet-config addendum must not contain links")
		}
		if entry.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return errors.New("fleet-config addendum contains a special file")
		}
		if extraHardLink(info) {
			return errors.New("fleet-config addendum contains a special file")
		}
		if err := classifyAddendumPath(slash); err != nil {
			return err
		}
		if info.Size() > MaxFileBytes {
			return errors.New("fleet-config file is too large")
		}
		data, err := os.ReadFile(path) // #nosec G304,G122 -- Lstat-bounded walk of a caller-selected addendum tree.
		if err != nil {
			return errors.New("fleet-config addendum walk failed")
		}
		files[slash] = data
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

func classifyAddendumPath(path string) error {
	if path == "CLAUDE.md" {
		return nil
	}
	if _, err := classifyPath(path); err == nil {
		return nil
	}
	if strings.HasPrefix(path, "projects/") {
		project, rest, ok := splitFirst(strings.TrimPrefix(path, "projects/"))
		if ok && rest == "CLAUDE.md" && entryNamePattern.MatchString(project) {
			return nil
		}
	}
	return errors.New("fleet-config addendum layout is invalid")
}

// ResolveAddendum returns the addendum for a published path. A project
// addendum overrides a matching global addendum.
func ResolveAddendum(files map[string][]byte, path string) []byte {
	if files == nil {
		return nil
	}
	if body, ok := files[path]; ok {
		return body
	}
	if !strings.HasPrefix(path, "projects/") {
		return nil
	}
	_, rest, ok := splitFirst(strings.TrimPrefix(path, "projects/"))
	if !ok {
		return nil
	}
	if rest == "AGENTS.md" || rest == "CLAUDE.md" {
		return files[rest]
	}
	if skillRest, ok := strings.CutPrefix(rest, "skills/"); ok {
		skill, file, skillOK := splitFirst(skillRest)
		if !skillOK {
			return nil
		}
		if body, ok := files["common/"+skill+"/"+file]; ok {
			return body
		}
		return files["skills/"+skill+"/"+file]
	}
	return nil
}

// Rehydrate composes a managed dest from a published file, the winning
// addendum, and the live user region.
func Rehydrate(published, addendum, existing []byte) []byte {
	user := existing
	if _, extracted, ok := SplitUser(existing); ok {
		user = extracted
	} else if IsManagedContent(existing) || bytes.Contains(existing, []byte(AddendumStart)) {
		user = nil
	}
	return composeManaged(published, addendum, user)
}

// ComposeClaudeFile writes AGENTS.md plus Claude addendum(s) as a regular file.
func ComposeClaudeFile(agentsPublished, agentsAddendum, claudeAddendum, existing []byte) []byte {
	var addendum bytes.Buffer
	if len(agentsAddendum) > 0 {
		addendum.Write(bytes.TrimRight(agentsAddendum, "\n"))
		addendum.WriteByte('\n')
	}
	if len(claudeAddendum) > 0 {
		addendum.Write(bytes.TrimRight(claudeAddendum, "\n"))
		addendum.WriteByte('\n')
	}
	return Rehydrate(agentsPublished, addendum.Bytes(), existing)
}

func composeManaged(published, addendum, user []byte) []byte {
	var buf bytes.Buffer
	if len(published) > 0 {
		buf.Write(bytes.TrimRight(published, "\n"))
		buf.WriteByte('\n')
	}
	buf.WriteString(ManagedMark)
	buf.WriteByte('\n')
	buf.WriteString(AddendumStart)
	buf.WriteByte('\n')
	if len(addendum) > 0 {
		buf.Write(bytes.TrimRight(addendum, "\n"))
		buf.WriteByte('\n')
	}
	buf.WriteString(AddendumEnd)
	buf.WriteByte('\n')
	buf.WriteString(UserStart)
	if len(user) > 0 && user[0] != '\n' {
		buf.WriteByte('\n')
	}
	buf.Write(user)
	if len(user) == 0 || user[len(user)-1] != '\n' {
		buf.WriteByte('\n')
	}
	buf.WriteString(UserEnd)
	buf.WriteByte('\n')
	return buf.Bytes()
}

// IsManagedContent reports whether live bytes carry the Punaro ownership mark.
func IsManagedContent(data []byte) bool {
	return bytes.Contains(data, []byte(ManagedMark))
}

// IsManagedDir reports whether a skill destination directory is Punaro-owned.
func IsManagedDir(path string) bool {
	info, err := os.Lstat(filepath.Join(path, ManagedDirMarker))
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}

// SplitUser extracts the live user region when markers are present.
func SplitUser(content []byte) (prefix, user []byte, ok bool) {
	text := string(content)
	start := strings.Index(text, UserStart)
	end := strings.LastIndex(text, UserEnd)
	if start < 0 || end < 0 || end < start {
		return nil, nil, false
	}
	prefix = []byte(strings.TrimRight(text[:start], "\n"))
	user = []byte(text[start+len(UserStart) : end])
	return prefix, user, true
}
