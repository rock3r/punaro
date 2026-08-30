package fleetconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ApplyLiveRequest is the real start state for dest copy and rehydrate.
type ApplyLiveRequest struct {
	Tree         Tree
	Root         string
	Home         string
	AddendumRoot string
	Matches      []ProjectMatch
	Logs         io.Writer
}

// ApplyLiveResult is the content-free outcome of one dest apply.
type ApplyLiveResult struct {
	Collisions map[string]bool
	Drift      bool
	Written    int
}

// ApplyLive copies rehydrated regular files to live destinations. Destinations
// are never symlinks, junctions, or CLAUDE.md aliases. Common skills are copied
// into present member projects and are never written to ~/.agents/skills.
func ApplyLive(req ApplyLiveRequest) (ApplyLiveResult, error) {
	result := ApplyLiveResult{Collisions: map[string]bool{}}
	if err := Validate(req.Tree); err != nil {
		return result, err
	}
	addendumRoot := req.AddendumRoot
	if addendumRoot == "" && req.Home != "" {
		addendumRoot = DefaultAddendumRoot(req.Home)
	}
	addendums, err := LoadAddendums(addendumRoot)
	if err != nil {
		return result, err
	}
	present := map[string]string{}
	for _, match := range req.Matches {
		if match.Name != "" && match.Path != "" {
			present[match.Name] = match.Path
		}
	}
	published := expandDestFiles(req.Tree, present)
	staged := map[string][]byte{}
	for _, rel := range destApplyOrder(published) {
		body := published[rel]
		live := liveDestPath(req.Home, present, rel)
		if live == "" {
			continue
		}
		if collision, err := destCollision(rel, live); err != nil {
			return result, err
		} else if collision {
			result.Collisions[rel] = true
			result.Drift = true
			continue
		}
		next := composeDest(rel, body, published, addendums, live)
		if err := writeRegularDest(live, next); err != nil {
			return result, err
		}
		if skillDir, ok := skillDirForRel(rel, live); ok {
			if err := markManagedSkillDir(skillDir); err != nil {
				return result, err
			}
		}
		staged[rel] = next
		result.Written++
	}
	if req.Root != "" && len(staged) > 0 {
		if err := os.MkdirAll(req.Root, 0o700); err != nil {
			return result, errors.New("fleet-config apply failed")
		}
		digest := destSnapshotDigest(staged)
		if !sameDestSnapshot(req.Root, digest) {
			if err := pruneDroppedManagedDests(req.Root, req.Home, present, staged); err != nil {
				return result, err
			}
			if err := PublishTree(req.Root, staged, digest); err != nil {
				return result, err
			}
		}
	}
	if req.Logs != nil {
		_, _ = io.WriteString(req.Logs, FormatApplyLog(result, req.Tree.SkillCount())+"\n")
	}
	return result, nil
}

// RollbackLive restores last-known-good published dest bytes onto live dests.
func RollbackLive(req ApplyLiveRequest) error {
	if req.Root == "" {
		return errors.New("fleet-config last-known-good is unavailable")
	}
	if err := RestoreLastGood(req.Root); err != nil {
		return err
	}
	present := map[string]string{}
	for _, match := range req.Matches {
		if match.Name != "" && match.Path != "" {
			present[match.Name] = match.Path
		}
	}
	current := filepath.Join(req.Root, "current")
	return filepath.WalkDir(current, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		rel, relErr := filepath.Rel(current, path)
		if relErr != nil {
			return errors.New("fleet-config last-known-good restore failed")
		}
		slash := filepath.ToSlash(rel)
		live := liveDestPath(req.Home, present, slash)
		if live == "" {
			return nil
		}
		body, readErr := os.ReadFile(path) // #nosec G304,G122 -- adapter-owned last-known-good dest snapshot.
		if readErr != nil {
			return errors.New("fleet-config last-known-good restore failed")
		}
		if err := writeRegularDest(live, body); err != nil {
			return err
		}
		if skillDir, ok := skillDirForRel(slash, live); ok {
			return markManagedSkillDir(skillDir)
		}
		return nil
	})
}

// FormatApplyLog is the content-free apply log line. It must not include file bodies.
func FormatApplyLog(result ApplyLiveResult, skillCount int) string {
	return fmt.Sprintf("fleet-config apply written=%d collisions=%d skills=%d drift=%t", result.Written, len(result.Collisions), skillCount, result.Drift)
}

func expandDestFiles(tree Tree, present map[string]string) map[string][]byte {
	common := map[string]map[string][]byte{}
	optIns := map[string]map[string]struct{}{}
	files := map[string][]byte{}
	for _, file := range tree.Files {
		switch {
		case strings.HasPrefix(file.Path, "common/"):
			skill, rest, ok := splitFirst(strings.TrimPrefix(file.Path, "common/"))
			if !ok {
				continue
			}
			if common[skill] == nil {
				common[skill] = map[string][]byte{}
			}
			common[skill][rest] = file.Data
		case strings.HasPrefix(file.Path, "projects/"):
			project, rest, ok := splitFirst(strings.TrimPrefix(file.Path, "projects/"))
			if !ok {
				continue
			}
			if skillRest, ok := strings.CutPrefix(rest, "skills/"); ok {
				skill, name, skillOK := splitFirst(skillRest)
				if skillOK && name == CommonMarkerName {
					if optIns[project] == nil {
						optIns[project] = map[string]struct{}{}
					}
					optIns[project][skill] = struct{}{}
					continue
				}
			}
			if _, ok := present[project]; ok {
				files[file.Path] = file.Data
			}
		case file.Path == "AGENTS.md" || strings.HasPrefix(file.Path, "skills/"):
			files[file.Path] = file.Data
		}
	}
	for project := range present {
		for skill := range optIns[project] {
			for rest, body := range common[skill] {
				files["projects/"+project+"/skills/"+skill+"/"+rest] = body
			}
		}
	}
	if _, ok := files["AGENTS.md"]; ok {
		files["CLAUDE.md"] = files["AGENTS.md"]
	}
	for project := range present {
		if body, ok := files["projects/"+project+"/AGENTS.md"]; ok {
			files["projects/"+project+"/CLAUDE.md"] = body
		}
	}
	return files
}

func composeDest(rel string, published []byte, destFiles map[string][]byte, addendums map[string][]byte, livePath string) []byte {
	existing, _ := readRegularFile(livePath)
	if !rehydrateRel(rel) {
		return append([]byte(nil), published...)
	}
	if strings.HasSuffix(rel, "/CLAUDE.md") || rel == "CLAUDE.md" {
		agentsRel := strings.TrimSuffix(rel, "CLAUDE.md") + "AGENTS.md"
		agentsPublished := destFiles[agentsRel]
		if len(agentsPublished) == 0 {
			agentsPublished = published
		}
		return ComposeClaudeFile(agentsPublished, ResolveAddendum(addendums, agentsRel), ResolveAddendum(addendums, rel), existing)
	}
	return Rehydrate(published, ResolveAddendum(addendums, rel), existing)
}

func rehydrateRel(rel string) bool {
	base := rel
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		base = rel[i+1:]
	}
	return base == "AGENTS.md" || base == "CLAUDE.md" || base == "SKILL.md" || strings.HasSuffix(base, ".md")
}

func liveDestPath(home string, present map[string]string, rel string) string {
	switch {
	case rel == "AGENTS.md" || rel == "CLAUDE.md":
		if home == "" {
			return ""
		}
		return filepath.Join(home, rel)
	case strings.HasPrefix(rel, "skills/"):
		if home == "" {
			return ""
		}
		return filepath.Join(append([]string{home, ".agents"}, strings.Split(rel, "/")...)...)
	case strings.HasPrefix(rel, "projects/"):
		name, rest, ok := strings.Cut(strings.TrimPrefix(rel, "projects/"), "/")
		if !ok {
			return ""
		}
		root, found := present[name]
		if !found || root == "" {
			return ""
		}
		if rest == "AGENTS.md" || rest == "CLAUDE.md" {
			return filepath.Join(root, rest)
		}
		if skillRest, ok := strings.CutPrefix(rest, "skills/"); ok {
			return filepath.Join(append([]string{root, ".agents", "skills"}, strings.Split(skillRest, "/")...)...)
		}
	}
	return ""
}

func destCollision(rel, live string) (bool, error) {
	if skillDir, ok := skillDirForRel(rel, live); ok && unmanagedSkillDir(skillDir) {
		return true, nil
	}
	info, err := os.Lstat(live)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, errors.New("fleet-config live tree is unsafe")
	}
	if info.Mode()&os.ModeSymlink != 0 || destIsJunctionOrReparse(info) {
		return false, errors.New("fleet-config live tree is unsafe")
	}
	if info.IsDir() {
		return true, nil
	}
	if !info.Mode().IsRegular() {
		return true, nil
	}
	body, err := os.ReadFile(live) // #nosec G304 -- live destination fenced by Lstat as a regular file.
	if err != nil {
		return false, errors.New("fleet-config live tree is unsafe")
	}
	if rehydrateRel(rel) && !IsManagedContent(body) {
		return true, nil
	}
	return false, nil
}

func skillDirForRel(rel, live string) (string, bool) {
	rest := ""
	switch {
	case strings.HasPrefix(rel, "skills/"):
		rest = strings.TrimPrefix(rel, "skills/")
	default:
		_, after, ok := strings.Cut(rel, "/skills/")
		if !ok {
			return "", false
		}
		rest = after
	}
	_, file, ok := splitFirst(rest)
	if !ok || file == "" {
		return "", false
	}
	suffix := filepath.FromSlash(file)
	if !strings.HasSuffix(live, suffix) {
		return "", false
	}
	root := strings.TrimSuffix(live, suffix)
	return filepath.Clean(root), true
}

func unmanagedSkillDir(dir string) bool {
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return true
	}
	return !IsManagedDir(dir)
}

func markManagedSkillDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return errors.New("fleet-config apply failed")
	}
	marker := filepath.Join(dir, ManagedDirMarker)
	if IsManagedDir(dir) {
		return nil
	}
	return writeRegularDest(marker, nil)
}

func writeRegularDest(path string, body []byte) error {
	info, statErr := os.Lstat(path)
	if statErr == nil && (info.Mode()&os.ModeSymlink != 0 || destIsJunctionOrReparse(info)) {
		return errors.New("fleet-config live tree is unsafe")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return errors.New("fleet-config apply failed")
	}
	tmp := path + ".punaro-tmp"
	_ = os.Remove(tmp)
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- tmp is a sibling of a validated destination.
	if err != nil {
		return errors.New("fleet-config apply failed")
	}
	if _, err := file.Write(body); err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return errors.New("fleet-config apply failed")
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmp)
		return errors.New("fleet-config apply failed")
	}
	if statErr == nil && info.Mode().IsRegular() {
		_ = os.Remove(path)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return errors.New("fleet-config apply failed")
	}
	out, err := os.Lstat(path)
	if err != nil || !out.Mode().IsRegular() || destIsJunctionOrReparse(out) {
		return errors.New("fleet-config live tree is unsafe")
	}
	return nil
}

func readRegularFile(path string) ([]byte, bool) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, false
	}
	body, err := os.ReadFile(path) // #nosec G304 -- live destination fenced by Lstat as a regular file.
	if err != nil {
		return nil, false
	}
	return body, true
}

func sameDestSnapshot(root, digest string) bool {
	body, err := os.ReadFile(filepath.Join(root, "applied.json")) // #nosec G304 -- apply root is created by this process.
	if err != nil {
		return false
	}
	var state ApplyState
	if json.Unmarshal(body, &state) != nil || digest == "" {
		return false
	}
	return state.Digest == digest
}

func pruneDroppedManagedDests(root, home string, present map[string]string, staged map[string][]byte) error {
	current := filepath.Join(root, "current")
	info, err := os.Lstat(current)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	var removeDirs, removeFiles []string
	if err := filepath.WalkDir(current, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(current, path)
		if relErr != nil {
			return relErr
		}
		slash := filepath.ToSlash(rel)
		if _, kept := staged[slash]; kept {
			return nil
		}
		live := liveDestPath(home, present, slash)
		if live == "" {
			return nil
		}
		if skillDir, ok := skillDirForRel(slash, live); ok && IsManagedDir(skillDir) {
			removeDirs = append(removeDirs, skillDir)
			return nil
		}
		body, ok := readRegularFile(live)
		if !ok || !IsManagedContent(body) {
			return nil
		}
		removeFiles = append(removeFiles, live)
		return nil
	}); err != nil {
		return err
	}
	for _, dir := range removeDirs {
		if err := os.RemoveAll(dir); err != nil {
			return err
		}
	}
	for _, file := range removeFiles {
		if err := os.Remove(file); err != nil {
			return err
		}
	}
	return nil
}

func destSnapshotDigest(files map[string][]byte) string {
	var buf bytes.Buffer
	for _, path := range sortedKeys(files) {
		buf.WriteString(path)
		buf.WriteByte(0)
		buf.Write(files[path])
		buf.WriteByte(0)
	}
	if buf.Len() == 0 {
		return DigestBytes([]byte("fleet-config-dest"))
	}
	return DigestBytes(buf.Bytes())
}

func sortedKeys(files map[string][]byte) []string {
	keys := make([]string, 0, len(files))
	for path := range files {
		keys = append(keys, path)
	}
	sort.Strings(keys)
	return keys
}

// destApplyOrder puts nested skill files before SKILL.md so apply cannot
// rely on map order to mark the skills/<name> root.
func destApplyOrder(files map[string][]byte) []string {
	keys := sortedKeys(files)
	sort.SliceStable(keys, func(i, j int) bool {
		di, dj := strings.Count(keys[i], "/"), strings.Count(keys[j], "/")
		if di != dj {
			return di > dj
		}
		return keys[i] < keys[j]
	})
	return keys
}
