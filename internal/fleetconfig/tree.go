// Package fleetconfig validates and materializes data-only fleet agent configuration.
package fleetconfig

import "sort"

const (
	// SchemaV1 is the fleet-config source/release schema.
	SchemaV1 = 1
	// TrailerStart marks the machine-local AGENTS.md trailer. It is illegal in fleet source.
	TrailerStart = "<!-- punaro-local-trailer:start -->"
	// TrailerEnd closes the machine-local trailer.
	TrailerEnd = "<!-- punaro-local-trailer:end -->"
	// UserStart opens the preserved live user region. It is illegal in fleet source.
	UserStart = "<!-- user -->"
	// UserEnd closes the preserved live user region.
	UserEnd = "<!--/user-->"
	// AddendumStart opens the machine-local addendum block. It is illegal in fleet source.
	AddendumStart = "<!-- punaro-addendum -->"
	// AddendumEnd closes the machine-local addendum block.
	AddendumEnd = "<!--/punaro-addendum-->"
	// ManagedMark records that Punaro owns a live AGENTS.md, CLAUDE.md, or skill file.
	ManagedMark = "<!-- punaro-managed -->"
	// ManagedDirMarker is the regular file that marks a managed skill directory.
	ManagedDirMarker = ".punaro-managed"
	// CommonMarkerName is the project opt-in file for a shared common skill.
	CommonMarkerName = "COMMON"
	// MaxFileBytes is the per-file bound for v1 source files.
	MaxFileBytes = 256 << 10
	// MaxSkills bounds global plus project skills.
	MaxSkills = 64
	// MaxFiles bounds archived regular files.
	MaxFiles = 512
	// MaxTotalBytes bounds the sum of file contents.
	MaxTotalBytes = 4 << 20
)

// File is one regular source file with a slash-separated relative path.
type File struct {
	Path string
	Data []byte
}

// Tree is a validated or candidate source snapshot.
type Tree struct {
	Files []File
}

// ManifestFile is one path recorded in a materialized release.
type ManifestFile struct {
	Path   string
	Size   int64
	SHA256 string
}

// Release is a content-addressed, data-only fleet-config archive plus manifest.
type Release struct {
	Schema             int
	SourceCommit       string
	Digest             string
	Archive            []byte
	Files              []ManifestFile
	SkillCount         int
	TotalBytes         int64
	DataOnly           bool
	ActivationCommands int
	Destinations       []string
}

// SkillCount counts validated skill roots (SKILL.md at the skill directory).
func (tree Tree) SkillCount() int {
	count := 0
	for _, file := range tree.Files {
		kind, err := classifyPath(file.Path)
		if err == nil && kind.class == pathSkillMarkdown {
			count++
		}
	}
	return count
}

// Projects returns sorted unique project names.
func (tree Tree) Projects() []string {
	seen := map[string]struct{}{}
	for _, file := range tree.Files {
		if name, ok := projectName(file.Path); ok {
			seen[name] = struct{}{}
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// HasProject reports whether a project tree is present.
func (tree Tree) HasProject(name string) bool {
	_, ok := indexOf(tree.Projects(), name)
	return ok
}

func indexOf(values []string, want string) (int, bool) {
	for i, value := range values {
		if value == want {
			return i, true
		}
	}
	return 0, false
}

func projectName(path string) (string, bool) {
	const prefix = "projects/"
	if len(path) < len(prefix)+1 || path[:len(prefix)] != prefix {
		return "", false
	}
	rest := path[len(prefix):]
	name, _, ok := splitFirst(rest)
	return name, ok && name != ""
}

func splitFirst(path string) (string, string, bool) {
	for i := 0; i < len(path); i++ {
		if path[i] == '/' {
			return path[:i], path[i+1:], true
		}
	}
	return path, "", path != ""
}
