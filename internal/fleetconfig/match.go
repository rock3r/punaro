package fleetconfig

import (
	"os"
	"path/filepath"
	"strings"
)

// ProjectMatch is a content-free project-path decision.
type ProjectMatch struct {
	Name string
	Path string
	Kind string
}

// MatchProjects maps published project names onto top-level directories.
func MatchProjects(base string, overrides map[string]string, names []string, lookup func(string) bool) []ProjectMatch {
	if lookup == nil {
		lookup = dirExists
	}
	if base == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			base = filepath.Join(home, "src")
		}
	}
	matches := make([]ProjectMatch, 0, len(names))
	for _, name := range names {
		if override := strings.TrimSpace(overrides[name]); override != "" {
			if filepath.IsAbs(override) && lookup(override) {
				matches = append(matches, ProjectMatch{Name: name, Path: override, Kind: "override"})
			} else {
				matches = append(matches, ProjectMatch{Name: name, Kind: "unmatched"})
			}
			continue
		}
		path := filepath.Join(base, name)
		if lookup(path) {
			matches = append(matches, ProjectMatch{Name: name, Path: path, Kind: "matched"})
			continue
		}
		matches = append(matches, ProjectMatch{Name: name, Kind: "unmatched"})
	}
	return matches
}

func dirExists(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0
}
