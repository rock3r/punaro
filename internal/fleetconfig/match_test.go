package fleetconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMatchProjectsIsTopLevelOnlyAndHonorsOverride(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	if err := os.Mkdir(filepath.Join(base, "punaro"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(base, "nested", "canopi"), 0o700); err != nil {
		t.Fatal(err)
	}
	override := t.TempDir()
	matches := MatchProjects(base, map[string]string{"canopi": override}, []string{"punaro", "canopi", "missing"}, dirExists)
	if len(matches) != 3 {
		t.Fatalf("matches=%#v", matches)
	}
	if matches[0].Kind != "matched" || matches[0].Path != filepath.Join(base, "punaro") {
		t.Fatalf("punaro=%#v", matches[0])
	}
	if matches[1].Kind != "override" || matches[1].Path != override {
		t.Fatalf("canopi=%#v", matches[1])
	}
	if matches[2].Kind != "unmatched" || matches[2].Path != "" {
		t.Fatalf("missing=%#v", matches[2])
	}
	nested := filepath.Join(base, "nested", "canopi")
	for _, match := range matches {
		if match.Path == nested {
			t.Fatal("nested project matched")
		}
	}
}
