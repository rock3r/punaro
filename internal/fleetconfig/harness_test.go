package fleetconfig

import (
	"path/filepath"
	"testing"
)

func TestDetectHarnessesMarksUnknownInstalledHarnessUnsupported(t *testing.T) {
	t.Parallel()
	home := filepath.Join("home", "me")
	lookup := func(path string) bool {
		return path == filepath.Join(home, ".claude") || path == filepath.Join(home, ".cursor")
	}
	got := DetectHarnesses(home, "", lookup)
	var sawClaude, sawUnsupported, sawAgents bool
	for _, harness := range got {
		switch harness.Name {
		case "claude":
			sawClaude = harness.Activation == "next_session" && harness.State == "current"
		case "unknown":
			sawUnsupported = harness.State == "unsupported"
		case "agents":
			sawAgents = harness.Activation == "next_turn"
		}
	}
	if !sawClaude || !sawUnsupported || !sawAgents {
		t.Fatalf("projections=%#v", got)
	}
}

func TestDetectHarnessesIncludesGeminiFromProjectMarker(t *testing.T) {
	t.Parallel()
	home := filepath.Join("home", "me")
	project := filepath.Join("repo", "punaro")
	lookup := func(path string) bool {
		return path == filepath.Join(project, "GEMINI.md")
	}
	got := DetectHarnesses(home, project, lookup)
	for _, harness := range got {
		if harness.Name == "gemini" && harness.Activation == "next_session" && harness.State == "current" {
			return
		}
	}
	t.Fatalf("missing gemini projection=%#v", got)
}
