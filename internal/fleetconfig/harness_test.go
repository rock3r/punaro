package fleetconfig

import "testing"

func TestDetectHarnessesMarksUnknownInstalledHarnessUnsupported(t *testing.T) {
	t.Parallel()
	lookup := func(path string) bool {
		return path == "/home/me/.claude" || path == "/home/me/.cursor"
	}
	got := DetectHarnesses("/home/me", lookup)
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
