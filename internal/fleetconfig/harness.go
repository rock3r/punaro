package fleetconfig

import "os"

// HarnessProjection is one built-in coding-agent mapping.
type HarnessProjection struct {
	Name       string
	Activation string
	State      string
}

// DetectHarnesses reports supported and unsupported installed harnesses.
func DetectHarnesses(home string, lookup func(string) bool) []HarnessProjection {
	if lookup == nil {
		lookup = func(path string) bool {
			_, err := os.Lstat(path)
			return err == nil
		}
	}
	projections := []HarnessProjection{
		{Name: "agents", Activation: "next_turn", State: "current"},
	}
	known := []struct {
		name       string
		marker     string
		activation string
	}{
		{name: "codex", marker: ".codex", activation: "next_turn"},
		{name: "claude", marker: ".claude", activation: "next_session"},
		{name: "gemini", marker: ".gemini", activation: "next_session"},
	}
	for _, harness := range known {
		if lookup(home + "/" + harness.marker) {
			projections = append(projections, HarnessProjection{Name: harness.name, Activation: harness.activation, State: "current"})
		}
	}
	if lookup(home+"/.cursor") || lookup(home+"/.windsurf") {
		projections = append(projections, HarnessProjection{Name: "unknown", Activation: "restart_required", State: "unsupported"})
	}
	return projections
}
