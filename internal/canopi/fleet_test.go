package canopi

import (
	"strings"
	"testing"
)

func TestEncodeFleetConvergenceOmitsConfigurationContents(t *testing.T) {
	t.Parallel()
	body, err := EncodeFleetConvergence(4, strings.Repeat("ab", 32), "current")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, `"kind":"fleet_config"`) || !strings.Contains(text, `"generation":4`) {
		t.Fatalf("body=%s", text)
	}
	if strings.Contains(text, "AGENTS.md") || strings.Contains(text, "# fleet") || strings.Contains(text, "/Users/") {
		t.Fatalf("leaked contents: %s", text)
	}
}
