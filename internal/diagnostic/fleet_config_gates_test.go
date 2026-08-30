package diagnostic

import (
	"os"
	"strings"
	"testing"
)

func TestFleetConfigReleaseGatesRemainUnchecked(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile("../../docs/security-release-gates.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, "## Fleet-global agent configuration (gated candidate; closed)") {
		t.Fatal("missing fleet-config release-gate section")
	}
	if strings.Contains(text, "- [x]") || strings.Contains(text, "- [X]") {
		t.Fatal("release gates may not be checked without official release-evidence")
	}
}
