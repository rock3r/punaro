//go:build windows

package canopi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStateStoreLockPathCanonicalizesWindowsCaseAliases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "State.json")
	if err := os.WriteFile(path, []byte("state"), 0o600); err != nil {
		t.Fatal(err)
	}
	canonical, err := stateStoreLockPath(path)
	if err != nil {
		t.Fatal(err)
	}
	aliases := []string{strings.ToUpper(path), `\\?\` + path}
	for _, alias := range aliases {
		got, err := stateStoreLockPath(alias)
		if err != nil {
			t.Fatalf("stateStoreLockPath(%q): %v", alias, err)
		}
		if got != canonical {
			t.Fatalf("alias lock path = %q, want %q", got, canonical)
		}
	}
}
