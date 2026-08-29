//go:build !windows

package canopicredential

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadTokenAcceptsOnlyBoundedPrivateStableFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "token")
	const want = "0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(path, []byte(want+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadToken(path); err != nil || got != want {
		t.Fatalf("ReadToken(private) = %q, %v", got, err)
	}

	unsafePath := filepath.Join(directory, "unsafe")
	// #nosec G306 -- deliberately unsafe permissions verify fail-closed loading.
	if err := os.WriteFile(unsafePath, []byte(want), 0o644); err != nil {
		t.Fatal(err)
	}
	assertTokenRejected(t, unsafePath)

	linkPath := filepath.Join(directory, "link")
	if err := os.Symlink(path, linkPath); err != nil {
		t.Fatal(err)
	}
	assertTokenRejected(t, linkPath)

	hardlinkPath := filepath.Join(directory, "hardlink")
	if err := os.Link(path, hardlinkPath); err != nil {
		t.Fatal(err)
	}
	assertTokenRejected(t, path)

	assertTokenRejected(t, directory+"/./hardlink")
	assertTokenRejected(t, "relative-token")
}

func TestReadTokenRejectsInvalidLength(t *testing.T) {
	for name, token := range map[string]string{
		"short": "too-short",
		"large": strings.Repeat("x", 4097),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
				t.Fatal(err)
			}
			assertTokenRejected(t, path)
		})
	}
}

func TestReadTokenRejectsHeaderUnsafeOrMultilineValues(t *testing.T) {
	for name, token := range map[string]string{
		"two lines":       "0123456789abcdef\n0123456789abcdef",
		"embedded return": "0123456789abcdef\r0123456789abcdef",
		"space":           "01234567 89abcdef",
		"control":         "0123456789abcdef\x7f",
		"non ASCII":       "0123456789abcdeé",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
				t.Fatal(err)
			}
			assertTokenRejected(t, path)
		})
	}
}

func assertTokenRejected(t *testing.T, path string) {
	t.Helper()
	if _, err := ReadToken(path); err == nil {
		t.Fatalf("ReadToken(%q) accepted an unsafe token file", path)
	}
}
