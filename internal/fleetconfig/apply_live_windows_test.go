//go:build windows

package fleetconfig

import (
	"os"
	"strings"
	"testing"
)

func TestApplyLiveCopiesCommonSkillAsRegularFileNotJunction(t *testing.T) {
	t.Parallel()
	_, _, dest, _ := applyCopiedCommonSkill(t, skillMarkdown("shared", skillBodyProbe), nil)
	info, err := os.Lstat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("windows dest is not a regular file mode=%v", info.Mode())
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("windows dest is a symlink")
	}
	if destIsJunctionOrReparse(info) {
		t.Fatal("windows dest is a junction or reparse point")
	}
	body, err := os.ReadFile(dest) //nolint:gosec // G304: test fixture under t.TempDir.
	if err != nil || !strings.Contains(string(body), skillBodyProbe) {
		t.Fatalf("windows dest missing published skill: %q err=%v", body, err)
	}
}
