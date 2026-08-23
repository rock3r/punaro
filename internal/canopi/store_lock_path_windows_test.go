//go:build windows

package canopi

import "testing"

func TestStateStoreLockPathCanonicalizesWindowsCaseAliases(t *testing.T) {
	lower := stateStoreLockPath(`C:\data\state.json`)
	upper := stateStoreLockPath(`c:\DATA\STATE.JSON`)
	if lower != upper {
		t.Fatalf("case-alias lock paths differ: %q != %q", lower, upper)
	}
}
