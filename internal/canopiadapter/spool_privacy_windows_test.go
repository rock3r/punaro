//go:build windows

package canopiadapter

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsSpoolDirectoryGetsExclusiveCurrentUserACL(t *testing.T) {
	spool := Spool{Directory: t.TempDir()}
	if err := spool.ensureDirectory(); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid == nil {
		t.Fatalf("current user: %v", err)
	}
	if !privateWindowsSpoolACL(spool.Directory, user.User.Sid) {
		t.Fatal("spool directory does not have a protected current-user-only ACL")
	}
}
