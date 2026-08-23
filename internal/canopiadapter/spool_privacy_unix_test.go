//go:build !windows

package canopiadapter

import (
	"os"
	"syscall"
	"testing"
	"time"
)

type spoolDirectoryInfo struct {
	uid uint32
}

func (i spoolDirectoryInfo) Name() string       { return "spool" }
func (i spoolDirectoryInfo) Size() int64        { return 0 }
func (i spoolDirectoryInfo) Mode() os.FileMode  { return os.ModeDir | 0o700 }
func (i spoolDirectoryInfo) ModTime() time.Time { return time.Time{} }
func (i spoolDirectoryInfo) IsDir() bool        { return true }
func (i spoolDirectoryInfo) Sys() any           { return &syscall.Stat_t{Uid: i.uid} }

func TestSpoolDirectoryMustBelongToCurrentUser(t *testing.T) {
	current := uint32(os.Geteuid()) // #nosec G115 -- the OS effective UID fits syscall.Stat_t.
	if !ownedSpoolDirectory(spoolDirectoryInfo{uid: current}) {
		t.Fatal("current-user spool directory was rejected")
	}
	other := current + 1
	if other == current {
		other = current - 1
	}
	if ownedSpoolDirectory(spoolDirectoryInfo{uid: other}) {
		t.Fatal("other-user spool directory was accepted")
	}
}
