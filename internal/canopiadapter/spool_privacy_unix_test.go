//go:build !windows

package canopiadapter

import (
	"os"
	"path/filepath"
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

func TestSpoolRepairLockSerializesConcurrentRepair(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".enqueue.lock")
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- withSpoolRepairLock(path, func() error {
			close(firstEntered)
			<-releaseFirst
			return nil
		})
	}()
	<-firstEntered
	secondEntered := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		secondDone <- withSpoolRepairLock(path, func() error {
			close(secondEntered)
			return nil
		})
	}()
	select {
	case <-secondEntered:
		t.Fatal("second spool-lock repair entered while the first held the directory repair lock")
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseFirst)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-secondEntered:
	case <-time.After(time.Second):
		t.Fatal("second spool-lock repair did not enter after the first released")
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
}

func TestSpoolLocksRejectPreexistingSymlinks(t *testing.T) {
	for _, name := range []string{".enqueue.lock", ".drain.lock", ".supervisor.lock"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name)
			if err := os.Symlink(name, path); err != nil {
				t.Fatal(err)
			}
			file, err := openSpoolLockFile(path)
			if err != nil {
				t.Fatalf("openSpoolLockFile() did not recover from planted symlink: %v", err)
			}
			defer func() { _ = file.Close() }()
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if !privateSpoolFile(path, info) {
				t.Fatal("recovered spool lock is not a private current-user file")
			}
		})
	}
}
