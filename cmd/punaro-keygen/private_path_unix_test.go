//go:build !windows

package main

import (
	"os"
	"syscall"
	"testing"
	"time"
)

type testFileInfo struct {
	mode os.FileMode
	sys  any
}

func (info testFileInfo) Name() string       { return "fixture" }
func (info testFileInfo) Size() int64        { return 0 }
func (info testFileInfo) Mode() os.FileMode  { return info.mode }
func (info testFileInfo) ModTime() time.Time { return time.Time{} }
func (info testFileInfo) IsDir() bool        { return info.mode.IsDir() }
func (info testFileInfo) Sys() any           { return info.sys }

func TestPrivateOwnershipChecksRejectOtherUsers(t *testing.T) {
	t.Parallel()
	// #nosec G115 -- os.Geteuid is non-negative on the supported Unix targets.
	owner := uint32(os.Geteuid())
	notOwner := owner + 1
	if notOwner == owner {
		notOwner--
	}
	if !isPrivateOwnedDirectory(testFileInfo{mode: os.ModeDir | 0o700, sys: &syscall.Stat_t{Uid: owner}}) {
		t.Fatal("current-user private directory was rejected")
	}
	if isPrivateOwnedDirectory(testFileInfo{mode: os.ModeDir | 0o700, sys: &syscall.Stat_t{Uid: notOwner}}) {
		t.Fatal("other-user private directory was accepted")
	}
	if !isPrivateOwnedRegularFile(testFileInfo{mode: 0o600, sys: &syscall.Stat_t{Uid: owner}}) {
		t.Fatal("current-user private file was rejected")
	}
	if isPrivateOwnedRegularFile(testFileInfo{mode: 0o600, sys: &syscall.Stat_t{Uid: notOwner}}) {
		t.Fatal("other-user private file was accepted")
	}
}
