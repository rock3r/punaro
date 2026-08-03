//go:build !windows

package main

import (
	"io/fs"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestPrivateFileRequiresEffectiveOwner(t *testing.T) {
	info, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("temporary directory did not provide Unix file metadata")
	}
	other := *stat
	other.Uid ^= 1
	if isOwnedByEffectiveUser(privateFileInfo{sys: &other}) {
		t.Fatal("private file owned by another user was accepted")
	}
	if !isOwnedByEffectiveUser(info) {
		t.Fatal("private file owned by the effective user was rejected")
	}
}

type privateFileInfo struct {
	sys any
}

func (privateFileInfo) Name() string       { return "profile" }
func (privateFileInfo) Size() int64        { return 0 }
func (privateFileInfo) Mode() fs.FileMode  { return 0o600 }
func (privateFileInfo) ModTime() time.Time { return time.Time{} }
func (privateFileInfo) IsDir() bool        { return false }
func (info privateFileInfo) Sys() any      { return info.sys }
