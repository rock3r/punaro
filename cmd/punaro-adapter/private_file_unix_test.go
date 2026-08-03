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
	uid := uint32(os.Geteuid())
	if isOwnedByEffectiveUser(privateFileInfo{sys: &syscall.Stat_t{Uid: uid + 1}}) {
		t.Fatal("private file owned by another user was accepted")
	}
	if !isOwnedByEffectiveUser(privateFileInfo{sys: &syscall.Stat_t{Uid: uid}}) {
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
