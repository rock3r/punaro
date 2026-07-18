//go:build !windows

package v2

import "syscall"

func directorySnapshotTestSys(uid uint32) any { return &syscall.Stat_t{Uid: uid} }
