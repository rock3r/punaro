//go:build darwin || dragonfly || freebsd || netbsd || openbsd || solaris

package main

import "golang.org/x/sys/unix"

func syncAllFilesystems() error { return unix.Sync() }
