//go:build windows

package main

import "os"

func privateProfilePath(string) bool      { return false }
func privateProfileFile(os.FileInfo) bool { return false }
