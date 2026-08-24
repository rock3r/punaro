//go:build !windows

package main

import (
	"os"
	"strconv"
)

func currentUserID() string { return strconv.Itoa(os.Getuid()) }
