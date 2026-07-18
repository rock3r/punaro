//go:build !windows

// punaro-dpapi reports that Windows DPAPI setup is unavailable on this platform.
package main

import (
	"fmt"
	"os"
)

func main() {
	_, _ = fmt.Fprintln(os.Stderr, "punaro-dpapi: Windows DPAPI wrapping-key setup is only available on Windows")
	os.Exit(2)
}
