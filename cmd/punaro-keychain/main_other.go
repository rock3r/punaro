//go:build !darwin

// punaro-keychain reports that macOS Keychain setup is unavailable on this platform.
package main

import (
	"fmt"
	"os"
)

func main() {
	_, _ = fmt.Fprintln(os.Stderr, "punaro-keychain: macOS Keychain wrapping-key setup is only available on macOS")
	os.Exit(2)
}
