//go:build !windows

package main

import (
	"os"
	"syscall"
)

func executeSelectedComponent(path string, arguments []string) (int, error) {
	argv := append([]string{path}, arguments...)
	return 1, syscall.Exec(path, argv, os.Environ()) // #nosec G204,G702 -- path uses the launcher's closed component allowlist.
}
