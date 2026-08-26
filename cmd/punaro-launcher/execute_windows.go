//go:build windows

package main

import (
	"errors"
	"os"
	"os/exec"
)

func executeSelectedComponent(path string, arguments []string) (int, error) {
	// #nosec G204,G702 -- path uses the launcher's closed component allowlist.
	command := exec.Command(path, arguments...) //nolint:noctx // Windows child lifetime intentionally matches the dispatcher process; path uses the closed component allowlist.
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.Env = os.Environ()
	if err := command.Run(); err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return exitError.ExitCode(), nil
		}
		return 1, err
	}
	return 0, nil
}
