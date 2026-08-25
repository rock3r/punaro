// punaro-launcher is the stable installer-owned dispatcher for signed client
// components. The familiar command names are copies of this binary; payloads
// always execute from the selected bootstrap slot.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
)

var allowedComponents = map[string]struct{}{
	"punaro-adapter":            {},
	"punaro-enroll":             {},
	"punaro-memory":             {},
	"punaro-trusted-attachment": {},
}

func main() {
	os.Exit(run())
}

func run() int {
	path, err := selectedComponentPath(runtime.GOOS, runtime.GOARCH, userHome(), os.Getenv("LOCALAPPDATA"), filepath.Base(os.Args[0]))
	if err != nil {
		fmt.Fprintln(os.Stderr, "punaro launcher: selected component is unavailable; run the Punaro client installer or bootstrap doctor")
		return 1
	}
	info, err := os.Lstat(path) // #nosec G703 -- path is constrained to one allowlisted component below the private bootstrap root.
	if err != nil || !info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		fmt.Fprintln(os.Stderr, "punaro launcher: selected component is unavailable; run the Punaro client installer or bootstrap doctor")
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	command := exec.CommandContext(ctx, path, os.Args[1:]...) // #nosec G204,G702 -- executable path uses a closed component allowlist.
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.Env = os.Environ()
	if err := command.Run(); err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return exitError.ExitCode()
		}
		fmt.Fprintln(os.Stderr, "punaro launcher: selected component could not start")
		return 1
	}
	return 0
}

func userHome() string {
	home, _ := os.UserHomeDir()
	return home
}

func selectedComponentPath(goos, goarch, home, localAppData, invoked string) (string, error) {
	component := strings.TrimSuffix(filepath.Base(invoked), ".exe")
	if _, ok := allowedComponents[component]; !ok || (goarch != "amd64" && goarch != "arm64") {
		return "", errors.New("unsupported component")
	}
	name := component + "-" + goos + "-" + goarch
	var root string
	switch goos {
	case "darwin", "linux":
		if !filepath.IsAbs(home) {
			return "", errors.New("home is unavailable")
		}
		root = filepath.Join(home, ".local", "state", "punaro-bootstrap")
	case "windows":
		if !filepath.IsAbs(localAppData) {
			return "", errors.New("local app data is unavailable")
		}
		root = filepath.Join(localAppData, "Punaro", "bootstrap")
		name += ".exe"
	default:
		return "", errors.New("unsupported platform")
	}
	return filepath.Join(root, "current", name), nil
}
