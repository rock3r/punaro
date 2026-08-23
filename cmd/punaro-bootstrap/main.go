// punaro-bootstrap installs signed Punaro artifacts from GitHub Releases
// and supervises the current-slot adapter.
package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rock3r/punaro/internal/bootstrap"
	punarorelease "github.com/rock3r/punaro/internal/release"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		code := 2
		var coded interface{ ExitCode() int }
		if errors.As(err, &coded) {
			code = coded.ExitCode()
		}
		if err.Error() != "" {
			fmt.Fprintln(os.Stderr, err.Error())
		}
		os.Exit(code)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: punaro-bootstrap update|status|doctor|fleet-doctor|rollback|run|seed-checkout|version")
	}
	switch args[0] {
	case "update":
		return runUpdate(args[1:])
	case "status":
		return runStatus(args[1:])
	case "doctor":
		if code := runBootstrapDoctor(args[1:], os.Stdout, os.Stderr); code != 0 {
			return bootstrapExitError{code: code}
		}
		return nil
	case "fleet-doctor":
		if code := runFleetDoctor(args[1:], os.Stdout, os.Stderr); code != 0 {
			return bootstrapExitError{code: code}
		}
		return nil
	case "rollback":
		return runRollback(args[1:])
	case "run":
		return runRun(args[1:])
	case "seed-checkout":
		return runSeedCheckout(args[1:])
	case "version":
		if len(args) != 1 || bootstrapBuildRelease == "" {
			return bootstrapExitError{code: 1}
		}
		fmt.Println(bootstrapBuildRelease)
		return nil
	default:
		return errors.New("usage: punaro-bootstrap update|status|doctor|fleet-doctor|rollback|run|seed-checkout|version")
	}
}

func runUpdate(args []string) error {
	flags := flag.NewFlagSet("punaro-bootstrap update", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directory := flags.String("directory", "", "absolute private bootstrap directory")
	keysFile := flags.String("keys-file", "", "release public key set")
	origin := flags.String("origin", punarorelease.GitHubReleaseOrigin, "fixed HTTPS release origin")
	releaseName := flags.String("release", "", "catalog-listed release to install")
	if err := flags.Parse(args); err != nil {
		return errors.New("bootstrap update is invalid")
	}
	if flags.NArg() != 0 || *directory == "" || *keysFile == "" {
		return errors.New("bootstrap update is invalid")
	}
	keys, err := loadKeys(*keysFile)
	if err != nil {
		return err
	}
	result, err := bootstrap.Update(bootstrap.Request{
		Directory: *directory,
		Origin:    strings.TrimSpace(*origin),
		Keys:      keys,
		Release:   *releaseName,
	})
	if err != nil {
		return err
	}
	fmt.Printf("installed %s sequence %d\n", result.Release, result.Sequence)
	return nil
}

func runStatus(args []string) error {
	flags := flag.NewFlagSet("punaro-bootstrap status", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directory := flags.String("directory", "", "absolute private bootstrap directory")
	if err := flags.Parse(args); err != nil {
		return errors.New("bootstrap status is invalid")
	}
	if flags.NArg() != 0 || *directory == "" {
		return errors.New("bootstrap status is invalid")
	}
	state, err := bootstrap.Status(*directory)
	if err != nil {
		return err
	}
	if state.Current == "" {
		fmt.Println("current none")
		if state.RecoveryOnly {
			fmt.Println("recovery-only")
		}
		return nil
	}
	fmt.Printf("current %s sequence %d\n", state.Current, state.CurrentSequence)
	if state.Previous != "" {
		fmt.Printf("previous %s sequence %d\n", state.Previous, state.PreviousSequence)
	}
	if state.RecoveryOnly {
		fmt.Println("recovery-only")
	}
	return nil
}

func runRollback(args []string) error {
	flags := flag.NewFlagSet("punaro-bootstrap rollback", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directory := flags.String("directory", "", "absolute private bootstrap directory")
	if err := flags.Parse(args); err != nil {
		return errors.New("bootstrap rollback is invalid")
	}
	if flags.NArg() != 0 || *directory == "" {
		return errors.New("bootstrap rollback is invalid")
	}
	result, err := bootstrap.Rollback(*directory)
	if err != nil {
		return err
	}
	fmt.Printf("rolled back to %s sequence %d\n", result.Release, result.Sequence)
	return nil
}

func runRun(args []string) error {
	flags := flag.NewFlagSet("punaro-bootstrap run", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directory := flags.String("directory", "", "absolute private bootstrap directory")
	keysFile := flags.String("keys-file", "", "release public key set")
	origin := flags.String("origin", punarorelease.GitHubReleaseOrigin, "fixed HTTPS release origin")
	if err := flags.Parse(args); err != nil {
		return errors.New("bootstrap run is invalid")
	}
	if flags.NArg() != 0 || *directory == "" {
		return errors.New("bootstrap run is invalid")
	}
	var keys map[string]ed25519.PublicKey
	if *keysFile != "" {
		loaded, err := loadKeys(*keysFile)
		if err != nil {
			return err
		}
		keys = loaded
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	err := bootstrap.Run(ctx, bootstrap.RunRequest{
		Directory:     *directory,
		Origin:        strings.TrimSpace(*origin),
		Keys:          keys,
		HealthTimeout: bootstrap.DefaultHealthTimeout,
		HealthWindow:  bootstrap.DefaultHealthWindow,
		WaitRecovery:  true,
		OnRecoveryOnly: func() {
			fmt.Println("recovery-only")
		},
	})
	if errors.Is(err, bootstrap.ErrRecoveryOnly) {
		return nil
	}
	return err
}

func runSeedCheckout(args []string) error {
	flags := flag.NewFlagSet("punaro-bootstrap seed-checkout", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directory := flags.String("directory", "", "absolute private bootstrap directory")
	adapter := flags.String("adapter", "", "absolute checkout adapter binary")
	keysFile := flags.String("keys-file", "", "release public key set")
	if err := flags.Parse(args); err != nil {
		return errors.New("bootstrap seed-checkout is invalid")
	}
	if flags.NArg() != 0 || *directory == "" || *adapter == "" {
		return errors.New("bootstrap seed-checkout is invalid")
	}
	var keys map[string]ed25519.PublicKey
	if *keysFile != "" {
		loaded, err := loadKeys(*keysFile)
		if err != nil {
			return err
		}
		keys = loaded
	}
	return bootstrap.SeedLocalCheckout(*directory, *adapter, keys)
}

func loadKeys(path string) (map[string]ed25519.PublicKey, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("bootstrap keys file is invalid")
	}
	body, err := os.ReadFile(path) // #nosec G304 -- operator-selected public key set.
	if err != nil {
		return nil, errors.New("bootstrap keys file is invalid")
	}
	return punarorelease.ParsePublicKeys(body)
}
