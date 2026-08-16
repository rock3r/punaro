// punaro-bootstrap installs signed Punaro artifacts from GitHub Releases.
// It verifies catalog and manifest signatures and exact artifact digests.
package main

import (
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rock3r/punaro/internal/bootstrap"
	punarorelease "github.com/rock3r/punaro/internal/release"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(2)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: punaro-bootstrap update|status|rollback")
	}
	switch args[0] {
	case "update":
		return runUpdate(args[1:])
	case "status":
		return runStatus(args[1:])
	case "rollback":
		return runRollback(args[1:])
	default:
		return errors.New("usage: punaro-bootstrap update|status|rollback")
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
		return nil
	}
	fmt.Printf("current %s sequence %d\n", state.Current, state.CurrentSequence)
	if state.Previous != "" {
		fmt.Printf("previous %s sequence %d\n", state.Previous, state.PreviousSequence)
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
