package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rock3r/punaro/internal/bootstrap"
	punarodiagnostic "github.com/rock3r/punaro/internal/diagnostic"
	"github.com/rock3r/punaro/internal/incrementalfs"
	punarorelease "github.com/rock3r/punaro/internal/release"
)

const (
	defaultBootstrapDoctorTimeout = 20 * time.Second
	maximumBootstrapDoctorTimeout = 30 * time.Second
)

var bootstrapBuildRelease string

type bootstrapExitError struct{ code int }

func (err bootstrapExitError) Error() string { return "" }
func (err bootstrapExitError) ExitCode() int { return err.code }

func runBootstrapDoctor(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("punaro-bootstrap doctor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "absolute private bootstrap directory")
	keysFile := flags.String("keys-file", "", "release public key set")
	origin := flags.String("origin", punarorelease.GitHubReleaseOrigin, "fixed HTTPS release origin")
	timeout := flags.Duration("timeout", defaultBootstrapDoctorTimeout, "total diagnostic deadline")
	machineID := flags.String("machine-id", strings.TrimSpace(os.Getenv("PUNARO_MACHINE_ID")), "stable fleet machine identity")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *directory == "" || *timeout < time.Second || *timeout > maximumBootstrapDoctorTimeout {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	var keys map[string]ed25519.PublicKey
	if *keysFile != "" {
		loaded, err := loadDoctorKeys(ctx, *keysFile)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "punaro-bootstrap doctor failed: release keys are unavailable")
			return 2
		}
		keys = loaded
	}
	report, err := bootstrap.Doctor(ctx, bootstrap.DoctorRequest{Directory: *directory, MachineID: strings.TrimSpace(*machineID), Origin: strings.TrimSpace(*origin), Keys: keys, BootstrapRelease: bootstrapBuildRelease})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "punaro-bootstrap doctor failed: diagnostic report unavailable")
		return 2
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		_, _ = fmt.Fprintln(stderr, "punaro-bootstrap doctor failed: diagnostic report unavailable")
		return 2
	}
	return punarodiagnostic.ExitCode(report)
}

func loadDoctorKeys(ctx context.Context, path string) (map[string]ed25519.PublicKey, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("bootstrap keys file is invalid")
	}
	body, err := incrementalfs.ReadFile(ctx, path, punarorelease.MaximumEnvelopeBytes)
	if err != nil {
		return nil, errors.New("bootstrap keys file is invalid")
	}
	return punarorelease.ParsePublicKeys(body)
}
