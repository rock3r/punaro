package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/rock3r/punaro/internal/cutover"
	"github.com/rock3r/punaro/internal/operator"
	punaropostgres "github.com/rock3r/punaro/internal/postgres"
)

type mailCutoverCommand func(context.Context, operator.Installation, bool, bool, cutover.Request) (any, error)

func runMailCutover(args []string, stdout, stderr io.Writer, execute mailCutoverCommand) int {
	flags := flag.NewFlagSet("mail cutover", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "absolute Punaro installation directory")
	dryRun := flags.Bool("dry-run", false, "inspect source and target without changing either authority")
	abort := flags.Bool("abort", false, "abort the exact prepared epoch before source retirement")
	epochID := flags.String("epoch-id", "", "explicit cutover epoch UUID")
	expectedFingerprint := flags.String("expected-source-fingerprint", "", "exact fingerprint printed by dry-run")
	relayMachinesFile := flags.String("relay-machines-file", "", "protected static relay enrollment JSON to persist before execution")
	confirmed := flags.Bool("yes", false, "confirm the irreversible source retirement and PostgreSQL activation")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *directory == "" || execute == nil {
		return 2
	}
	if !*dryRun && !*abort && (!*confirmed || *epochID == "" || *expectedFingerprint == "") {
		_, _ = fmt.Fprintln(stderr, "mail cutover execution requires --epoch-id, --expected-source-fingerprint, and --yes")
		return 2
	}
	if *dryRun && (*abort || *confirmed || *epochID != "" || *expectedFingerprint != "" || *relayMachinesFile != "") {
		_, _ = fmt.Fprintln(stderr, "mail cutover dry-run does not accept execution authorization")
		return 2
	}
	if *abort && (!*confirmed || *epochID == "" || *expectedFingerprint != "" || *relayMachinesFile != "") {
		_, _ = fmt.Fprintln(stderr, "mail cutover abort requires --epoch-id and --yes")
		return 2
	}
	var installation operator.Installation
	var err error
	if !*dryRun && !*abort {
		installation, err = operator.LoadMailCutoverRecovery(*directory)
	} else {
		installation, err = operator.Load(*directory)
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "mail cutover installation is unavailable")
		return 1
	}
	if !*dryRun && !*abort {
		if *relayMachinesFile != "" {
			installation, err = operator.ConfigureMailCutoverRelayMachines(*directory, *relayMachinesFile)
			if err != nil {
				_, _ = fmt.Fprintln(stderr, "mail cutover relay enrollment is unavailable")
				return 1
			}
		}
		if installation.RelayMachinesJSON == "" {
			_, _ = fmt.Fprintln(stderr, "mail cutover execution requires --relay-machines-file")
			return 2
		}
	}
	if (*dryRun || *abort) && len(operator.CheckPaths(installation)) != 0 {
		_, _ = fmt.Fprintln(stderr, "mail cutover installation paths are not ready")
		return 1
	}
	request := cutover.Request{ActorPrincipalID: installation.OwnerPrincipalID, EpochID: *epochID, ExpectedSourceFingerprint: *expectedFingerprint, Cutoff: time.Now().UTC()}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	value, err := execute(ctx, installation, *dryRun, *abort, request)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "mail cutover failed")
		return 1
	}
	return writeJSON(stdout, stderr, value)
}

func executeMailCutover(ctx context.Context, installation operator.Installation, dryRun, abort bool, request cutover.Request) (any, error) {
	admin, err := punaropostgres.OpenAdministration(ctx, punaropostgres.Config{DSNFile: installation.OwnerDSNFile})
	if err != nil {
		return nil, errors.New("mail cutover administration is unavailable")
	}
	defer func() { _ = admin.Close() }()
	executor := cutover.Executor{
		Source: cutover.FileSource{Path: filepath.Join(installation.DataDir, "relay.db")}, Destination: admin, BatchSize: 128,
		Publish: func(_ context.Context, publication operator.MailCutoverPublication) error {
			_, err := operator.PublishMailCutover(installation.Directory, publication)
			return err
		},
	}
	if dryRun {
		return executor.DryRun(ctx)
	}
	if abort {
		return executor.Abort(ctx, request.ActorPrincipalID, request.EpochID)
	}
	return executor.Execute(ctx, request)
}
