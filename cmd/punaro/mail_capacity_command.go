package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/rock3r/punaro/internal/operator"
	punaropostgres "github.com/rock3r/punaro/internal/postgres"
	"github.com/rock3r/punaro/internal/relay"
)

type mailReconcileCapacityCommand func(operator.Installation) error

func runMailReconcileCapacity(args []string, stdout, stderr io.Writer, execute mailReconcileCapacityCommand) int {
	flags := flag.NewFlagSet("mail reconcile-capacity", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "absolute Punaro installation directory")
	confirmed := flags.Bool("yes", false, "confirm bounded pending-capacity counter repair")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *directory == "" || !*confirmed || execute == nil {
		if flags.Parsed() && *directory != "" && !*confirmed {
			_, _ = fmt.Fprintln(stderr, "mail capacity reconciliation requires --yes")
		}
		return 2
	}
	installation, err := operator.Load(*directory)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "mail capacity reconciliation installation is unavailable")
		return 1
	}
	if err := execute(installation); err != nil {
		_, _ = fmt.Fprintln(stderr, "mail capacity reconciliation failed")
		return 1
	}
	return writeJSON(stdout, stderr, map[string]any{"status": "capacity_reconciled", "directory": installation.Directory})
}

func executeMailReconcileCapacity(installation operator.Installation) error {
	if installation.MailCutover != nil {
		ctx := context.Background()
		database, err := punaropostgres.OpenApplication(ctx, punaropostgres.Config{DSNFile: installation.AppDSNFile})
		if err != nil {
			return err
		}
		defer func() { _ = database.Close() }()
		return database.ReconcilePendingCapacity()
	}
	return relay.ReconcilePendingCapacityFile(filepath.Join(installation.DataDir, "relay.db"))
}
