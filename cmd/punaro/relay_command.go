package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/rock3r/punaro/internal/operator"
	punaropostgres "github.com/rock3r/punaro/internal/postgres"
	"github.com/rock3r/punaro/internal/relay"
)

type relayConfigureCommand func(string, string) (operator.Installation, error)

type relayRegisterCommand func(string, string) (operator.Installation, error)

func runRelayConfigure(args []string, stdout, stderr io.Writer, configure relayConfigureCommand) int {
	flags := flag.NewFlagSet("relay configure", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "absolute Punaro installation directory")
	machinesFile := flags.String("relay-machines-file", "", "protected complete public relay machine enrollment JSON file")
	confirmed := flags.Bool("yes", false, "confirm replacing the complete relay machine enrollment set")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *directory == "" || *machinesFile == "" || !*confirmed || configure == nil {
		return 2
	}
	installation, err := configure(*directory, *machinesFile)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "relay configuration did not complete; rerun the exact command to recover safely")
		return 1
	}
	return writeJSON(stdout, stderr, map[string]any{"status": "relay_configured", "directory": installation.Directory})
}

func runRelayRegister(args []string, stdout, stderr io.Writer, register relayRegisterCommand) int {
	flags := flag.NewFlagSet("relay register", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "absolute Punaro installation directory")
	machineFile := flags.String("machine-enrollment-file", "", "protected single public machine enrollment JSON object")
	confirmed := flags.Bool("yes", false, "confirm post-cutover registration and relay authority publication")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *directory == "" || *machineFile == "" || !*confirmed || register == nil {
		return 2
	}
	installation, err := register(*directory, *machineFile)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "relay machine registration did not complete; rerun the exact command to recover safely")
		return 1
	}
	return writeJSON(stdout, stderr, map[string]any{"status": "relay_machine_registered", "directory": installation.Directory})
}

func registerPostCutoverRelayMachine(directory, machineFile string) (operator.Installation, error) {
	installation, err := operator.LoadMailCutoverRecovery(directory)
	if err != nil || installation.MailCutover == nil {
		return operator.Installation{}, fmt.Errorf("post-cutover installation is unavailable")
	}
	ctx := context.Background()
	state, err := inspectSchema(ctx, installation.AppDSNFile)
	if err != nil || state.Classification != punaropostgres.Compatible {
		return operator.Installation{}, fmt.Errorf("post-cutover schema is incompatible")
	}
	if err := verifyInstallationPair(ctx, installation.AppDSNFile, installation.OwnerDSNFile); err != nil {
		return operator.Installation{}, fmt.Errorf("post-cutover database roles do not match")
	}
	owner, err := inspectOwner(ctx, installation.AppDSNFile)
	if err != nil || owner.ID != installation.OwnerPrincipalID {
		return operator.Installation{}, fmt.Errorf("post-cutover owner does not match")
	}
	admin, err := punaropostgres.OpenAdministration(ctx, punaropostgres.Config{DSNFile: installation.OwnerDSNFile})
	if err != nil {
		return operator.Installation{}, fmt.Errorf("post-cutover administration is unavailable")
	}
	defer func() { _ = admin.Close() }()
	return operator.RegisterPostCutoverRelayMachine(directory, machineFile, func(name string, publicKey ed25519.PublicKey) error {
		_, err := admin.RegisterPostCutoverLegacyMachine(ctx, installation.OwnerPrincipalID, name, publicKey)
		return err
	})
}

type relayReconcileCapacityCommand func(string) (relay.QuotaCounters, error)

func runRelayReconcileCapacity(args []string, stdout, stderr io.Writer, reconcile relayReconcileCapacityCommand) int {
	flags := flag.NewFlagSet("relay reconcile-capacity", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "absolute Punaro installation directory")
	confirmed := flags.Bool("yes", false, "confirm rebuilding pending-delivery capacity counters")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *directory == "" || !*confirmed || reconcile == nil {
		return 2
	}
	counters, err := reconcile(*directory)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "relay capacity reconciliation did not complete; rerun the exact command to recover safely")
		return 1
	}
	return writeJSON(stdout, stderr, map[string]any{"status": "capacity_reconciled", "directory": *directory, "pending_count": counters.Count, "pending_bytes": counters.Bytes})
}

func reconcileRelayCapacity(directory string) (relay.QuotaCounters, error) {
	installation, err := operator.Load(directory)
	if err != nil {
		return relay.QuotaCounters{}, err
	}
	if installation.MailCutover != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		database, err := punaropostgres.OpenApplication(ctx, punaropostgres.Config{DSNFile: installation.AppDSNFile})
		if err != nil {
			return relay.QuotaCounters{}, err
		}
		defer func() { _ = database.Close() }()
		return database.ReconcilePendingQuota(ctx)
	}
	path := filepath.Join(installation.DataDir, "relay.db")
	if _, err := os.Stat(path); err != nil {
		return relay.QuotaCounters{}, errors.New("relay capacity store is unavailable")
	}
	store, err := relay.OpenForCapacityRepair(path)
	if err != nil {
		return relay.QuotaCounters{}, err
	}
	defer func() { _ = store.Close() }()
	return relay.ReconcilePendingQuota(store)
}

type relayTerminalListCommand func(string, int, string) (relay.TerminalPage, error)

func runRelayTerminalList(args []string, stdout, stderr io.Writer, list relayTerminalListCommand) int {
	flags := flag.NewFlagSet("relay terminal list", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "absolute Punaro installation directory")
	limit := flags.Int("limit", relay.DefaultRoleListLimit, "page size from 1 to 100")
	after := flags.String("after", "", "opaque delivery id from the previous page")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *directory == "" || *limit < 1 || *limit > relay.MaxRoleListLimit || list == nil {
		return 2
	}
	page, err := list(*directory, *limit, *after)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "relay terminal list did not complete; rerun the exact command to recover safely")
		return 1
	}
	return writeJSON(stdout, stderr, page)
}

type relayTerminalMaintainCommand func(string) (relay.MaintenanceResult, error)

func runRelayTerminalMaintain(args []string, stdout, stderr io.Writer, maintain relayTerminalMaintainCommand) int {
	flags := flag.NewFlagSet("relay terminal maintain", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "absolute Punaro installation directory")
	confirmed := flags.Bool("yes", false, "confirm one bounded pending-expiry and terminal-prune batch")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *directory == "" || !*confirmed || maintain == nil {
		return 2
	}
	result, err := maintain(*directory)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "relay terminal maintenance did not complete; rerun the exact command to recover safely")
		return 1
	}
	return writeJSON(stdout, stderr, map[string]any{"status": "terminal_maintained", "directory": *directory, "expired": result.Expired, "pruned": result.Pruned})
}

func openRelayTerminalStore(directory string) (interface {
	ListTerminalDeliveries(int, string) (relay.TerminalPage, error)
	MaintainTerminalDeliveries(time.Time) (relay.MaintenanceResult, error)
	Close() error
}, error) {
	installation, err := operator.Load(directory)
	if err != nil {
		return nil, err
	}
	if installation.MailCutover != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		database, err := punaropostgres.OpenApplication(ctx, punaropostgres.Config{DSNFile: installation.AppDSNFile})
		if err != nil {
			return nil, err
		}
		return database, nil
	}
	path := filepath.Join(installation.DataDir, "relay.db")
	if _, err := os.Stat(path); err != nil {
		return nil, errors.New("relay terminal store is unavailable")
	}
	return relay.Open(path)
}

func listRelayTerminalDeliveries(directory string, limit int, after string) (relay.TerminalPage, error) {
	store, err := openRelayTerminalStore(directory)
	if err != nil {
		return relay.TerminalPage{}, err
	}
	defer func() { _ = store.Close() }()
	return store.ListTerminalDeliveries(limit, after)
}

func maintainRelayTerminalDeliveries(directory string) (relay.MaintenanceResult, error) {
	store, err := openRelayTerminalStore(directory)
	if err != nil {
		return relay.MaintenanceResult{}, err
	}
	defer func() { _ = store.Close() }()
	return store.MaintainTerminalDeliveries(time.Now().UTC())
}
