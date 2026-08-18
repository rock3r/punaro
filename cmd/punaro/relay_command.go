package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

type relayListTerminalsCommand func(string, relay.TerminalListInput) (relay.TerminalListPage, error)

func runRelayListTerminals(args []string, stdout, stderr io.Writer, list relayListTerminalsCommand) int {
	flags := flag.NewFlagSet("relay list-terminals", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "absolute Punaro installation directory")
	limit := flags.Int("limit", 0, "bounded terminal page size")
	cursor := flags.String("cursor", "", "opaque terminal list cursor")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *directory == "" || list == nil {
		return 2
	}
	page, err := list(*directory, relay.TerminalListInput{Cursor: *cursor, Limit: *limit})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "relay terminal listing did not complete; rerun the exact command to recover safely")
		return 1
	}
	payload := map[string]any{"status": "terminals_listed", "directory": *directory, "terminals": page.Terminals}
	if page.NextCursor != "" {
		payload["next_cursor"] = page.NextCursor
	}
	return writeJSON(stdout, stderr, payload)
}

type relayMaintainDeliveriesCommand func(string) (relay.MaintenanceResult, error)

func runRelayMaintainDeliveries(args []string, stdout, stderr io.Writer, maintain relayMaintainDeliveriesCommand) int {
	flags := flag.NewFlagSet("relay maintain-deliveries", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "absolute Punaro installation directory")
	confirmed := flags.Bool("yes", false, "confirm bounded pending-age expiry and terminal prune")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *directory == "" || !*confirmed || maintain == nil {
		return 2
	}
	result, err := maintain(*directory)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "relay delivery maintenance did not complete; rerun the exact command to recover safely")
		return 1
	}
	return writeJSON(stdout, stderr, map[string]any{"status": "deliveries_maintained", "directory": *directory, "expired": result.Expired, "pruned": result.Pruned, "continuation": result.Continuation})
}

type relayTerminalStore interface {
	SetRetentionPolicy(relay.RetentionConfig) error
	MaintainDeliveries(time.Time) (relay.MaintenanceResult, error)
	ListDeliveryTerminals(relay.TerminalListInput) (relay.TerminalListPage, error)
	Close() error
}

func listRelayTerminals(directory string, input relay.TerminalListInput) (relay.TerminalListPage, error) {
	store, err := openRelayTerminalStore(directory)
	if err != nil {
		return relay.TerminalListPage{}, err
	}
	defer func() { _ = store.Close() }()
	return store.ListDeliveryTerminals(input)
}

func maintainRelayDeliveries(directory string) (relay.MaintenanceResult, error) {
	policy, err := retentionPolicyFromEnvFile(operator.EnvFile(directory))
	if err != nil {
		return relay.MaintenanceResult{}, err
	}
	store, err := openRelayTerminalStore(directory)
	if err != nil {
		return relay.MaintenanceResult{}, err
	}
	defer func() { _ = store.Close() }()
	if err := store.SetRetentionPolicy(policy); err != nil {
		return relay.MaintenanceResult{}, err
	}
	return store.MaintainDeliveries(time.Now().UTC())
}

func openRelayTerminalStore(directory string) (relayTerminalStore, error) {
	installation, err := operator.Load(directory)
	if err != nil {
		return nil, err
	}
	storeName, _ := dotenvValue(operator.EnvFile(directory), "PUNARO_RELAY_STORE")
	if relayUsesPostgres(installation, storeName) {
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

func relayUsesPostgres(installation operator.Installation, store string) bool {
	if strings.EqualFold(strings.TrimSpace(store), "postgres") {
		return true
	}
	return installation.RelayEnabled || installation.MailCutover != nil
}

func retentionPolicyFromEnvFile(path string) (relay.RetentionConfig, error) {
	cfg := relay.DefaultRetentionConfig()
	values, err := readDotEnvMap(path)
	if err != nil {
		return relay.RetentionConfig{}, err
	}
	if raw, ok := values["PUNARO_RELAY_PENDING_MAX_AGE_SECONDS"]; ok {
		n, err := strconv.Atoi(raw)
		if err != nil || n < relay.RetentionAgeMinSeconds || n > relay.RetentionAgeMaxSeconds {
			return relay.RetentionConfig{}, fmt.Errorf("PUNARO_RELAY_PENDING_MAX_AGE_SECONDS must be an integer between %d and %d", relay.RetentionAgeMinSeconds, relay.RetentionAgeMaxSeconds)
		}
		cfg.PendingMaxAgeSeconds = n
	}
	if raw, ok := values["PUNARO_RELAY_TERMINAL_RETENTION_SECONDS"]; ok {
		n, err := strconv.Atoi(raw)
		if err != nil || n < relay.RetentionKeepMinSeconds || n > relay.RetentionKeepMaxSeconds {
			return relay.RetentionConfig{}, fmt.Errorf("PUNARO_RELAY_TERMINAL_RETENTION_SECONDS must be an integer between %d and %d", relay.RetentionKeepMinSeconds, relay.RetentionKeepMaxSeconds)
		}
		cfg.TerminalRetentionSeconds = n
	}
	if raw, ok := values["PUNARO_RELAY_DELIVERY_MAINTENANCE_BATCH"]; ok {
		n, err := strconv.Atoi(raw)
		if err != nil || n < relay.RetentionBatchMin || n > relay.RetentionBatchMax {
			return relay.RetentionConfig{}, fmt.Errorf("PUNARO_RELAY_DELIVERY_MAINTENANCE_BATCH must be an integer between %d and %d", relay.RetentionBatchMin, relay.RetentionBatchMax)
		}
		cfg.MaintenanceBatch = n
	}
	if err := cfg.Validate(); err != nil {
		return relay.RetentionConfig{}, err
	}
	return cfg, nil
}

func dotenvValue(path, key string) (string, error) {
	values, err := readDotEnvMap(path)
	if err != nil {
		return "", err
	}
	return values[key], nil
}

func readDotEnvMap(path string) (map[string]string, error) {
	file, err := os.Open(path) // #nosec G304 -- operator-chosen installation dotenv path.
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	values := map[string]string{}
	scanner := bufio.NewScanner(file)
	for line := 1; scanner.Scan(); line++ {
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		key, value, found := strings.Cut(raw, "=")
		key = strings.TrimSpace(strings.TrimPrefix(key, "export "))
		if !found || key == "" || strings.ContainsAny(key, " \t") {
			return nil, fmt.Errorf("parse dotenv file line %d", line)
		}
		values[key] = strings.Trim(strings.TrimSpace(value), "\"'")
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return values, nil
}
