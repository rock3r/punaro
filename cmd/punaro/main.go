// punaro is the supported host-local operator wrapper.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	punarobackup "github.com/rock3r/punaro/internal/backup"
	"github.com/rock3r/punaro/internal/ingress"
	"github.com/rock3r/punaro/internal/operator"
	punaropostgres "github.com/rock3r/punaro/internal/postgres"
)

var (
	inspectSchema = func(ctx context.Context, dsnFile string) (punaropostgres.SchemaState, error) {
		database, err := punaropostgres.OpenApplication(ctx, punaropostgres.Config{DSNFile: dsnFile})
		if err != nil {
			return punaropostgres.SchemaState{}, err
		}
		defer func() { _ = database.Close() }()
		return database.SchemaState(ctx)
	}
	inspectOwner = func(ctx context.Context, dsnFile string) (punaropostgres.Principal, error) {
		database, err := punaropostgres.OpenApplication(ctx, punaropostgres.Config{DSNFile: dsnFile})
		if err != nil {
			return punaropostgres.Principal{}, err
		}
		defer func() { _ = database.Close() }()
		return database.InstallationOwner(ctx)
	}
	maintenanceActive = func(ctx context.Context, dsnFile string) (bool, error) {
		database, err := punaropostgres.OpenApplication(ctx, punaropostgres.Config{DSNFile: dsnFile})
		if err != nil {
			return false, err
		}
		defer func() { _ = database.Close() }()
		return database.MaintenanceActive(ctx)
	}
	migratePristinePair = func(ctx context.Context, appDSNFile, ownerDSNFile string) (punaropostgres.SchemaState, error) {
		return punaropostgres.MigratePristinePair(ctx, punaropostgres.Config{DSNFile: appDSNFile}, punaropostgres.Config{DSNFile: ownerDSNFile})
	}
	createOwner = func(ctx context.Context, dsnFile, name string) (punaropostgres.Principal, error) {
		admin, err := punaropostgres.OpenAdministration(ctx, punaropostgres.Config{DSNFile: dsnFile})
		if err != nil {
			return punaropostgres.Principal{}, err
		}
		defer func() { _ = admin.Close() }()
		return admin.BootstrapOwner(ctx, name)
	}
	verifyInstallationPair = func(ctx context.Context, appDSNFile, ownerDSNFile string) error {
		app, err := punaropostgres.OpenApplication(ctx, punaropostgres.Config{DSNFile: appDSNFile})
		if err != nil {
			return err
		}
		defer func() { _ = app.Close() }()
		admin, err := punaropostgres.OpenAdministration(ctx, punaropostgres.Config{DSNFile: ownerDSNFile})
		if err != nil {
			return err
		}
		defer func() { _ = admin.Close() }()
		appState, err := app.InstallationState(ctx)
		if err != nil {
			return err
		}
		ownerState, err := admin.InstallationState(ctx)
		if err != nil {
			return err
		}
		if appState.InstallationID != ownerState.InstallationID || appState.TimelineID != ownerState.TimelineID {
			return errors.New("application and owner DSNs target different installations")
		}
		return nil
	}
	verifyPristinePair = func(ctx context.Context, appDSNFile, ownerDSNFile string) error {
		return punaropostgres.VerifyPristinePair(ctx, punaropostgres.Config{DSNFile: appDSNFile}, punaropostgres.Config{DSNFile: ownerDSNFile})
	}
	recoverInstallationOwner = func(ctx context.Context, installation operator.Installation) (punaropostgres.Principal, error) {
		state, err := inspectSchema(ctx, installation.AppDSNFile)
		if err != nil {
			return punaropostgres.Principal{}, err
		}
		if state.Classification == punaropostgres.Pristine {
			_, err = migratePristinePair(ctx, installation.AppDSNFile, installation.OwnerDSNFile)
			if err == nil {
				state, err = inspectSchema(ctx, installation.AppDSNFile)
			}
		}
		if err != nil || state.Classification != punaropostgres.Compatible {
			return punaropostgres.Principal{}, errors.New("database schema is not compatible")
		}
		if err := verifyInstallationPair(ctx, installation.AppDSNFile, installation.OwnerDSNFile); err != nil {
			return punaropostgres.Principal{}, err
		}
		admin, err := punaropostgres.OpenAdministration(ctx, punaropostgres.Config{DSNFile: installation.OwnerDSNFile})
		if err != nil {
			return punaropostgres.Principal{}, err
		}
		defer func() { _ = admin.Close() }()
		owner, err := admin.InstallationOwner(ctx)
		if errors.Is(err, punaropostgres.ErrNotFound) {
			return admin.BootstrapOwner(ctx, installation.OwnerName)
		}
		return owner, err
	}
	issueEnrollment = func(ctx context.Context, installation operator.Installation, request punaropostgres.EnrollmentRequest, previewHash string) (punaropostgres.PendingEnrollment, error) {
		admin, err := punaropostgres.OpenAdministration(ctx, punaropostgres.Config{DSNFile: installation.OwnerDSNFile})
		if err != nil {
			return punaropostgres.PendingEnrollment{}, err
		}
		defer func() { _ = admin.Close() }()
		return admin.CreateEnrollment(ctx, installation.OwnerPrincipalID, request, previewHash)
	}
	startServices = func(ctx context.Context, installation operator.Installation) error {
		command, err := composeUpCommand(ctx, installation)
		if err != nil {
			return err
		}
		output, err := command.CombinedOutput()
		if err != nil {
			return fmt.Errorf("service start failed: %s", boundedText(output))
		}
		return nil
	}
	probe                 = probeHTTP
	createOperatorBackup  = createBackup
	listOperatorBackups   = punarobackup.List
	verifyOperatorBackup  = punarobackup.Verify
	restoreOperatorBackup = restoreBackup
)

type restoreRequest struct {
	BackupDirectory string
	RecoveryReceipt string
	Directory       string
	DataDir         string
	BackupDir       string
	OwnerDSNFile    string
	AppDSNFile      string
}

func composeUpCommand(ctx context.Context, installation operator.Installation) (*exec.Cmd, error) {
	arguments, err := composeUpArgs(installation)
	if err != nil {
		return nil, err
	}
	command := exec.CommandContext(ctx, "docker", arguments...) // #nosec G204 -- fixed executable and generated private file arguments.
	command.Dir = installation.Directory
	command.Env = composeEnvironment(os.Environ(), installation.Directory)
	return command, nil
}

func composeUpArgs(installation operator.Installation) ([]string, error) {
	projectName, err := operator.ComposeProjectName(installation)
	if err != nil {
		return nil, err
	}
	return []string{"compose", "--project-name", projectName, "--env-file", operator.EnvFile(installation.Directory), "-f", operator.OverrideFile(installation.Directory), "up", "-d"}, nil
}

func composeEnvironment(environment []string, directory string) []string {
	sanitized := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		name, _, found := strings.Cut(entry, "=")
		canonicalName := strings.ToUpper(name)
		if !found || canonicalName == "PWD" || strings.HasPrefix(canonicalName, "PUNARO_") || strings.HasPrefix(canonicalName, "COMPOSE_") {
			continue
		}
		sanitized = append(sanitized, entry)
	}
	return append(sanitized, "PWD="+directory)
}

func pgDumpSnapshot(ctx context.Context, dsnFile, snapshotID, destination string) error {
	if snapshotID == "" || !filepath.IsAbs(destination) {
		return errors.New("database dump inputs are invalid")
	}
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- explicit private backup staging path.
	if err != nil {
		return errors.New("database dump destination cannot be reserved")
	}
	succeeded := false
	defer func() {
		_ = output.Close()
		if !succeeded {
			_ = os.Remove(destination)
		}
	}()
	if err := runPostgresToolIO(ctx, "pg_dump", dsnFile, nil, output, func(connection string) []string {
		return []string{"--no-password", "--dbname", connection, "--snapshot", snapshotID, "--format=custom", "--no-owner", "--exclude-table-data=jobs.backup_gc_fences"}
	}); err != nil {
		return err
	}
	if err := output.Sync(); err != nil {
		return errors.New("database dump could not be made durable")
	}
	if err := output.Close(); err != nil {
		return errors.New("database dump could not be closed")
	}
	succeeded = true
	return nil
}

func pgRestoreDump(ctx context.Context, dsnFile string, dump io.Reader) error {
	if dump == nil {
		return errors.New("database restore input is invalid")
	}
	return runPostgresToolInput(ctx, "pg_restore", dsnFile, dump, func(connection string) []string {
		return []string{"--no-password", "--dbname", connection, "--exit-on-error", "--single-transaction", "--no-owner"}
	})
}

func runPostgresTool(ctx context.Context, executable, dsnFile string, arguments func(string) []string) error {
	return runPostgresToolInput(ctx, executable, dsnFile, nil, arguments)
}

func runPostgresToolInput(ctx context.Context, executable, dsnFile string, input io.Reader, arguments func(string) []string) error {
	return runPostgresToolIO(ctx, executable, dsnFile, input, nil, arguments)
}

func runPostgresToolIO(ctx context.Context, executable, dsnFile string, input io.Reader, output io.Writer, arguments func(string) []string) error {
	dsn, err := punaropostgres.ReadDSNFile(dsnFile)
	if err != nil {
		return err
	}
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.User == nil || parsed.User.Username() == "" || parsed.Host == "" || parsed.Path == "" || parsed.Fragment != "" || strings.Contains(parsed.Host, ",") || strings.Contains(parsed.Hostname(), "/") {
		return errors.New("PostgreSQL tool requires a canonical single-host TCP URI DSN")
	}
	password, _ := parsed.User.Password()
	username := parsed.User.Username()
	for _, field := range []string{parsed.Hostname(), username, strings.TrimPrefix(parsed.EscapedPath(), "/"), password} {
		if strings.ContainsAny(field, "\r\n") {
			return errors.New("PostgreSQL tool credential is invalid")
		}
	}
	port := parsed.Port()
	if port == "" {
		port = "5432"
	}
	if parsedPort, parseErr := strconv.ParseUint(port, 10, 16); parseErr != nil || parsedPort == 0 {
		return errors.New("PostgreSQL tool port is invalid")
	}
	database, err := url.PathUnescape(strings.TrimPrefix(parsed.EscapedPath(), "/"))
	if err != nil || database == "" || strings.ContainsAny(database, "\r\n") {
		return errors.New("PostgreSQL tool database is invalid")
	}
	sanitized := *parsed
	sanitized.User = url.User(username)
	sanitizedQuery := sanitized.Query()
	for key := range sanitizedQuery {
		if strings.EqualFold(key, "password") || strings.EqualFold(key, "sslpassword") {
			return errors.New("PostgreSQL tool URI must not contain password query parameters")
		}
		if strings.EqualFold(key, "host") || strings.EqualFold(key, "hostaddr") {
			return errors.New("PostgreSQL tool URI host overrides are unsupported")
		}
		if strings.EqualFold(key, "passfile") || strings.EqualFold(key, "service") || strings.EqualFold(key, "servicefile") {
			sanitizedQuery.Del(key)
		}
	}
	sanitized.RawQuery = sanitizedQuery.Encode()
	temporary, err := os.MkdirTemp("", "punaro-postgres-tool-")
	if err != nil {
		return errors.New("PostgreSQL tool credential staging failed")
	}
	defer func() { _ = os.RemoveAll(temporary) }()
	passFile := filepath.Join(temporary, "pgpass")
	passEntry := strings.Join([]string{escapePGPass(parsed.Hostname()), port, escapePGPass(database), escapePGPass(username), escapePGPass(password)}, ":") + "\n"
	if err := os.WriteFile(passFile, []byte(passEntry), 0o600); err != nil { // #nosec G306 -- pgpass requires exactly owner-only access.
		return errors.New("PostgreSQL tool credential staging failed")
	}
	command := exec.CommandContext(ctx, executable, arguments(sanitized.String())...) // #nosec G204 -- fixed audited executable and structured arguments.
	command.Dir = filepath.Dir(dsnFile)
	command.Env = postgresToolEnvironment(os.Environ(), passFile)
	command.Stdin = input
	command.Stdout = output
	if command.Stdout == nil {
		command.Stdout = io.Discard
	}
	command.Stderr = io.Discard
	err = command.Run()
	if err != nil {
		return errors.New("PostgreSQL tool failed; verify the client version and database connectivity")
	}
	return nil
}

func postgresToolEnvironment(environment []string, passFile string) []string {
	sanitized := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		name, _, found := strings.Cut(entry, "=")
		if !found || strings.HasPrefix(strings.ToUpper(name), "PG") {
			continue
		}
		sanitized = append(sanitized, entry)
	}
	return append(sanitized, "PGPASSFILE="+passFile)
}

func escapePGPass(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	return strings.ReplaceAll(value, ":", "\\:")
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "usage: punaro init|up|status|doctor|client|backup|restore|update")
		return 2
	}
	switch args[0] {
	case "init":
		return runInit(args[1:], stdout, stderr)
	case "up":
		return runUp(args[1:], stdout, stderr)
	case "status":
		return runStatus(args[1:], stdout, stderr, false)
	case "doctor":
		return runStatus(args[1:], stdout, stderr, true)
	case "client":
		if len(args) > 1 && args[1] == "add" {
			return runClientAdd(args[2:], stdout, stderr)
		}
	case "backup":
		return runBackup(args[1:], stdout, stderr)
	case "restore":
		return runRestore(args[1:], stdout, stderr)
	case "update":
		return runUpdate(args[1:], stdout, stderr)
	}
	_, _ = fmt.Fprintln(stderr, "unsupported operator command")
	return 2
}

func runInit(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "new absolute installation directory")
	dataDir := flags.String("data-dir", "", "existing private data directory")
	backupDir := flags.String("backup-dir", "", "existing private backup directory")
	image := flags.String("image", "", "release image reference pinned by sha256 digest")
	ownerDSN := flags.String("owner-dsn-file", "", "protected schema-owner DSN file")
	appDSN := flags.String("app-dsn-file", "", "protected application DSN file")
	ownerName := flags.String("owner-name", "", "first operator display name")
	mode := flags.String("mode", "", "lan, proxy, or internet")
	listen := flags.String("listen-addr", "127.0.0.1:8080", "concrete listen IP and port")
	publicURL := flags.String("public-url", "", "canonical HTTPS public URL")
	trustedLAN := flags.String("trusted-lan-cidr", "", "private or link-local trusted LAN")
	allowLANHTTP := flags.Bool("allow-lan-http", false, "explicitly allow plaintext credentials from the trusted LAN")
	healthListen := flags.String("health-listen-addr", "127.0.0.1:8081", "distinct loopback-only health listener")
	resume := flags.Bool("resume", false, "resume a durably staged initialization")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *directory == "" {
		return 2
	}
	if *resume {
		installation, err := operator.Resume(context.Background(), *directory, recoverInstallationOwner)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "punaro init recovery failed: %v\n", err)
			return 1
		}
		return writeJSON(stdout, stderr, map[string]any{"status": "initialized", "owner_principal_id": installation.OwnerPrincipalID, "directory": *directory})
	}
	if *dataDir == "" || *backupDir == "" || *image == "" || *ownerDSN == "" || *appDSN == "" || *ownerName == "" || *mode == "" {
		return 2
	}
	bootstrap := func(ctx context.Context, ownerFile, name string) (punaropostgres.Principal, error) {
		state, err := inspectSchema(ctx, *appDSN)
		if err != nil || state.Classification != punaropostgres.Pristine {
			return punaropostgres.Principal{}, operator.ErrBootstrapNotAttempted
		}
		if _, err = migratePristinePair(ctx, *appDSN, ownerFile); err != nil {
			if errors.Is(err, punaropostgres.ErrMigrationNotAttempted) {
				return punaropostgres.Principal{}, operator.ErrBootstrapNotAttempted
			}
			return punaropostgres.Principal{}, err
		}
		state, err = inspectSchema(ctx, *appDSN)
		if err != nil || state.Classification != punaropostgres.Compatible {
			return punaropostgres.Principal{}, errors.New("database schema is not compatible")
		}
		if err := verifyInstallationPair(ctx, *appDSN, ownerFile); err != nil {
			return punaropostgres.Principal{}, err
		}
		return createOwner(ctx, ownerFile, name)
	}
	installation, err := operator.Init(context.Background(), operator.InitOptions{Directory: *directory, DataDir: *dataDir, BackupDir: *backupDir, Image: *image, OwnerDSNFile: *ownerDSN, AppDSNFile: *appDSN, OwnerName: *ownerName, Ingress: ingress.Policy{Mode: ingress.Mode(*mode), ListenAddr: *listen, PublicURL: *publicURL, TrustedLAN: *trustedLAN, AllowPlaintext: *allowLANHTTP}, HealthListenAddr: *healthListen}, bootstrap)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "punaro init failed: %v\n", err)
		return 1
	}
	if installation.Ingress.Mode == ingress.LAN {
		_, _ = fmt.Fprintln(stderr, "WARNING: trusted-LAN HTTP sends enrollment and device credentials without TLS; use only on the validated private/link-local network")
	}
	return writeJSON(stdout, stderr, map[string]any{"status": "initialized", "owner_principal_id": installation.OwnerPrincipalID, "directory": *directory})
}

func runUp(args []string, stdout, stderr io.Writer) int {
	directory, ok := parseDirectory("up", args, stderr)
	if !ok {
		return 2
	}
	installation, err := operator.Load(directory)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "punaro up refused: %v\n", err)
		return 1
	}
	if failures := operator.CheckPaths(installation); len(failures) != 0 {
		_, _ = fmt.Fprintf(stderr, "punaro up refused: %s; run punaro doctor\n", strings.Join(failures, ", "))
		return 1
	}
	state, err := inspectSchema(context.Background(), installation.AppDSNFile)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "punaro up refused: database schema state is unavailable")
		return 1
	}
	switch operator.DecideUp(state) {
	case operator.StartCompatible:
	case operator.RefuseUpgradeRequired:
		_, _ = fmt.Fprintln(stderr, "punaro up refused: existing schema requires migration, but this staged release has no in-place updater; continue the previous compatible release")
		return 1
	default:
		_, _ = fmt.Fprintf(stderr, "punaro up refused: schema is %s; follow the documented recovery procedure\n", state.Classification)
		return 1
	}
	active, err := maintenanceActive(context.Background(), installation.AppDSNFile)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "punaro up refused: maintenance state is unavailable")
		return 1
	}
	if active {
		_, _ = fmt.Fprintln(stderr, "punaro up refused: an update transaction owns the maintenance fence; resume with punaro update")
		return 1
	}
	if err := verifyInstallationPair(context.Background(), installation.AppDSNFile, installation.OwnerDSNFile); err != nil {
		_, _ = fmt.Fprintln(stderr, "punaro up refused: database roles do not target the same installation; follow recovery")
		return 1
	}
	owner, err := inspectOwner(context.Background(), installation.AppDSNFile)
	if err != nil || owner.ID != installation.OwnerPrincipalID {
		_, _ = fmt.Fprintln(stderr, "punaro up refused: database owner does not match the installation configuration; follow recovery")
		return 1
	}
	if err := startServices(context.Background(), installation); err != nil {
		_, _ = fmt.Fprintln(stderr, "punaro up failed: services could not be started")
		return 1
	}
	readyURL := strings.TrimRight(installation.HealthURL, "/") + "/readyz"
	deadline := time.Now().Add(30 * time.Second)
	for {
		if err := probe(context.Background(), readyURL); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_, _ = fmt.Fprintln(stderr, "punaro up failed: readiness deadline exceeded; run punaro doctor")
			return 1
		}
		time.Sleep(500 * time.Millisecond)
	}
	result := diagnose(context.Background(), installation)
	if !result.Healthy {
		_ = writeJSON(stdout, stderr, result)
		return 1
	}
	return writeJSON(stdout, stderr, result)
}

type statusResult struct {
	Healthy      bool                          `json:"healthy"`
	Reachable    bool                          `json:"reachable"`
	Ready        bool                          `json:"ready"`
	Schema       punaropostgres.Classification `json:"schema"`
	Core         []string                      `json:"core_capabilities"`
	Optional     []string                      `json:"optional_capabilities"`
	FailedChecks []string                      `json:"failed_checks,omitempty"`
}

func runStatus(args []string, stdout, stderr io.Writer, doctor bool) int {
	name := "status"
	if doctor {
		name = "doctor"
	}
	directory, ok := parseDirectory(name, args, stderr)
	if !ok {
		return 2
	}
	installation, err := operator.Load(directory)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "punaro %s failed: %v\n", name, err)
		return 1
	}
	result := diagnose(context.Background(), installation)
	if code := writeJSON(stdout, stderr, result); code != 0 {
		return code
	}
	if doctor && !result.Healthy {
		return 1
	}
	return 0
}

func diagnose(ctx context.Context, installation operator.Installation) statusResult {
	result := statusResult{Core: []string{"postgresql", "device-enrollment", "device-authentication"}, Optional: []string{}}
	result.FailedChecks = append(result.FailedChecks, operator.CheckPaths(installation)...)
	state, err := inspectSchema(ctx, installation.AppDSNFile)
	if err != nil {
		result.FailedChecks = append(result.FailedChecks, "database unavailable")
	} else {
		result.Schema = state.Classification
		if state.Classification != punaropostgres.Compatible {
			result.FailedChecks = append(result.FailedChecks, "schema not compatible")
		} else if err := verifyInstallationPair(ctx, installation.AppDSNFile, installation.OwnerDSNFile); err != nil {
			result.FailedChecks = append(result.FailedChecks, "database roles target different installations")
		}
	}
	owner, ownerErr := inspectOwner(ctx, installation.AppDSNFile)
	if ownerErr != nil || owner.ID != installation.OwnerPrincipalID {
		result.FailedChecks = append(result.FailedChecks, "database owner does not match installation configuration")
	}
	base := strings.TrimRight(installation.HealthURL, "/")
	if err := probe(ctx, base+"/healthz"); err == nil {
		result.Reachable = true
	} else {
		result.FailedChecks = append(result.FailedChecks, "daemon unreachable")
	}
	if err := probe(ctx, base+"/readyz"); err == nil {
		result.Ready = true
	} else {
		result.FailedChecks = append(result.FailedChecks, "daemon not ready")
	}
	result.Healthy = len(result.FailedChecks) == 0
	return result
}

type stringList []string

func (s *stringList) String() string { return fmt.Sprint([]string(*s)) }
func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func runClientAdd(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("client add", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "absolute installation directory")
	name := flags.String("name", "", "client display name")
	allProjects := flags.Bool("all-projects", false, "grant current and future project access")
	confirmed := flags.Bool("yes", false, "confirm the exact printed grants")
	confirmedHash := flags.String("confirm-preview-hash", "", "exact preview hash printed by the prior preview-only run")
	ttl := flags.Duration("ttl", 10*time.Minute, "single-use code lifetime")
	credentialTTL := flags.Duration("credential-ttl", 0, "optional credential lifetime")
	var projects stringList
	flags.Var(&projects, "project", "selected opaque project UUID (repeatable)")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *directory == "" || *name == "" {
		return 2
	}
	installation, err := operator.Load(*directory)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "client enrollment refused: installation configuration is unavailable")
		return 1
	}
	grants, previewHash, err := punaropostgres.PreviewTrustedAgentEnrollment(projects, *allProjects)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "client enrollment refused: grants are invalid")
		return 1
	}
	preview := map[string]any{"template": "trusted-agent", "preview_hash": previewHash, "grants": grants}
	if !*confirmed {
		if code := writeJSON(stdout, stderr, preview); code != 0 {
			return code
		}
		_, _ = fmt.Fprintln(stderr, "grant preview printed; rerun with --yes and --confirm-preview-hash to create the enrollment")
		return 3
	}
	if *confirmedHash == "" || *confirmedHash != previewHash {
		if code := writeJSON(stdout, stderr, preview); code != 0 {
			return code
		}
		_, _ = fmt.Fprintln(stderr, "client enrollment refused: confirmed preview hash does not match the exact grants above")
		return 3
	}
	if failures := operator.CheckPaths(installation); len(failures) != 0 {
		_, _ = fmt.Fprintln(stderr, "client enrollment refused: installation safety checks failed; run punaro doctor")
		return 1
	}
	state, err := inspectSchema(context.Background(), installation.AppDSNFile)
	if err != nil || state.Classification != punaropostgres.Compatible {
		_, _ = fmt.Fprintln(stderr, "client enrollment refused: database schema is not compatible")
		return 1
	}
	if err := verifyInstallationPair(context.Background(), installation.AppDSNFile, installation.OwnerDSNFile); err != nil {
		_, _ = fmt.Fprintln(stderr, "client enrollment refused: database roles do not target the same installation")
		return 1
	}
	owner, err := inspectOwner(context.Background(), installation.AppDSNFile)
	if err != nil || owner.ID != installation.OwnerPrincipalID {
		_, _ = fmt.Fprintln(stderr, "client enrollment refused: database owner does not match the installation configuration")
		return 1
	}
	pending, err := issueEnrollment(context.Background(), installation, punaropostgres.EnrollmentRequest{ClientBinding: uuid.NewString(), Label: *name, ProjectIDs: projects, AllProjects: *allProjects, TTL: *ttl, CredentialTTL: *credentialTTL}, previewHash)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "client enrollment failed")
		return 1
	}
	return writeJSON(stdout, stderr, pending)
}

func runBackup(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "list" {
		directory, ok := parseDirectory("backup list", args[1:], stderr)
		if !ok {
			return 2
		}
		installation, err := operator.Load(directory)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "backup list failed: installation configuration is unavailable")
			return 1
		}
		backups, err := listOperatorBackups(installation.BackupDir)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "backup list failed: backup directory is unavailable")
			return 1
		}
		return writeJSON(stdout, stderr, backups)
	}
	if len(args) > 0 && args[0] == "verify" {
		flags := flag.NewFlagSet("backup verify", flag.ContinueOnError)
		flags.SetOutput(stderr)
		path := flags.String("backup", "", "absolute published backup directory")
		if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *path == "" || !filepath.IsAbs(*path) || filepath.Clean(*path) != *path {
			return 2
		}
		manifest, err := verifyOperatorBackup(*path)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "backup verification failed")
			return 1
		}
		return writeJSON(stdout, stderr, manifest)
	}
	directory, ok := parseDirectory("backup", args, stderr)
	if !ok {
		return 2
	}
	installation, err := operator.Load(directory)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "backup failed: installation configuration is unavailable")
		return 1
	}
	manifest, path, err := createOperatorBackup(context.Background(), installation)
	if err != nil {
		var operationErr *punarobackup.OperationError
		if errors.As(err, &operationErr) && operationErr.Phase == punarobackup.PhaseDataPublished && operationErr.PublishedPath != "" {
			_, _ = fmt.Fprintf(stderr, "backup published at %s, but parent-directory durability is uncertain; verify it before use\n", operationErr.PublishedPath)
			return 1
		}
		_, _ = fmt.Fprintln(stderr, "backup failed; no complete backup was published")
		return 1
	}
	return writeJSON(stdout, stderr, map[string]any{"status": "verified", "directory": path, "manifest": manifest})
}

func runRestore(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("restore", flag.ContinueOnError)
	flags.SetOutput(stderr)
	backupDirectory := flags.String("backup", "", "absolute verified backup directory")
	directory := flags.String("into-new-stack", "", "new absolute installation directory")
	dataDir := flags.String("data-dir", "", "new absolute daemon data directory")
	backupDir := flags.String("backup-dir", "", "existing private backup root for the restored stack")
	ownerDSN := flags.String("owner-dsn-file", "", "protected target schema-owner DSN file")
	appDSN := flags.String("app-dsn-file", "", "protected target application DSN file")
	updateReceipt := flags.String("update-receipt", "", "protected host receipt for an update recovery backup")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *backupDirectory == "" || *directory == "" || *dataDir == "" || *backupDir == "" || *ownerDSN == "" || *appDSN == "" {
		return 2
	}
	for _, path := range []string{*backupDirectory, *directory, *dataDir, *backupDir, *ownerDSN, *appDSN} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return 2
		}
	}
	if *updateReceipt != "" && (!filepath.IsAbs(*updateReceipt) || filepath.Clean(*updateReceipt) != *updateReceipt) {
		return 2
	}
	state, err := restoreOperatorBackup(context.Background(), restoreRequest{BackupDirectory: *backupDirectory, RecoveryReceipt: *updateReceipt, Directory: *directory, DataDir: *dataDir, BackupDir: *backupDir, OwnerDSNFile: *ownerDSN, AppDSNFile: *appDSN})
	if err != nil {
		var operationErr *punarobackup.OperationError
		if errors.As(err, &operationErr) && operationErr.Phase != punarobackup.PhasePreflight {
			_, _ = fmt.Fprintln(stderr, "restore is incomplete; retry the exact same restore command to resume its durable journal")
		} else {
			_, _ = fmt.Fprintln(stderr, "restore refused before database mutation")
		}
		return 1
	}
	return writeJSON(stdout, stderr, map[string]any{"status": "restored", "directory": *directory, "state": state, "external_dependencies_required": []string{"host-tls", "oauth", "reverse-proxy", "telegram", "tunnel"}})
}

func createBackup(ctx context.Context, installation operator.Installation) (punarobackup.Manifest, string, error) {
	manifest, path, _, err := createBackupWithUpdate(ctx, installation, nil)
	return manifest, path, err
}

func createUpdateBackup(ctx context.Context, installation operator.Installation, transaction punaropostgres.UpdateTransaction) (punarobackup.Manifest, string, punaropostgres.UpdateBackupMarker, error) {
	return createBackupWithUpdate(ctx, installation, &transaction)
}

func createBackupWithUpdate(ctx context.Context, installation operator.Installation, transaction *punaropostgres.UpdateTransaction) (punarobackup.Manifest, string, punaropostgres.UpdateBackupMarker, error) {
	if failures := operator.CheckPaths(installation); len(failures) != 0 {
		return punarobackup.Manifest{}, "", punaropostgres.UpdateBackupMarker{}, errors.New("installation safety checks failed")
	}
	state, err := inspectSchema(ctx, installation.AppDSNFile)
	bridgeBackup := transaction != nil && transaction.Phase == punaropostgres.UpdateWritersStopped && state.Classification == punaropostgres.UpgradeRequired && state.Version == transaction.SourceSchema
	if err != nil || (state.Classification != punaropostgres.Compatible && !bridgeBackup) {
		return punarobackup.Manifest{}, "", punaropostgres.UpdateBackupMarker{}, errors.New("database schema is not compatible")
	}
	if err := verifyInstallationPair(ctx, installation.AppDSNFile, installation.OwnerDSNFile); err != nil {
		return punarobackup.Manifest{}, "", punaropostgres.UpdateBackupMarker{}, err
	}
	owner, err := inspectOwner(ctx, installation.AppDSNFile)
	if err != nil || owner.ID != installation.OwnerPrincipalID {
		return punarobackup.Manifest{}, "", punaropostgres.UpdateBackupMarker{}, errors.New("installation owner does not match configuration")
	}
	database, err := punaropostgres.OpenApplication(ctx, punaropostgres.Config{DSNFile: installation.AppDSNFile})
	if err != nil {
		return punarobackup.Manifest{}, "", punaropostgres.UpdateBackupMarker{}, err
	}
	defer func() { _ = database.Close() }()
	var source *punaropostgres.BackupSource
	if transaction == nil {
		source, err = punaropostgres.NewBackupSource(database, installation.OwnerDSNFile, pgDumpSnapshot)
	} else {
		source, err = punaropostgres.NewUpdateBackupSource(database, installation.OwnerDSNFile, transaction.UpdateID, pgDumpSnapshot)
	}
	if err != nil {
		return punarobackup.Manifest{}, "", punaropostgres.UpdateBackupMarker{}, err
	}
	options := punarobackup.CreateOptions{
		BackupRoot:       installation.BackupDir,
		BlobRoot:         filepath.Join(installation.DataDir, "blobs"),
		InstallationFile: operator.ConfigFile(installation.Directory),
		EnvironmentFile:  operator.EnvFile(installation.Directory),
		ComposeFile:      operator.OverrideFile(installation.Directory),
		OwnerDSNFile:     installation.OwnerDSNFile,
		AppDSNFile:       installation.AppDSNFile,
	}
	if transaction != nil {
		_, digest, found := strings.Cut(transaction.TargetImage, "@")
		if !found {
			return punarobackup.Manifest{}, "", punaropostgres.UpdateBackupMarker{}, errors.New("update target image is invalid")
		}
		options.Update = &punarobackup.UpdateTarget{UpdateID: transaction.UpdateID, TargetRelease: transaction.TargetRelease, TargetImageDigest: digest}
	}
	manifest, path, err := punarobackup.Create(ctx, options, source)
	if err != nil || transaction == nil {
		return manifest, path, punaropostgres.UpdateBackupMarker{}, err
	}
	binding, err := punarobackup.BuildUpdateBinding(path)
	if err != nil {
		return punarobackup.Manifest{}, "", punaropostgres.UpdateBackupMarker{}, err
	}
	if _, err := punarobackup.VerifyForUpdate(path, binding); err != nil {
		return punarobackup.Manifest{}, "", punaropostgres.UpdateBackupMarker{}, err
	}
	return manifest, path, punaropostgres.UpdateBackupMarker{
		UpdateID: binding.UpdateID, BackupID: manifest.BackupID, InstallationID: binding.InstallationID,
		TimelineID: binding.TimelineID, ChangeSequence: binding.ChangeSequence, SourceSchema: binding.SourceSchema,
		TargetRelease: binding.TargetRelease, TargetImageDigest: binding.TargetImageDigest,
		ExportedSnapshotID: binding.ExportedSnapshotID, ManifestSHA256: binding.ManifestSHA256,
	}, nil
}

func restoreBackup(ctx context.Context, request restoreRequest) (punarobackup.State, error) {
	manifest, err := punarobackup.Verify(request.BackupDirectory)
	if err != nil {
		return punarobackup.State{}, err
	}
	var updateMarker *punaropostgres.UpdateBackupMarker
	receiptDigest := ""
	if manifest.Update != nil {
		if request.RecoveryReceipt == "" {
			return punarobackup.State{}, errors.New("update recovery requires an independent host receipt")
		}
		receipt, digest, receiptErr := operator.LoadUpdateRecoveryReceipt(request.RecoveryReceipt)
		if receiptErr != nil {
			return punarobackup.State{}, errors.New("update recovery receipt is unavailable or invalid")
		}
		binding, bindingErr := punarobackup.BuildUpdateBinding(request.BackupDirectory)
		if bindingErr != nil {
			return punarobackup.State{}, errors.New("update recovery binding is unavailable")
		}
		if _, verifyErr := punarobackup.VerifyForUpdate(request.BackupDirectory, binding); verifyErr != nil {
			return punarobackup.State{}, errors.New("update recovery binding is invalid")
		}
		canonicalBackup, canonicalErr := filepath.EvalSymlinks(request.BackupDirectory)
		if canonicalErr != nil || receipt.BackupDirectory != canonicalBackup || receipt.BackupID != manifest.BackupID || !receiptMatchesBinding(receipt, binding) {
			return punarobackup.State{}, errors.New("update recovery receipt does not match the verified backup")
		}
		receiptDigest = digest
		updateMarker = &punaropostgres.UpdateBackupMarker{
			UpdateID: binding.UpdateID, BackupID: manifest.BackupID, InstallationID: binding.InstallationID,
			TimelineID: binding.TimelineID, ChangeSequence: binding.ChangeSequence, SourceSchema: binding.SourceSchema,
			TargetRelease: binding.TargetRelease, TargetImageDigest: binding.TargetImageDigest,
			ExportedSnapshotID: binding.ExportedSnapshotID, ManifestSHA256: binding.ManifestSHA256,
		}
	} else if request.RecoveryReceipt != "" {
		return punarobackup.State{}, errors.New("ordinary restore does not accept an update recovery receipt")
	}
	if manifest.SchemaVersion != punaropostgres.CurrentManifest().MaxSupported && (updateMarker == nil || manifest.SchemaVersion != updateMarker.SourceSchema) {
		return punarobackup.State{}, errors.New("backup schema version is not exactly supported by this restore binary")
	}
	canonicalSource, err := filepath.EvalSymlinks(request.BackupDirectory)
	if err != nil {
		return punarobackup.State{}, errors.New("backup source path cannot be resolved")
	}
	canonicalNewBackup, err := filepath.EvalSymlinks(request.BackupDir)
	if err != nil || cliPathsOverlap(canonicalSource, canonicalNewBackup) {
		return punarobackup.State{}, errors.New("source and restored backup roots must be separate")
	}
	for _, planned := range []string{request.Directory, request.DataDir} {
		canonicalParent, parentErr := filepath.EvalSymlinks(filepath.Dir(planned))
		if parentErr != nil || cliPathsOverlap(canonicalSource, filepath.Join(canonicalParent, filepath.Base(planned))) {
			return punarobackup.State{}, errors.New("restore source and target paths must not overlap")
		}
	}
	installationBody, err := punarobackup.ReadVerifiedFile(request.BackupDirectory, manifest, "config/installation.json", 64<<10)
	if err != nil {
		return punarobackup.State{}, errors.New("backup installation configuration changed after verification")
	}
	sourceInstallation, err := operator.ParseInstallationArtifact(installationBody)
	if err != nil || sourceInstallation.OwnerPrincipalID == "" {
		return punarobackup.State{}, errors.New("backup installation configuration is invalid")
	}
	prepared, err := operator.PrepareRestore(operator.RestoreOptions{Source: sourceInstallation, Directory: request.Directory, DataDir: request.DataDir, BackupDir: request.BackupDir, OwnerDSNFile: request.OwnerDSNFile, AppDSNFile: request.AppDSNFile})
	if err != nil {
		return punarobackup.State{}, err
	}
	targetIdentity, err := postgresDatabaseIdentity(ctx, request.AppDSNFile)
	if err != nil {
		return punarobackup.State{}, err
	}
	ownerTargetIdentity, err := postgresOwnerDatabaseIdentity(ctx, request.OwnerDSNFile)
	if err != nil || ownerTargetIdentity != targetIdentity {
		return punarobackup.State{}, errors.New("restore database credentials do not identify the same target database")
	}
	releaseDatabaseLock, err := punaropostgres.AcquireRestoreLock(ctx, punaropostgres.Config{DSNFile: request.AppDSNFile}, targetIdentity)
	if err != nil {
		return punarobackup.State{}, err
	}
	defer releaseDatabaseLock()
	canonicalInstallationParent, err := filepath.EvalSymlinks(filepath.Dir(request.Directory))
	if err != nil {
		return punarobackup.State{}, errors.New("restore installation parent cannot be resolved")
	}
	canonicalOwnerDSN, ownerErr := filepath.EvalSymlinks(request.OwnerDSNFile)
	canonicalAppDSN, appErr := filepath.EvalSymlinks(request.AppDSNFile)
	if ownerErr != nil || appErr != nil {
		return punarobackup.State{}, errors.New("restore database credential paths cannot be resolved")
	}
	target := punarobackup.RestoreTarget{
		InstallationDirectory: filepath.Join(canonicalInstallationParent, filepath.Base(request.Directory)),
		BackupRoot:            canonicalNewBackup,
		OwnerDSNFile:          canonicalOwnerDSN,
		AppDSNFile:            canonicalAppDSN,
		DatabaseIdentity:      targetIdentity,
	}
	if updateMarker != nil {
		target.UpdateID = updateMarker.UpdateID
		target.ManifestSHA256 = updateMarker.ManifestSHA256
		target.RecoveryReceiptFile = request.RecoveryReceipt
		target.RecoveryReceiptSHA256 = receiptDigest
	}
	finalizationStage := ""
	state, err := punarobackup.Restore(ctx, punarobackup.RestoreOptions{
		BackupDirectory: request.BackupDirectory,
		TargetDataDir:   request.DataDir,
		Target:          target,
		Preflight: func(preflightCtx context.Context) error {
			currentIdentity, identityErr := postgresDatabaseIdentity(preflightCtx, request.AppDSNFile)
			currentOwnerIdentity, ownerIdentityErr := postgresOwnerDatabaseIdentity(preflightCtx, request.OwnerDSNFile)
			if identityErr != nil || ownerIdentityErr != nil || currentIdentity != targetIdentity || currentOwnerIdentity != targetIdentity {
				return &punarobackup.OperationError{Phase: punarobackup.PhasePreflight, Err: errors.New("restore target database identity changed")}
			}
			targetState, inspectErr := inspectSchema(preflightCtx, request.AppDSNFile)
			if inspectErr != nil || targetState.Classification != punaropostgres.Pristine {
				return &punarobackup.OperationError{Phase: punarobackup.PhasePreflight, Err: errors.New("restore target database must be pristine")}
			}
			if err := verifyPristinePair(preflightCtx, request.AppDSNFile, request.OwnerDSNFile); err != nil {
				return &punarobackup.OperationError{Phase: punarobackup.PhasePreflight, Err: err}
			}
			return nil
		},
		RestoreDump: func(restoreCtx context.Context, dump io.Reader) error {
			currentIdentity, identityErr := postgresDatabaseIdentity(restoreCtx, request.AppDSNFile)
			currentOwnerIdentity, ownerIdentityErr := postgresOwnerDatabaseIdentity(restoreCtx, request.OwnerDSNFile)
			if identityErr != nil || ownerIdentityErr != nil || currentIdentity != targetIdentity || currentOwnerIdentity != targetIdentity {
				return &punarobackup.OperationError{Phase: punarobackup.PhasePreflight, Err: errors.New("restore target database identity changed")}
			}
			targetState, inspectErr := inspectSchema(restoreCtx, request.AppDSNFile)
			if inspectErr != nil {
				return inspectErr
			}
			switch targetState.Classification {
			case punaropostgres.Pristine:
				if err := verifyPristinePair(restoreCtx, request.AppDSNFile, request.OwnerDSNFile); err != nil {
					return err
				}
				return pgRestoreDump(restoreCtx, request.OwnerDSNFile, dump)
			case punaropostgres.Compatible, punaropostgres.UpgradeRequired:
				if targetState.Classification == punaropostgres.UpgradeRequired && (updateMarker == nil || targetState.Version != updateMarker.SourceSchema) {
					break
				}
				database, openErr := punaropostgres.OpenApplication(restoreCtx, punaropostgres.Config{DSNFile: request.AppDSNFile})
				if openErr != nil {
					return openErr
				}
				defer func() { _ = database.Close() }()
				current, currentErr := database.InstallationState(restoreCtx)
				if currentErr == nil && targetState.Version == manifest.SchemaVersion && current.InstallationID == manifest.State.InstallationID && current.TimelineID == manifest.State.TimelineID && current.ChangeSequence == manifest.State.ChangeSequence {
					return nil
				}
			}
			return errors.New("restore target database is neither pristine nor the exact restored backup state")
		},
		RotateTimeline: func(rotateCtx context.Context, verified punarobackup.Manifest) (punarobackup.State, error) {
			admin, openErr := punaropostgres.OpenAdministration(rotateCtx, punaropostgres.Config{DSNFile: request.OwnerDSNFile})
			if openErr != nil {
				return punarobackup.State{}, openErr
			}
			defer func() { _ = admin.Close() }()
			if updateMarker != nil {
				rotated, _, rotateErr := admin.RestoreUpdateRecovery(rotateCtx, *updateMarker)
				return punarobackup.State{InstallationID: rotated.InstallationID, TimelineID: rotated.TimelineID, ChangeSequence: rotated.ChangeSequence}, rotateErr
			}
			rotated, rotateErr := admin.RotateRestoredTimeline(rotateCtx, verified.BackupID, punaropostgres.InstallationState{InstallationID: verified.State.InstallationID, TimelineID: verified.State.TimelineID, ChangeSequence: verified.State.ChangeSequence})
			return punarobackup.State{InstallationID: rotated.InstallationID, TimelineID: rotated.TimelineID, ChangeSequence: rotated.ChangeSequence}, rotateErr
		},
		Finalize: func(finalizeCtx context.Context, finalized punarobackup.State) error {
			finalizationStage = "schema"
			schema, inspectErr := inspectSchema(finalizeCtx, request.AppDSNFile)
			schemaMatches := inspectErr == nil && schema.Version == manifest.SchemaVersion && schema.Classification == punaropostgres.Compatible
			if updateMarker != nil {
				schemaMatches = inspectErr == nil && schema.Version == updateMarker.SourceSchema && (schema.Classification == punaropostgres.Compatible || schema.Classification == punaropostgres.UpgradeRequired)
			}
			if !schemaMatches {
				return errors.New("restored database schema is not the exact supported backup schema")
			}
			if updateMarker != nil {
				admin, openErr := punaropostgres.OpenAdministration(finalizeCtx, punaropostgres.Config{DSNFile: request.OwnerDSNFile})
				if openErr != nil {
					return errors.New("restored update controls are unavailable")
				}
				active, activeErr := admin.ActiveUpdate(finalizeCtx)
				closeErr := admin.Close()
				if activeErr != nil || closeErr != nil || active.UpdateID != updateMarker.UpdateID || active.Phase != punaropostgres.UpdateRecoveryRequired || active.BackupManifestSHA256 != updateMarker.ManifestSHA256 {
					return errors.New("restored update transaction does not match the backup")
				}
			}
			finalizationStage = "roles"
			if err := verifyInstallationPair(finalizeCtx, request.AppDSNFile, request.OwnerDSNFile); err != nil {
				return errors.New("restored database roles do not match")
			}
			finalizationStage = "owner"
			owner, ownerErr := inspectOwner(finalizeCtx, request.AppDSNFile)
			if ownerErr != nil || owner.ID != sourceInstallation.OwnerPrincipalID {
				return errors.New("restored database owner does not match the backup")
			}
			finalizationStage = "timeline"
			restoredDatabase, openErr := punaropostgres.OpenApplication(finalizeCtx, punaropostgres.Config{DSNFile: request.AppDSNFile})
			if openErr != nil {
				return errors.New("restored database cannot be verified")
			}
			restoredState, stateErr := restoredDatabase.InstallationState(finalizeCtx)
			closeErr := restoredDatabase.Close()
			if stateErr != nil || closeErr != nil || restoredState.InstallationID != finalized.InstallationID || restoredState.TimelineID != finalized.TimelineID || restoredState.ChangeSequence != finalized.ChangeSequence {
				return errors.New("restored timeline state does not match publication")
			}
			finalizationStage = "configuration"
			if err := operator.PublishRestore(prepared); err != nil {
				return err
			}
			finalizationStage = ""
			return nil
		},
	})
	if err != nil {
		if finalizationStage != "" {
			return punarobackup.State{}, fmt.Errorf("%w (finalization stage: %s)", err, finalizationStage)
		}
		return punarobackup.State{}, err
	}
	if state.InstallationID != manifest.State.InstallationID {
		return punarobackup.State{}, errors.New("restored installation identity changed")
	}
	return state, nil
}

func receiptMatchesBinding(receipt operator.UpdateRecoveryReceipt, binding punarobackup.UpdateBinding) bool {
	return receipt.UpdateID == binding.UpdateID && receipt.InstallationID == binding.InstallationID &&
		receipt.TimelineID == binding.TimelineID && receipt.ChangeSequence == binding.ChangeSequence &&
		receipt.SourceSchema == binding.SourceSchema && receipt.TargetRelease == binding.TargetRelease &&
		receipt.TargetImageDigest == binding.TargetImageDigest && receipt.ExportedSnapshotID == binding.ExportedSnapshotID &&
		receipt.ManifestSHA256 == binding.ManifestSHA256
}

func postgresDatabaseIdentity(ctx context.Context, appDSNFile string) (string, error) {
	database, err := punaropostgres.OpenApplication(ctx, punaropostgres.Config{DSNFile: appDSNFile})
	if err != nil {
		return "", err
	}
	defer func() { _ = database.Close() }()
	return database.Identity(ctx)
}

func postgresOwnerDatabaseIdentity(ctx context.Context, ownerDSNFile string) (string, error) {
	return punaropostgres.OwnerDatabaseIdentity(ctx, punaropostgres.Config{DSNFile: ownerDSNFile})
}

func cliPathsOverlap(first, second string) bool {
	first = filepath.Clean(first)
	second = filepath.Clean(second)
	if first == second {
		return true
	}
	relative, err := filepath.Rel(first, second)
	if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return true
	}
	relative, err = filepath.Rel(second, first)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func parseDirectory(name string, args []string, stderr io.Writer) (string, bool) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "absolute installation directory")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *directory == "" || !filepath.IsAbs(*directory) {
		return "", false
	}
	return *directory, true
}

func probeHTTP(ctx context.Context, rawURL string) error {
	requestCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusOK {
		return errors.New("health check failed")
	}
	return nil
}

func boundedText(body []byte) string {
	if len(body) > 512 {
		body = body[:512]
	}
	return strings.TrimSpace(string(body))
}

func writeJSON(stdout, stderr io.Writer, value any) int {
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		_, _ = fmt.Fprintln(stderr, "operator output failed")
		return 1
	}
	return 0
}
