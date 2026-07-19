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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
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
	migrateSchema = func(ctx context.Context, dsnFile string) (punaropostgres.SchemaState, error) {
		return punaropostgres.Migrate(ctx, punaropostgres.Config{DSNFile: dsnFile})
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
	recoverInstallationOwner = func(ctx context.Context, installation operator.Installation) (punaropostgres.Principal, error) {
		state, err := inspectSchema(ctx, installation.AppDSNFile)
		if err != nil {
			return punaropostgres.Principal{}, err
		}
		if state.Classification == punaropostgres.Pristine {
			if _, err = migrateSchema(ctx, installation.OwnerDSNFile); err == nil {
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
	startServices = func(ctx context.Context, installation operator.Installation) error {
		command := exec.CommandContext(ctx, "docker", "compose", "--env-file", operator.EnvFile(installation.Directory), "-f", operator.OverrideFile(installation.Directory), "up", "-d") // #nosec G204 -- fixed executable and generated private file arguments.
		command.Dir = installation.Directory
		output, err := command.CombinedOutput()
		if err != nil {
			return fmt.Errorf("service start failed: %s", boundedText(output))
		}
		return nil
	}
	probe = probeHTTP
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "usage: punaro init|up|status|doctor|client")
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
		if _, err = migrateSchema(ctx, ownerFile); err != nil {
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
	installation, err := operator.Init(context.Background(), operator.InitOptions{Directory: *directory, DataDir: *dataDir, BackupDir: *backupDir, Image: *image, OwnerDSNFile: *ownerDSN, AppDSNFile: *appDSN, OwnerName: *ownerName, Ingress: ingress.Policy{Mode: ingress.Mode(*mode), ListenAddr: *listen, PublicURL: *publicURL, TrustedLAN: *trustedLAN, AllowPlaintext: *allowLANHTTP}}, bootstrap)
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
	case operator.RefuseAndUpdate:
		_, _ = fmt.Fprintln(stderr, "punaro up refused: existing schema requires migration; run punaro update")
		return 1
	default:
		_, _ = fmt.Fprintf(stderr, "punaro up refused: schema is %s; follow the documented recovery procedure\n", state.Classification)
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
	if code := writeJSON(stdout, stderr, preview); code != 0 {
		return code
	}
	if !*confirmed {
		_, _ = fmt.Fprintln(stderr, "grant preview printed; rerun with --yes and --confirm-preview-hash to create the enrollment")
		return 3
	}
	if *confirmedHash == "" || *confirmedHash != previewHash {
		_, _ = fmt.Fprintln(stderr, "client enrollment refused: confirmed preview hash does not match the exact grants above")
		return 3
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
	admin, err := punaropostgres.OpenAdministration(context.Background(), punaropostgres.Config{DSNFile: installation.OwnerDSNFile})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "client enrollment failed: host-local administration is unavailable")
		return 1
	}
	defer func() { _ = admin.Close() }()
	pending, err := admin.CreateEnrollment(context.Background(), installation.OwnerPrincipalID, punaropostgres.EnrollmentRequest{ClientBinding: uuid.NewString(), Label: *name, ProjectIDs: projects, AllProjects: *allProjects, TTL: *ttl, CredentialTTL: *credentialTTL}, previewHash)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "client enrollment failed")
		return 1
	}
	return writeJSON(stdout, stderr, pending)
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
