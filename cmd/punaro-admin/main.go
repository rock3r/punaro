// punaro-admin is the host-local control-plane administration entrypoint.
// It intentionally exposes no network listener.
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

	punaropostgres "github.com/rock3r/punaro/internal/postgres"
)

type adminDatabase interface {
	Close() error
	BootstrapOwner(context.Context, string) (punaropostgres.Principal, error)
	CreateEnrollment(context.Context, string, punaropostgres.EnrollmentRequest, string) (punaropostgres.PendingEnrollment, error)
	ListDeviceCredentials(context.Context, string, int) ([]punaropostgres.DeviceCredentialMetadata, error)
	BeginDeviceCredentialRotation(context.Context, string, string, int64) (punaropostgres.PendingCredentialRotation, error)
	RotateDeviceCredential(context.Context, string, punaropostgres.RotateCredential) (punaropostgres.DeviceCredential, error)
	RevokeDeviceCredential(context.Context, string, string) error
	RegisterLegacyMachine(context.Context, string, string, ed25519.PublicKey) (punaropostgres.LegacyMachine, error)
	ListLegacyMachines(context.Context, string) ([]punaropostgres.LegacyMachine, error)
	RetireLegacyMachine(context.Context, string, string) error
	DisableLegacyAuthentication(context.Context, string) error
}

var openAdminDatabase = func(ctx context.Context, cfg punaropostgres.Config) (adminDatabase, error) {
	return punaropostgres.OpenAdministration(ctx, cfg)
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "usage: punaro-admin init|client|credential|legacy")
		return 2
	}
	switch args[0] {
	case "init":
		return runInit(args[1:], stdout, stderr)
	case "client":
		if len(args) > 1 && args[1] == "add" {
			return runClientAdd(args[2:], stdout, stderr)
		}
	case "credential":
		if len(args) > 1 && args[1] == "list" {
			return runCredentialList(args[2:], stdout, stderr)
		}
		if len(args) > 1 && args[1] == "rotate" {
			return runCredentialRotate(args[2:], stdout, stderr)
		}
		if len(args) > 1 && args[1] == "revoke" {
			return runCredentialRevoke(args[2:], stdout, stderr)
		}
	case "legacy":
		if len(args) > 1 && args[1] == "register" {
			return runLegacyRegister(args[2:], stdout, stderr)
		}
		if len(args) > 1 && args[1] == "list" {
			return runLegacyList(args[2:], stdout, stderr)
		}
		if len(args) > 1 && args[1] == "retire" {
			return runLegacyRetire(args[2:], stdout, stderr)
		}
		if len(args) > 1 && args[1] == "disable" {
			return runLegacyDisable(args[2:], stdout, stderr)
		}
	}
	_, _ = fmt.Fprintln(stderr, "unsupported host-local administration command")
	return 2
}

func runInit(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dsnFile := flags.String("owner-dsn-file", "", "protected schema-owner DSN file")
	name := flags.String("name", "", "owner display name")
	if flags.Parse(args) != nil || *dsnFile == "" || *name == "" || flags.NArg() != 0 {
		return 2
	}
	admin, err := openAdminDatabase(context.Background(), punaropostgres.Config{DSNFile: *dsnFile})
	if err != nil {
		return adminError(stderr, err)
	}
	defer func() { _ = admin.Close() }()
	owner, err := admin.BootstrapOwner(context.Background(), *name)
	if err != nil {
		return adminError(stderr, err)
	}
	return writeJSON(stdout, stderr, owner)
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
	dsnFile := flags.String("owner-dsn-file", "", "protected schema-owner DSN file")
	actor := flags.String("actor-principal-id", "", "installation owner principal ID")
	name := flags.String("name", "", "client display name")
	binding := flags.String("client-binding", "", "client-generated opaque binding UUID")
	allProjects := flags.Bool("all-projects", false, "grant dynamic current and future project access")
	ttl := flags.Duration("ttl", 10*time.Minute, "single-use enrollment lifetime")
	credentialTTL := flags.Duration("credential-ttl", 0, "optional credential lifetime")
	legacyPrincipal := flags.String("legacy-principal-id", "", "operator-approved legacy machine principal for exchange")
	confirmed := flags.Bool("yes", false, "confirm the printed exact grant expansion")
	var projects stringList
	flags.Var(&projects, "project", "selected opaque project UUID (repeatable)")
	if flags.Parse(args) != nil || *actor == "" || *name == "" || *binding == "" || flags.NArg() != 0 {
		return 2
	}
	grants, previewHash, err := punaropostgres.PreviewTrustedAgentEnrollment(projects, *allProjects)
	if err != nil {
		return adminError(stderr, err)
	}
	preview := struct {
		Template    string                     `json:"template"`
		PreviewHash string                     `json:"preview_hash"`
		Grants      []punaropostgres.GrantSpec `json:"grants"`
	}{Template: "trusted-agent", PreviewHash: previewHash, Grants: grants}
	if code := writeJSON(stdout, stderr, preview); code != 0 {
		return code
	}
	if !*confirmed {
		_, _ = fmt.Fprintln(stderr, "grant preview printed; rerun with --yes to create the enrollment")
		return 3
	}
	if *dsnFile == "" {
		_, _ = fmt.Fprintln(stderr, "--owner-dsn-file is required after confirmation")
		return 2
	}
	admin, err := openAdminDatabase(context.Background(), punaropostgres.Config{DSNFile: *dsnFile})
	if err != nil {
		return adminError(stderr, err)
	}
	defer func() { _ = admin.Close() }()
	pending, err := admin.CreateEnrollment(context.Background(), *actor, punaropostgres.EnrollmentRequest{ClientBinding: *binding, Label: *name, ProjectIDs: projects, AllProjects: *allProjects, LegacyPrincipalID: *legacyPrincipal, TTL: *ttl, CredentialTTL: *credentialTTL}, previewHash)
	if err != nil {
		return adminError(stderr, err)
	}
	return writeJSON(stdout, stderr, pending)
}

func runCredentialList(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("credential list", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dsnFile := flags.String("owner-dsn-file", "", "protected schema-owner DSN file")
	actor := flags.String("actor-principal-id", "", "installation owner principal ID")
	limit := flags.Int("limit", 100, "maximum rows (1-1000)")
	if flags.Parse(args) != nil || *dsnFile == "" || *actor == "" || flags.NArg() != 0 {
		return 2
	}
	admin, err := openAdminDatabase(context.Background(), punaropostgres.Config{DSNFile: *dsnFile})
	if err != nil {
		return adminError(stderr, err)
	}
	defer func() { _ = admin.Close() }()
	items, err := admin.ListDeviceCredentials(context.Background(), *actor, *limit)
	if err != nil {
		return adminError(stderr, err)
	}
	return writeJSON(stdout, stderr, map[string]any{"credentials": items})
}

func runCredentialRotate(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("credential rotate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dsnFile := flags.String("owner-dsn-file", "", "protected schema-owner DSN file")
	actor := flags.String("actor-principal-id", "", "installation owner principal ID")
	lookup := flags.String("lookup-id", "", "credential public lookup UUID")
	generation := flags.Int64("expected-generation", 0, "current credential generation")
	codeOutput := flags.String("code-output", "", "new absolute 0600 file for a pending rotation code")
	codeFile := flags.String("code-file", "", "absolute protected pending rotation code file")
	if flags.Parse(args) != nil || *dsnFile == "" || *actor == "" || *lookup == "" || *generation < 1 || (*codeOutput == "") == (*codeFile == "") || flags.NArg() != 0 {
		return 2
	}
	admin, err := openAdminDatabase(context.Background(), punaropostgres.Config{DSNFile: *dsnFile})
	if err != nil {
		return adminError(stderr, err)
	}
	defer func() { _ = admin.Close() }()
	if *codeOutput != "" {
		pending, err := admin.BeginDeviceCredentialRotation(context.Background(), *actor, *lookup, *generation)
		if err != nil {
			return adminError(stderr, err)
		}
		if err := writeProtectedRotationCode(*codeOutput, pending.Code); err != nil {
			_, _ = fmt.Fprintln(stderr, "rotation code output failed")
			return 1
		}
		pending.Code = ""
		return writeJSON(stdout, stderr, pending)
	}
	code, err := readProtectedRotationCode(*codeFile)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "rotation code file is not a protected canonical code")
		return 2
	}
	credential, err := admin.RotateDeviceCredential(context.Background(), *actor, punaropostgres.RotateCredential{LookupID: *lookup, ExpectedGeneration: *generation, Code: code})
	if err != nil {
		return adminError(stderr, err)
	}
	return writeJSON(stdout, stderr, credential)
}

func writeProtectedRotationCode(path, code string) error {
	if !filepath.IsAbs(path) || len(code) != 43 || strings.Contains(code, "=") {
		return errors.New("invalid rotation code output")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- explicit host-local output, created exclusively.
	if err != nil {
		return err
	}
	if _, err := io.WriteString(file, code); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func readProtectedRotationCode(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("rotation code path must be absolute")
	}
	body, err := readProtectedRotationCodeFile(path)
	if err != nil || len(body) != 43 || strings.Contains(string(body), "=") {
		return "", errors.New("rotation code is invalid")
	}
	return string(body), nil
}

func runCredentialRevoke(args []string, _ io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("credential revoke", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dsnFile := flags.String("owner-dsn-file", "", "protected schema-owner DSN file")
	actor := flags.String("actor-principal-id", "", "installation owner principal ID")
	lookup := flags.String("lookup-id", "", "credential public lookup UUID")
	if flags.Parse(args) != nil || *dsnFile == "" || *actor == "" || *lookup == "" || flags.NArg() != 0 {
		return 2
	}
	admin, err := openAdminDatabase(context.Background(), punaropostgres.Config{DSNFile: *dsnFile})
	if err != nil {
		return adminError(stderr, err)
	}
	defer func() { _ = admin.Close() }()
	if err := admin.RevokeDeviceCredential(context.Background(), *actor, *lookup); err != nil {
		return adminError(stderr, err)
	}
	return 0
}

func runLegacyRegister(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("legacy register", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dsnFile := flags.String("owner-dsn-file", "", "protected schema-owner DSN file")
	actor := flags.String("actor-principal-id", "", "installation owner principal ID")
	name := flags.String("name", "", "legacy machine display name")
	publicKeyFile := flags.String("public-key-file", "", "file containing exactly 32 Ed25519 public-key bytes")
	if flags.Parse(args) != nil || *dsnFile == "" || *actor == "" || *name == "" || *publicKeyFile == "" || flags.NArg() != 0 {
		return 2
	}
	publicKey, err := os.ReadFile(*publicKeyFile) // #nosec G304 -- host-local operator explicitly selects this public input.
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		_, _ = fmt.Fprintln(stderr, "legacy public-key file must contain exactly 32 bytes")
		return 2
	}
	admin, err := openAdminDatabase(context.Background(), punaropostgres.Config{DSNFile: *dsnFile})
	if err != nil {
		return adminError(stderr, err)
	}
	defer func() { _ = admin.Close() }()
	machine, err := admin.RegisterLegacyMachine(context.Background(), *actor, *name, ed25519.PublicKey(publicKey))
	if err != nil {
		return adminError(stderr, err)
	}
	return writeJSON(stdout, stderr, machine)
}

func runLegacyList(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("legacy list", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dsnFile := flags.String("owner-dsn-file", "", "protected schema-owner DSN file")
	actor := flags.String("actor-principal-id", "", "installation owner principal ID")
	if flags.Parse(args) != nil || *dsnFile == "" || *actor == "" || flags.NArg() != 0 {
		return 2
	}
	admin, err := openAdminDatabase(context.Background(), punaropostgres.Config{DSNFile: *dsnFile})
	if err != nil {
		return adminError(stderr, err)
	}
	defer func() { _ = admin.Close() }()
	machines, err := admin.ListLegacyMachines(context.Background(), *actor)
	if err != nil {
		return adminError(stderr, err)
	}
	return writeJSON(stdout, stderr, map[string]any{"legacy_machines": machines})
}

func runLegacyRetire(args []string, _ io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("legacy retire", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dsnFile := flags.String("owner-dsn-file", "", "protected schema-owner DSN file")
	actor := flags.String("actor-principal-id", "", "installation owner principal ID")
	legacyPrincipal := flags.String("legacy-principal-id", "", "legacy machine principal ID")
	if flags.Parse(args) != nil || *dsnFile == "" || *actor == "" || *legacyPrincipal == "" || flags.NArg() != 0 {
		return 2
	}
	admin, err := openAdminDatabase(context.Background(), punaropostgres.Config{DSNFile: *dsnFile})
	if err != nil {
		return adminError(stderr, err)
	}
	defer func() { _ = admin.Close() }()
	if err := admin.RetireLegacyMachine(context.Background(), *actor, *legacyPrincipal); err != nil {
		return adminError(stderr, err)
	}
	return 0
}

func runLegacyDisable(args []string, _ io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("legacy disable", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dsnFile := flags.String("owner-dsn-file", "", "protected schema-owner DSN file")
	actor := flags.String("actor-principal-id", "", "installation owner principal ID")
	if flags.Parse(args) != nil || *dsnFile == "" || *actor == "" || flags.NArg() != 0 {
		return 2
	}
	admin, err := openAdminDatabase(context.Background(), punaropostgres.Config{DSNFile: *dsnFile})
	if err != nil {
		return adminError(stderr, err)
	}
	defer func() { _ = admin.Close() }()
	if err := admin.DisableLegacyAuthentication(context.Background(), *actor); err != nil {
		return adminError(stderr, err)
	}
	return 0
}

func writeJSON(stdout, stderr io.Writer, value any) int {
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		_, _ = fmt.Fprintln(stderr, "host-local output failed")
		return 1
	}
	return 0
}

func adminError(stderr io.Writer, err error) int {
	if errors.Is(err, punaropostgres.ErrAlreadyInitialized) || errors.Is(err, punaropostgres.ErrForbidden) || errors.Is(err, punaropostgres.ErrNotFound) || errors.Is(err, punaropostgres.ErrCredentialChanged) {
		_, _ = fmt.Fprintf(stderr, "host-local administration refused: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintln(stderr, "host-local administration failed")
	return 1
}
