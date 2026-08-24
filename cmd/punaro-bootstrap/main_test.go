package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rock3r/punaro/internal/bootstrap"
	punarodiagnostic "github.com/rock3r/punaro/internal/diagnostic"
	punarorelease "github.com/rock3r/punaro/internal/release"
)

func TestBootstrapCLIRequiresAbsoluteDirectoryAndKeys(t *testing.T) {
	if err := run(nil); err == nil {
		t.Fatal("empty args accepted")
	}
	if err := run([]string{"update"}); err == nil {
		t.Fatal("update without flags accepted")
	}
	if err := run([]string{"status", "--directory", "relative-state"}); err == nil {
		t.Fatal("relative status directory accepted")
	}
	if err := run([]string{"rollback", "--directory", "relative-state"}); err == nil {
		t.Fatal("relative rollback directory accepted")
	}
	if err := run([]string{"run", "--directory", "relative-state"}); err == nil {
		t.Fatal("relative run directory accepted")
	}
	if err := run([]string{"seed-checkout", "--directory", "relative-state", "--adapter", "adapter"}); err == nil {
		t.Fatal("relative seed-checkout directory accepted")
	}
	dir := t.TempDir()
	abs := filepath.Join(dir, "state")
	if err := os.Mkdir(abs, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"status", "--directory", abs}); err != nil {
		t.Fatal(err)
	}
	adapter := filepath.Join(dir, "punaro-adapter")
	if err := os.WriteFile(adapter, []byte("checkout-adapter"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"seed-checkout", "--directory", abs, "--adapter", adapter}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"seed-checkout", "--directory", abs, "--adapter", adapter, "--keys-file", "keys.json"}); err == nil {
		t.Fatal("relative seed-checkout keys file accepted")
	}
	if err := run([]string{"update", "--directory", abs, "--keys-file", "keys.json"}); err == nil {
		t.Fatal("relative keys file accepted")
	}
}

func TestFleetDoctorCLIAggregatesOnlyLocallyVerifiedSignedReports(t *testing.T) {
	root, catalogPath, catalogSignaturePath, keysPath := newFleetDoctorFixture(t)
	server := mustFleetDoctorReport(t, punarodiagnostic.ComponentServer, punarodiagnostic.Identity{MachineID: "punaro-lxc", Release: "v0.1.0", ReleaseSequence: 1, CatalogSequence: 1, Protocol: 1, StorageSchema: 44, Platform: "linux-arm64"})
	adapter := mustFleetDoctorReport(t, punarodiagnostic.ComponentAdapter, punarodiagnostic.Identity{MachineID: "mac-studio", Release: "v0.1.0", ReleaseSequence: 1, CatalogSequence: 1, Protocol: 1, Platform: "darwin-arm64", PluginVersion: "v0.1.0", SkillSetDigest: "sha256:" + strings.Repeat("a", 64)})
	serverPath := filepath.Join(root, "server-doctor.json")
	adapterPath := filepath.Join(root, "adapter-doctor.json")
	for path, report := range map[string]punarodiagnostic.Report{serverPath: server, adapterPath: adapter} {
		body, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var stdout, stderr bytes.Buffer
	args := []string{
		"--report", serverPath, "--report", adapterPath,
		"--expect", "punaro-lxc/server", "--expect", "mac-studio/adapter",
		"--catalog", catalogPath, "--catalog-signature", catalogSignaturePath,
		"--release-root", root, "--keys-file", keysPath,
	}
	code := runFleetDoctor(args, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	report, err := punarodiagnostic.Decode(bytes.NewReader(stdout.Bytes()))
	if err != nil || report.Component != punarodiagnostic.ComponentFleet || !report.Healthy {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runFleetDoctorAt(args, &stdout, &stderr, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)); code != 2 || stdout.Len() != 0 {
		t.Fatalf("expired catalog exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func mustFleetDoctorReport(t *testing.T, component punarodiagnostic.Component, identity punarodiagnostic.Identity) punarodiagnostic.Report {
	t.Helper()
	codes := punarodiagnostic.RequiredComponentCheckCodes(component)
	checks := make([]punarodiagnostic.Check, 0, len(codes))
	for _, code := range codes {
		checks = append(checks, punarodiagnostic.Pass(code))
	}
	report, err := punarodiagnostic.New(component, identity, checks)
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func newFleetDoctorFixture(t *testing.T) (string, string, string, string) {
	t.Helper()
	root := t.TempDir()
	artifacts := filepath.Join(root, "artifacts")
	if err := os.Mkdir(artifacts, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(artifacts, "punaro-adapter-linux-amd64"), []byte("adapter"), 0o600); err != nil {
		t.Fatal(err)
	}
	assembled, err := punarorelease.Assemble(punarorelease.AssembleRequest{
		Directory: artifacts, Release: "v0.1.0", Sequence: 1,
		PublishedAt: time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		MinimumSafeSequence: 1, CatalogSequence: 1, ComposeSHA256: strings.Repeat("a", 64), MigrationManifestSHA256: strings.Repeat("b", 64),
		Database: punarorelease.SchemaRange{Min: 10, Max: 44, Target: 44, RollbackFloor: 10}, PostgreSQLMajor: 18,
		GatewayProtocol: punarorelease.ProtocolRange{Min: 1, Max: 1}, ClientProtocol: punarorelease.ProtocolRange{Min: 1, Max: 1},
		MinimumRecoveryProtocol: 1, MinimumBootstrapRelease: "v0.1.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(document []byte) []byte {
		envelope, err := punarorelease.Sign(document, "release-1", private)
		if err != nil {
			t.Fatal(err)
		}
		body, err := punarorelease.EncodeEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	releaseDirectory := filepath.Join(root, "v0.1.0")
	if err := os.Mkdir(releaseDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(root, punarorelease.CatalogFile)
	catalogSignaturePath := filepath.Join(root, punarorelease.CatalogSignatureFile)
	for path, body := range map[string][]byte{
		catalogPath: assembled.CatalogJSON, catalogSignaturePath: sign(assembled.CatalogJSON),
		filepath.Join(releaseDirectory, punarorelease.ReleaseManifestFile):  assembled.ManifestJSON,
		filepath.Join(releaseDirectory, punarorelease.ReleaseSignatureFile): sign(assembled.ManifestJSON),
	} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	keys, err := punarorelease.EncodePublicKeys("release-1", public)
	if err != nil {
		t.Fatal(err)
	}
	keysPath := filepath.Join(root, "release.pub")
	if err := os.WriteFile(keysPath, keys, 0o600); err != nil {
		t.Fatal(err)
	}
	return root, catalogPath, catalogSignaturePath, keysPath
}

func TestBootstrapCLIStatusPrintsRecoveryWithoutCurrent(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "recovery.json"), []byte(`{"schema":1,"mode":"recovery-only","reason":"current-exited"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "status.out")
	out, err := os.Create(outPath) // #nosec G304 -- path is under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = out
	err = run([]string{"status", "--directory", state})
	os.Stdout = old
	_ = out.Close()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(outPath) // #nosec G304 -- path is under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)
	if !strings.Contains(got, "current none") || !strings.Contains(got, "recovery-only") {
		t.Fatalf("status=%q", got)
	}
}

func TestBootstrapCLISeedCheckoutPersistsKeys(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	_, keysPath := newCLIOrigin(t, dir)
	adapter := filepath.Join(dir, "punaro-adapter")
	if err := os.WriteFile(adapter, []byte("checkout-adapter"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"seed-checkout", "--directory", state, "--adapter", adapter, "--keys-file", keysPath}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(state, "release.pub")); err != nil {
		t.Fatalf("keys not persisted: %v", err)
	}
}

func TestBootstrapCLIUpdateInstallsSignedRelease(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	origin, keysPath := newCLIOrigin(t, dir)
	if err := run([]string{"update", "--directory", state, "--keys-file", keysPath, "--origin", origin}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"status", "--directory", state}); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapCLIDoctorEmitsStrictReadOnlyReport(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	origin, keysPath := newCLIOrigin(t, dir)
	if err := run([]string{"update", "--directory", state, "--keys-file", keysPath, "--origin", origin}); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := runBootstrapDoctor([]string{"--directory", state, "--keys-file", keysPath, "--origin", origin, "--timeout", "5s"}, &stdout, &stderr)
	if code != 1 || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	report, err := punarodiagnostic.Decode(bytes.NewReader(stdout.Bytes()))
	if err != nil || report.Component != punarodiagnostic.ComponentBootstrap || report.Identity.Release != "v0.1.0" || bootstrapDoctorStatus(report, "current_artifact_integrity") != punarodiagnostic.StatusPass || bootstrapDoctorStatus(report, "supervisor_process") != punarodiagnostic.StatusFail {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	for _, forbidden := range []string{state, origin, keysPath, "cli-adapter"} {
		if strings.Contains(stdout.String(), forbidden) {
			t.Fatalf("doctor leaked %q: %s", forbidden, stdout.String())
		}
	}
}

func TestBootstrapDoctorKeyReadIsBoundedAndContextAware(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", punarorelease.MaximumEnvelopeBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDoctorKeys(t.Context(), path); err == nil {
		t.Fatal("oversized doctor key set was accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := loadDoctorKeys(ctx, path); err == nil {
		t.Fatal("canceled doctor key read continued")
	}
}

func TestBootstrapDoctorDefersExplicitKeyReadToIsolatedProbe(t *testing.T) {
	previous := bootstrapDoctorProbe
	t.Cleanup(func() { bootstrapDoctorProbe = previous })
	keysPath := filepath.Join(t.TempDir(), "stalled-keys.json")
	called := false
	bootstrapDoctorProbe = func(_ context.Context, request bootstrap.DoctorRequest) (punarodiagnostic.Report, error) {
		called = true
		if request.KeysFile != keysPath || len(request.Keys) != 0 {
			t.Fatalf("doctor key request=%#v", request)
		}
		return punarodiagnostic.Report{}, errors.New("fixture stop")
	}
	if code := runBootstrapDoctor([]string{"--directory", t.TempDir(), "--keys-file", keysPath}, io.Discard, io.Discard); code != 2 || !called {
		t.Fatalf("doctor code=%d isolated_probe_called=%t", code, called)
	}
}

func bootstrapDoctorStatus(report punarodiagnostic.Report, code string) punarodiagnostic.Status {
	for _, check := range report.Checks {
		if check.Code == code {
			return check.Status
		}
	}
	return ""
}

func newCLIOrigin(t *testing.T, dir string) (string, string) {
	t.Helper()
	build := filepath.Join(dir, "build")
	if err := os.Mkdir(build, 0o700); err != nil {
		t.Fatal(err)
	}
	name := "punaro-adapter-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if err := os.WriteFile(filepath.Join(build, name), []byte("cli-adapter"), 0o600); err != nil {
		t.Fatal(err)
	}
	assembled, err := punarorelease.Assemble(punarorelease.AssembleRequest{
		Directory:               build,
		Release:                 "v0.1.0",
		Sequence:                1,
		PublishedAt:             time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC),
		ExpiresAt:               time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC),
		MinimumSafeSequence:     1,
		CatalogSequence:         1,
		ComposeSHA256:           strings.Repeat("a", 64),
		MigrationManifestSHA256: strings.Repeat("b", 64),
		Database:                punarorelease.SchemaRange{Min: 10, Max: 44, Target: 44, RollbackFloor: 10},
		PostgreSQLMajor:         18,
		GatewayProtocol:         punarorelease.ProtocolRange{Min: 1, Max: 1},
		ClientProtocol:          punarorelease.ProtocolRange{Min: 1, Max: 1},
		MinimumRecoveryProtocol: 1,
		MinimumBootstrapRelease: "v0.1.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	catalogSig, err := punarorelease.Sign(assembled.CatalogJSON, "punaro-release-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	catalogSigJSON, err := punarorelease.EncodeEnvelope(catalogSig)
	if err != nil {
		t.Fatal(err)
	}
	manifestSig, err := punarorelease.Sign(assembled.ManifestJSON, "punaro-release-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	manifestSigJSON, err := punarorelease.EncodeEnvelope(manifestSig)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		punarorelease.CatalogReleaseName + "/" + punarorelease.CatalogFile:          assembled.CatalogJSON,
		punarorelease.CatalogReleaseName + "/" + punarorelease.CatalogSignatureFile: catalogSigJSON,
		"v0.1.0/" + punarorelease.ReleaseManifestFile:                               assembled.ManifestJSON,
		"v0.1.0/" + punarorelease.ReleaseSignatureFile:                              manifestSigJSON,
		"v0.1.0/" + name: []byte("cli-adapter"),
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := files[strings.TrimPrefix(r.URL.Path, "/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	keys, err := punarorelease.EncodePublicKeys("punaro-release-1", pub)
	if err != nil {
		t.Fatal(err)
	}
	keysPath := filepath.Join(dir, "release.pub")
	if err := os.WriteFile(keysPath, keys, 0o600); err != nil {
		t.Fatal(err)
	}
	return server.URL, keysPath
}
