package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

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
		ExpiresAt:               time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC),
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
