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
	dir := t.TempDir()
	abs := filepath.Join(dir, "state")
	if err := os.Mkdir(abs, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"status", "--directory", abs}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"update", "--directory", abs, "--keys-file", "keys.json"}); err == nil {
		t.Fatal("relative keys file accepted")
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
