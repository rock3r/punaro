package bootstrap

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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

const (
	testCompose  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testMigrate  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testKeyID    = "punaro-release-1"
	testArtifact = "adapter-bytes-for-bootstrap"
)

func TestUpdateInstallsSignedPlatformArtifacts(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH})
	dir := t.TempDir()
	result, err := Update(Request{
		Directory: dir,
		Origin:    origin.URL,
		Keys:      origin.Keys,
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
		Now:       time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Release != "v0.1.0" || result.Sequence != 1 {
		t.Fatalf("result=%#v", result)
	}
	installed := filepath.Join(dir, "current", artifactName("punaro-adapter", runtime.GOOS, runtime.GOARCH))
	body, err := os.ReadFile(installed) // #nosec G304 -- path is under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != testArtifact {
		t.Fatalf("installed=%q", body)
	}
	status, err := Status(dir)
	if err != nil {
		t.Fatal(err)
	}
	if status.Current != "v0.1.0" || status.CurrentSequence != 1 || status.Previous != "" {
		t.Fatalf("status=%#v", status)
	}
}

func TestUpdatePromotesCurrentToPrevious(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: "first", goos: runtime.GOOS, goarch: runtime.GOARCH})
	dir := t.TempDir()
	req := Request{Directory: dir, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}
	if _, err := Update(req); err != nil {
		t.Fatal(err)
	}
	origin.republish(t, originSpec{payload: "second", goos: runtime.GOOS, goarch: runtime.GOARCH, release: "v0.2.0", sequence: 2, catalogSequence: 2})
	if _, err := Update(req); err != nil {
		t.Fatal(err)
	}
	status, err := Status(dir)
	if err != nil {
		t.Fatal(err)
	}
	if status.Current != "v0.2.0" || status.CurrentSequence != 2 || status.Previous != "v0.1.0" || status.PreviousSequence != 1 {
		t.Fatalf("status=%#v", status)
	}
	current, err := os.ReadFile(filepath.Join(dir, "current", artifactName("punaro-adapter", runtime.GOOS, runtime.GOARCH))) // #nosec G304 -- path is under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	previous, err := os.ReadFile(filepath.Join(dir, "previous", artifactName("punaro-adapter", runtime.GOOS, runtime.GOARCH))) // #nosec G304 -- path is under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != "second" || string(previous) != "first" {
		t.Fatalf("current=%q previous=%q", current, previous)
	}
}

func TestRollbackSwapsPublishedSlots(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: "first", goos: runtime.GOOS, goarch: runtime.GOARCH})
	dir := t.TempDir()
	req := Request{Directory: dir, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}
	if _, err := Update(req); err != nil {
		t.Fatal(err)
	}
	origin.republish(t, originSpec{payload: "second", goos: runtime.GOOS, goarch: runtime.GOARCH, release: "v0.2.0", sequence: 2, catalogSequence: 2})
	if _, err := Update(req); err != nil {
		t.Fatal(err)
	}
	result, err := Rollback(dir)
	if err != nil {
		t.Fatal(err)
	}
	if result.Release != "v0.1.0" || result.Sequence != 1 {
		t.Fatalf("rollback=%#v", result)
	}
	status, err := Status(dir)
	if err != nil {
		t.Fatal(err)
	}
	if status.Current != "v0.1.0" || status.Previous != "v0.2.0" {
		t.Fatalf("status=%#v", status)
	}
	if _, err := Update(req); err != nil {
		t.Fatal(err)
	}
	status, err = Status(dir)
	if err != nil {
		t.Fatal(err)
	}
	if status.Current != "v0.2.0" || status.Previous != "v0.1.0" {
		t.Fatalf("reupdate status=%#v", status)
	}
}

func TestRollbackRequiresPreviousSlot(t *testing.T) {
	dir := t.TempDir()
	if _, err := Rollback(dir); err == nil {
		t.Fatal("rollback without slots accepted")
	}
}

func TestUpdateRejectsUnsignedCatalog(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH})
	delete(origin.Files, punarorelease.CatalogReleaseName+"/"+punarorelease.CatalogSignatureFile)
	dir := t.TempDir()
	if _, err := Update(Request{Directory: dir, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}); err == nil {
		t.Fatal("unsigned catalog accepted")
	}
}

func TestUpdateRejectsUnsignedManifest(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH})
	delete(origin.Files, "v0.1.0/"+punarorelease.ReleaseSignatureFile)
	dir := t.TempDir()
	if _, err := Update(Request{Directory: dir, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}); err == nil {
		t.Fatal("unsigned manifest accepted")
	}
}

func TestUpdateRejectsAlteredArtifactBytes(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH})
	name := artifactName("punaro-adapter", runtime.GOOS, runtime.GOARCH)
	origin.Files["v0.1.0/"+name] = []byte("tampered-adapter-bytes")
	dir := t.TempDir()
	if _, err := Update(Request{Directory: dir, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}); err == nil {
		t.Fatal("altered artifact accepted")
	}
}

func TestUpdateRejectsStaleCatalog(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH})
	dir := t.TempDir()
	if _, err := Update(Request{Directory: dir, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: time.Date(2026, 8, 24, 0, 0, 0, 0, time.UTC)}); err == nil {
		t.Fatal("expired catalog accepted")
	}
}

func TestUpdateRejectsCriticalBlock(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH, criticalBlocks: []int64{1}})
	dir := t.TempDir()
	if _, err := Update(Request{Directory: dir, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}); err == nil {
		t.Fatal("critically blocked release accepted")
	}
}

func TestUpdateRejectsReleaseSequenceDowngrade(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH})
	dir := t.TempDir()
	req := Request{Directory: dir, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}
	if _, err := Update(req); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, acceptedFile), []byte(`{"schema":1,"release":"v9.9.9","release_sequence":9,"catalog_sequence":9,"manifest_sha256":"`+strings.Repeat("c", 64)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Update(req); err == nil {
		t.Fatal("sequence downgrade accepted")
	}
}

func TestUpdateRejectsCatalogSequenceDowngrade(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH})
	dir := t.TempDir()
	req := Request{Directory: dir, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}
	if _, err := Update(req); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, acceptedFile), []byte(`{"schema":1,"release":"v0.1.0","release_sequence":1,"catalog_sequence":9,"manifest_sha256":"`+strings.Repeat("c", 64)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Update(req); err == nil {
		t.Fatal("catalog sequence downgrade accepted")
	}
}

func TestUpdateRejectsPathTraversalAsset(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "..") {
			t.Fatal("bootstrap requested a parent path")
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(origin.Close)
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if _, err := Update(Request{Directory: dir, Origin: origin.URL + "/../evil", Keys: map[string]ed25519.PublicKey{testKeyID: pub}, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}); err == nil {
		t.Fatal("origin with parent path accepted")
	}
}

func TestUpdateRejectsNonLocalHTTPOrigin(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if _, err := Update(Request{Directory: dir, Origin: "http://example.com/releases", Keys: map[string]ed25519.PublicKey{testKeyID: pub}, Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}); err == nil {
		t.Fatal("cleartext remote origin accepted")
	}
}

func TestUpdateSelectsOnlyRequestedPlatform(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: "linux", goarch: "amd64"})
	dir := t.TempDir()
	if _, err := Update(Request{Directory: dir, Origin: origin.URL, Keys: origin.Keys, GOOS: "windows", GOARCH: "amd64", Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}); err == nil {
		t.Fatal("missing platform artifacts accepted")
	}
}

func TestUpdateRejectsRelativeDirectory(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH})
	if _, err := Update(Request{Directory: "relative-state", Origin: origin.URL, Keys: origin.Keys, Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}); err == nil {
		t.Fatal("relative directory accepted")
	}
}

func TestSignedDocumentDigestMatchesCatalog(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: "linux", goarch: "amd64"})
	sum := sha256.Sum256(origin.Files["v0.1.0/"+punarorelease.ReleaseManifestFile])
	catalog, err := punarorelease.ParseCatalog(origin.Files[punarorelease.CatalogReleaseName+"/"+punarorelease.CatalogFile])
	if err != nil {
		t.Fatal(err)
	}
	if !catalog.Allows("v0.1.0", 1, hex.EncodeToString(sum[:])) {
		t.Fatal("test catalog does not bind the assembled manifest")
	}
}

type originSpec struct {
	payload         string
	goos            string
	goarch          string
	release         string
	sequence        int64
	catalogSequence int64
	criticalBlocks  []int64
}

type signedOrigin struct {
	URL   string
	Keys  map[string]ed25519.PublicKey
	Files map[string][]byte
	priv  ed25519.PrivateKey
}

func newSignedOrigin(t *testing.T, spec originSpec) *signedOrigin {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := files[strings.TrimPrefix(r.URL.Path, "/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	origin := &signedOrigin{
		URL:   server.URL,
		Keys:  map[string]ed25519.PublicKey{testKeyID: pub},
		Files: files,
		priv:  priv,
	}
	origin.republish(t, spec)
	return origin
}

func (origin *signedOrigin) republish(t *testing.T, spec originSpec) {
	t.Helper()
	if spec.release == "" {
		spec.release = "v0.1.0"
	}
	if spec.sequence == 0 {
		spec.sequence = 1
	}
	if spec.catalogSequence == 0 {
		spec.catalogSequence = 1
	}
	build := t.TempDir()
	name := artifactName("punaro-adapter", spec.goos, spec.goarch)
	if err := os.WriteFile(filepath.Join(build, name), []byte(spec.payload), 0o600); err != nil {
		t.Fatal(err)
	}
	assembled, err := punarorelease.Assemble(punarorelease.AssembleRequest{
		Directory:               build,
		Release:                 spec.release,
		Sequence:                spec.sequence,
		PublishedAt:             time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC),
		ExpiresAt:               time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC),
		MinimumSafeSequence:     1,
		CatalogSequence:         spec.catalogSequence,
		ComposeSHA256:           testCompose,
		MigrationManifestSHA256: testMigrate,
		Database:                punarorelease.SchemaRange{Min: 10, Max: 44, Target: 44, RollbackFloor: 10},
		PostgreSQLMajor:         18,
		GatewayProtocol:         punarorelease.ProtocolRange{Min: 1, Max: 1},
		ClientProtocol:          punarorelease.ProtocolRange{Min: 1, Max: 1},
		MinimumRecoveryProtocol: 1,
		MinimumBootstrapRelease: "v0.1.0",
		CriticalBlocks:          spec.criticalBlocks,
	})
	if err != nil {
		t.Fatal(err)
	}
	catalogSig, err := punarorelease.Sign(assembled.CatalogJSON, testKeyID, origin.priv)
	if err != nil {
		t.Fatal(err)
	}
	catalogSigJSON, err := punarorelease.EncodeEnvelope(catalogSig)
	if err != nil {
		t.Fatal(err)
	}
	manifestSig, err := punarorelease.Sign(assembled.ManifestJSON, testKeyID, origin.priv)
	if err != nil {
		t.Fatal(err)
	}
	manifestSigJSON, err := punarorelease.EncodeEnvelope(manifestSig)
	if err != nil {
		t.Fatal(err)
	}
	for key := range origin.Files {
		delete(origin.Files, key)
	}
	origin.Files[punarorelease.CatalogReleaseName+"/"+punarorelease.CatalogFile] = assembled.CatalogJSON
	origin.Files[punarorelease.CatalogReleaseName+"/"+punarorelease.CatalogSignatureFile] = catalogSigJSON
	origin.Files[spec.release+"/"+punarorelease.ReleaseManifestFile] = assembled.ManifestJSON
	origin.Files[spec.release+"/"+punarorelease.ReleaseSignatureFile] = manifestSigJSON
	origin.Files[spec.release+"/"+name] = []byte(spec.payload)
}
