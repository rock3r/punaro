package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rock3r/punaro/internal/operator"
	punarorelease "github.com/rock3r/punaro/internal/release"
)

func TestReleaseToolAssemblesSignsAndVerifiesExactBytes(t *testing.T) {
	dir := t.TempDir()
	artifacts := filepath.Join(dir, "artifacts")
	if err := os.Mkdir(artifacts, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(artifacts, "punaro-adapter-linux-amd64"), []byte("adapter"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{
		"assemble",
		"--dir", artifacts,
		"--release", "v0.1.0",
		"--sequence", "10",
		"--catalog-sequence", "10",
		"--minimum-safe-sequence", "1",
		"--published-at", "2026-08-16T12:00:00Z",
		"--expires-at", "2026-08-23T12:00:00Z",
		"--minimum-bootstrap-release", "v0.1.0",
		"--supported-from", "v0.0.9",
		"--critical-block", "9",
	}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"validate", "--dir", artifacts}); err != nil {
		t.Fatal(err)
	}
	originalNow := publicationNow
	publicationNow = func() time.Time { return time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { publicationNow = originalNow })
	if err := run([]string{"publication-check", "--catalog", filepath.Join(artifacts, punarorelease.CatalogFile)}); err != nil {
		t.Fatalf("fresh assembled catalog failed publication check: %v", err)
	}
	if err := run([]string{"validate", "--dir", artifacts, "--release", "v9.9.9"}); err == nil {
		t.Fatal("unexpected release identity was accepted")
	}
	manifestPath := filepath.Join(artifacts, punarorelease.ReleaseManifestFile)
	privatePath := filepath.Join(dir, "release.key")
	publicPath := filepath.Join(dir, "release.pub")
	signaturePath := filepath.Join(dir, punarorelease.ReleaseSignatureFile)
	if err := run([]string{"keygen", "--key-id", "punaro-release-1", "--private-key-file", privatePath, "--public-key-file", publicPath}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"sign", "--key-id", "punaro-release-1", "--key-file", privatePath, "--in", manifestPath, "--out", signaturePath}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"verify", "--keys-file", publicPath, "--document", manifestPath, "--signature", signaturePath}); err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(manifestPath) // #nosec G304 -- assembled file in t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := punarorelease.ParseReleaseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.MinimumBootstrapRelease != "v0.1.0" {
		t.Fatalf("minimum bootstrap=%q", parsed.MinimumBootstrapRelease)
	}
	if len(parsed.SupportedFrom) != 1 || parsed.SupportedFrom[0] != "v0.0.9" {
		t.Fatalf("supported from=%v", parsed.SupportedFrom)
	}
	if parsed.ComposeSHA256 != operator.ComposeManifestSHA256() {
		t.Fatalf("compose digest=%q want generated artifact %q", parsed.ComposeSHA256, operator.ComposeManifestSHA256())
	}
	catalog, err := os.ReadFile(filepath.Join(artifacts, punarorelease.CatalogFile)) // #nosec G304 -- assembled file in t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	parsedCatalog, err := punarorelease.ParseCatalog(catalog)
	if err != nil || len(parsedCatalog.CriticalBlocks) != 1 || parsedCatalog.CriticalBlocks[0] != 9 {
		t.Fatalf("critical blocks=%v err=%v", parsedCatalog.CriticalBlocks, err)
	}
	info, err := os.Stat(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("private key permissions=%v", info.Mode())
	}
}

func TestReleaseToolBoundsCriticalBlockInputs(t *testing.T) {
	args := []string{"assemble"}
	for sequence := 1; sequence <= maximumReleaseCriticalBlocks+1; sequence++ {
		args = append(args, "--critical-block", "1")
	}
	if err := run(args); err == nil {
		t.Fatal("release assembly accepted too many critical blocks")
	}
}

func TestReleaseToolBoundsSupportedFromInputs(t *testing.T) {
	args := []string{"assemble"}
	for sequence := 1; sequence <= maximumReleaseSupportedFrom+1; sequence++ {
		args = append(args, "--supported-from", "v0.1.0")
	}
	if err := run(args); err == nil {
		t.Fatal("release assembly accepted too many supported upgrade sources")
	}
}

func TestBuildFactsBindsPluginSkillsGeneratedComposeAndMigrations(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	facts, err := buildFacts([]string{"--release", "v0.1.0-alpha.1", "--plugin-root", root})
	if err != nil || facts.Release != "v0.1.0-alpha.1" || facts.ComposeSHA256 != operator.ComposeManifestSHA256() || len(facts.MigrationManifestSHA256) != 64 || len(facts.SkillSetSHA256) != 64 {
		t.Fatalf("facts=%#v err=%v", facts, err)
	}
	if _, err := buildFacts([]string{"--release", "v0.1.0", "--plugin-root", root}); err == nil {
		t.Fatal("release not matching all plugin manifests was accepted")
	}
}

func TestPublicationCatalogMustBeFreshAndAdvance(t *testing.T) {
	now := time.Date(2026, 8, 23, 16, 0, 0, 0, time.UTC)
	candidate := punarorelease.Catalog{
		Sequence:    5,
		PublishedAt: now.Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:   now.Add(time.Hour).Format(time.RFC3339),
	}
	previous := candidate
	previous.Sequence = 4
	if err := validatePublicationCatalog(candidate, &previous, now); err != nil {
		t.Fatalf("fresh advancing catalog rejected: %v", err)
	}
	if err := validatePublicationCatalog(candidate, nil, now); err != nil {
		t.Fatalf("fresh initial catalog rejected: %v", err)
	}

	expired := candidate
	expired.ExpiresAt = now.Format(time.RFC3339)
	if err := validatePublicationCatalog(expired, &previous, now); err == nil {
		t.Fatal("expired catalog accepted for publication")
	}
	future := candidate
	future.PublishedAt = now.Add(time.Minute).Format(time.RFC3339)
	if err := validatePublicationCatalog(future, &previous, now); err == nil {
		t.Fatal("not-yet-valid catalog accepted for publication")
	}
	for _, sequence := range []int64{4, 3} {
		downgrade := candidate
		downgrade.Sequence = sequence
		if err := validatePublicationCatalog(downgrade, &previous, now); err == nil {
			t.Fatalf("catalog sequence %d accepted after %d", sequence, previous.Sequence)
		}
	}
}

func TestPublicationCatalogMustRetainEligibleLiveReleases(t *testing.T) {
	now := time.Date(2026, 8, 23, 16, 0, 0, 0, time.UTC)
	priorEntry := punarorelease.CatalogRelease{Release: "v0.1.0-alpha.1", Sequence: 1, ManifestPath: "v0.1.0-alpha.1/punaro-release.json", ManifestLength: 100, ManifestSHA256: strings.Repeat("a", 64)}
	currentEntry := punarorelease.CatalogRelease{Release: "v0.1.0-alpha.2", Sequence: 2, ManifestPath: "v0.1.0-alpha.2/punaro-release.json", ManifestLength: 100, ManifestSHA256: strings.Repeat("b", 64)}
	previous := punarorelease.Catalog{Sequence: 1, MinimumSafeSequence: 1, Releases: []punarorelease.CatalogRelease{priorEntry}}
	candidate := punarorelease.Catalog{Sequence: 2, PublishedAt: now.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), MinimumSafeSequence: 1, Releases: []punarorelease.CatalogRelease{currentEntry}}
	if err := validatePublicationCatalog(candidate, &previous, now); err == nil {
		t.Fatal("replacement catalog dropped an eligible rollback release")
	}
	candidate.CriticalBlocks = []int64{1}
	if err := validatePublicationCatalog(candidate, &previous, now); err != nil {
		t.Fatalf("explicitly blocked prior release was required: %v", err)
	}
}

func TestPublicationCatalogAllowsRetiredCriticalBlocks(t *testing.T) {
	now := time.Date(2026, 8, 23, 16, 0, 0, 0, time.UTC)
	first := punarorelease.CatalogRelease{Release: "v0.1.0-alpha.1", Sequence: 1, ManifestPath: "v0.1.0-alpha.1/punaro-release.json", ManifestLength: 100, ManifestSHA256: strings.Repeat("a", 64)}
	second := punarorelease.CatalogRelease{Release: "v0.1.0-alpha.2", Sequence: 2, ManifestPath: "v0.1.0-alpha.2/punaro-release.json", ManifestLength: 100, ManifestSHA256: strings.Repeat("b", 64)}
	third := punarorelease.CatalogRelease{Release: "v0.1.0-alpha.3", Sequence: 3, ManifestPath: "v0.1.0-alpha.3/punaro-release.json", ManifestLength: 100, ManifestSHA256: strings.Repeat("c", 64)}
	previous := punarorelease.Catalog{Sequence: 2, MinimumSafeSequence: 1, Releases: []punarorelease.CatalogRelease{first, second}, CriticalBlocks: []int64{1}}
	candidate := punarorelease.Catalog{Sequence: 3, PublishedAt: now.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), MinimumSafeSequence: 2, Releases: []punarorelease.CatalogRelease{second, third}}
	if err := validatePublicationCatalog(candidate, &previous, now); err != nil {
		t.Fatalf("retired below-floor critical block was retained: %v", err)
	}
}

func TestReleaseToolRefusesExistingPublicKeyWithoutWritingPrivate(t *testing.T) {
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "release.key")
	publicPath := filepath.Join(dir, "release.pub")
	if err := os.WriteFile(publicPath, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"keygen", "--key-id", "punaro-release-1", "--private-key-file", privatePath, "--public-key-file", publicPath}); err == nil {
		t.Fatal("existing public key overwritten")
	}
	if _, err := os.Stat(privatePath); !os.IsNotExist(err) {
		t.Fatal("private key written after public-key preflight failure")
	}
}

func TestReleaseToolAppendsSecondSignature(t *testing.T) {
	dir := t.TempDir()
	document := filepath.Join(dir, "doc.json")
	if err := os.WriteFile(document, []byte(`{"schema":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	firstPriv := filepath.Join(dir, "first.key")
	firstPub := filepath.Join(dir, "first.pub")
	secondPriv := filepath.Join(dir, "second.key")
	secondPub := filepath.Join(dir, "second.pub")
	firstSig := filepath.Join(dir, "first.sig")
	bothSig := filepath.Join(dir, "both.sig")
	if err := run([]string{"keygen", "--key-id", "punaro-release-1", "--private-key-file", firstPriv, "--public-key-file", firstPub}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"keygen", "--key-id", "punaro-release-2", "--private-key-file", secondPriv, "--public-key-file", secondPub}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"sign", "--key-id", "punaro-release-1", "--key-file", firstPriv, "--in", document, "--out", firstSig}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"sign", "--key-id", "punaro-release-2", "--key-file", secondPriv, "--in", document, "--signature", firstSig, "--out", bothSig}); err == nil {
		t.Fatal("append without verifying keys accepted")
	}
	if err := run([]string{"sign", "--key-id", "punaro-release-2", "--key-file", secondPriv, "--in", document, "--signature", firstSig, "--keys-file", firstPub, "--out", bothSig}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"verify", "--keys-file", firstPub, "--document", document, "--signature", bothSig}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"verify", "--keys-file", secondPub, "--document", document, "--signature", bothSig}); err != nil {
		t.Fatal(err)
	}
}

func TestReleaseToolRefusesToOverwritePrivateKey(t *testing.T) {
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "release.key")
	publicPath := filepath.Join(dir, "release.pub")
	if err := os.WriteFile(privatePath, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"keygen", "--key-id", "punaro-release-1", "--private-key-file", privatePath, "--public-key-file", publicPath}); err == nil {
		t.Fatal("existing private key overwritten")
	}
}

func TestVerifyRejectsTamperedManifest(t *testing.T) {
	dir := t.TempDir()
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	document := []byte(`{"schema":1}`)
	if err := os.WriteFile(filepath.Join(dir, "doc.json"), document, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "release.key"), punarorelease.EncodePrivateKey(private), 0o600); err != nil {
		t.Fatal(err)
	}
	public, err := punarorelease.EncodePublicKeys("punaro-release-1", private.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "release.pub"), public, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"sign", "--key-id", "punaro-release-1", "--key-file", filepath.Join(dir, "release.key"), "--in", filepath.Join(dir, "doc.json"), "--out", filepath.Join(dir, "doc.sig")}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "doc.json"), []byte(`{"schema":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"verify", "--keys-file", filepath.Join(dir, "release.pub"), "--document", filepath.Join(dir, "doc.json"), "--signature", filepath.Join(dir, "doc.sig")}); err == nil {
		t.Fatal("tampered document verified")
	}
}
