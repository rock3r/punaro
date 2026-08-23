package release

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAssembleWritesCatalogAndManifestForScannedArtifacts(t *testing.T) {
	dir := t.TempDir()
	adapter := []byte("adapter-bytes-for-release-assemble")
	if err := os.WriteFile(filepath.Join(dir, "punaro-adapter-darwin-arm64"), adapter, 0o600); err != nil {
		t.Fatal(err)
	}
	windows := []byte("windows-adapter")
	if err := os.WriteFile(filepath.Join(dir, "punaro-adapter-windows-amd64.exe"), windows, 0o600); err != nil {
		t.Fatal(err)
	}
	assembled, err := Assemble(AssembleRequest{
		Directory:               dir,
		Release:                 "v0.1.0",
		Sequence:                1,
		PublishedAt:             time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC),
		ExpiresAt:               time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC),
		MinimumSafeSequence:     1,
		ComposeSHA256:           testComposeDigest,
		MigrationManifestSHA256: testMigrateDigest,
		Database:                SchemaRange{Min: 10, Max: 44, Target: 44, RollbackFloor: 10},
		PostgreSQLMajor:         18,
		GatewayProtocol:         ProtocolRange{Min: 1, Max: 1},
		ClientProtocol:          ProtocolRange{Min: 1, Max: 1},
		MinimumRecoveryProtocol: 1,
		MinimumBootstrapRelease: "v0.1.0",
		CatalogSequence:         1,
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := ParseReleaseManifest(assembled.ManifestJSON)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := ParseCatalog(assembled.CatalogJSON)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Artifacts) != 2 {
		t.Fatalf("artifacts=%#v", manifest.Artifacts)
	}
	wantAdapter := sha256.Sum256(adapter)
	if manifest.Artifacts[0].Path != "v0.1.0/punaro-adapter-darwin-arm64" || manifest.Artifacts[0].Length != int64(len(adapter)) || manifest.Artifacts[0].SHA256 != hex.EncodeToString(wantAdapter[:]) || manifest.Artifacts[0].Mode != 0o755 {
		t.Fatalf("darwin artifact=%#v", manifest.Artifacts[0])
	}
	if manifest.Artifacts[1].Path != "v0.1.0/punaro-adapter-windows-amd64.exe" || manifest.Artifacts[1].OS != "windows" {
		t.Fatalf("windows artifact=%#v", manifest.Artifacts[1])
	}
	sum := sha256.Sum256(assembled.ManifestJSON)
	if !catalog.Allows("v0.1.0", 1, hex.EncodeToString(sum[:])) {
		t.Fatalf("catalog does not name the assembled manifest: %#v", catalog)
	}
	if _, err := os.Stat(filepath.Join(dir, ReleaseManifestFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, CatalogFile)); err != nil {
		t.Fatal(err)
	}
}

func TestAssembleRetainsEligiblePriorReleasesForRollback(t *testing.T) {
	firstDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(firstDir, "punaro-adapter-linux-amd64"), []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := Assemble(AssembleRequest{
		Directory: firstDir, Release: "v0.1.0-alpha.1", Sequence: 1, CatalogSequence: 1,
		PublishedAt: time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC),
		MinimumSafeSequence: 1, ComposeSHA256: testComposeDigest, MigrationManifestSHA256: testMigrateDigest,
		Database: SchemaRange{Min: 10, Max: 44, Target: 44, RollbackFloor: 10}, PostgreSQLMajor: 18,
		GatewayProtocol: ProtocolRange{Min: 1, Max: 1}, ClientProtocol: ProtocolRange{Min: 1, Max: 1},
		MinimumRecoveryProtocol: 1, MinimumBootstrapRelease: "v0.1.0-alpha.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	secondDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(secondDir, "punaro-adapter-linux-amd64"), []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := Assemble(AssembleRequest{
		Directory: secondDir, Release: "v0.1.0-alpha.2", Sequence: 2, CatalogSequence: 2, PreviousCatalog: &first.Catalog,
		PublishedAt: time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC),
		ComposeSHA256: testComposeDigest, MigrationManifestSHA256: testMigrateDigest,
		Database: SchemaRange{Min: 10, Max: 44, Target: 44, RollbackFloor: 10}, PostgreSQLMajor: 18,
		GatewayProtocol: ProtocolRange{Min: 1, Max: 1}, ClientProtocol: ProtocolRange{Min: 1, Max: 1},
		MinimumRecoveryProtocol: 1, MinimumBootstrapRelease: "v0.1.0-alpha.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	prior := first.Catalog.Releases[0]
	if len(second.Catalog.Releases) != 2 || second.Catalog.MinimumSafeSequence != 1 || !second.Catalog.Allows(prior.Release, prior.Sequence, prior.ManifestSHA256) {
		t.Fatalf("replacement catalog lost rollback release: %#v", second.Catalog)
	}
}

func TestAssembleRejectsUnexpectedFilenamesAndAbsoluteArtifactPaths(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "latest"), []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Assemble(AssembleRequest{
		Directory:               dir,
		Release:                 "v0.1.0",
		Sequence:                1,
		PublishedAt:             time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC),
		ExpiresAt:               time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC),
		MinimumSafeSequence:     1,
		ComposeSHA256:           testComposeDigest,
		MigrationManifestSHA256: testMigrateDigest,
		Database:                SchemaRange{Min: 10, Max: 44, Target: 44, RollbackFloor: 10},
		PostgreSQLMajor:         18,
		GatewayProtocol:         ProtocolRange{Min: 1, Max: 1},
		ClientProtocol:          ProtocolRange{Min: 1, Max: 1},
		MinimumRecoveryProtocol: 1,
		MinimumBootstrapRelease: "v0.1.0",
		CatalogSequence:         1,
	})
	if err == nil {
		t.Fatal("unexpected filename accepted")
	}
}

func TestFixedGitHubReleaseOriginHasNoMutableLatestPointer(t *testing.T) {
	if GitHubReleaseOrigin != "https://github.com/rock3r/punaro/releases/download" {
		t.Fatalf("origin=%q", GitHubReleaseOrigin)
	}
	if CatalogReleaseName != "catalog" || ReleaseManifestFile != "punaro-release.json" || CatalogFile != "punaro-catalog.json" {
		t.Fatalf("names manifest=%q catalog=%q tag=%q", ReleaseManifestFile, CatalogFile, CatalogReleaseName)
	}
	if err := ValidateRelativePath("latest/punaro-adapter"); err == nil {
		t.Fatal("latest artifact path accepted")
	}
	if err := ValidateRelativePath("v0.1.0/punaro-adapter-darwin-arm64"); err != nil {
		t.Fatal(err)
	}
}
