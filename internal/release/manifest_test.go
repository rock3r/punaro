package release

import (
	"bytes"
	"strings"
	"testing"
)

const (
	testManifestDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testComposeDigest  = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	testMigrateDigest  = "1111111111111111111111111111111111111111111111111111111111111111"
)

func validReleaseManifestJSON() string {
	return `{
  "schema": 1,
  "sequence": 1,
  "release": "v0.1.0",
  "published_at": "2026-08-16T12:00:00Z",
  "gateway_protocol": {"min": 1, "max": 1},
  "client_protocol": {"min": 1, "max": 1},
  "minimum_recovery_protocol": 1,
  "minimum_bootstrap_release": "v0.1.0",
  "database": {"min": 10, "max": 44, "target": 44, "rollback_floor": 10},
  "postgres_major": 18,
  "compose_sha256": "` + testComposeDigest + `",
  "migration_manifest_sha256": "` + testMigrateDigest + `",
  "artifacts": [
    {
      "component": "punaro-adapter",
      "os": "darwin",
      "arch": "arm64",
      "path": "v0.1.0/punaro-adapter-darwin-arm64",
      "length": 32,
      "mode": 493,
      "sha256": "` + testManifestDigest + `"
    }
  ],
  "supported_from": [],
  "stepping_stones": []
}`
}

func TestValidProductReleaseNameDefinesSharedIdentityContract(t *testing.T) {
	for _, name := range []string{"v0.1.0-alpha.1", "v1.2.3", "v1.2.3-rc.1+darwin.arm64"} {
		if !ValidProductReleaseName(name) {
			t.Fatalf("valid release name rejected: %q", name)
		}
	}
	for _, name := range []string{"", "latest", CatalogReleaseName, LocalCheckoutRelease, "release/name", "release secret", "v1..2.3", "v1.2.3junk", "v01.2.3", "v1.2.3-01", "plugin+alpha"} {
		if ValidProductReleaseName(name) {
			t.Fatalf("invalid release name accepted: %q", name)
		}
	}
}

func TestParseReleaseManifestBindsExactPublicReleaseContract(t *testing.T) {
	manifest, err := ParseReleaseManifest([]byte(validReleaseManifestJSON()))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Schema != 1 || manifest.Sequence != 1 || manifest.Release != "v0.1.0" || manifest.PublishedAt != "2026-08-16T12:00:00Z" {
		t.Fatalf("identity=%#v", manifest)
	}
	if manifest.GatewayProtocol != (ProtocolRange{Min: 1, Max: 1}) || manifest.ClientProtocol != (ProtocolRange{Min: 1, Max: 1}) {
		t.Fatalf("protocols=%#v", manifest)
	}
	if manifest.MinimumRecoveryProtocol != 1 || manifest.MinimumBootstrapRelease != "v0.1.0" {
		t.Fatalf("bootstrap bound=%#v", manifest)
	}
	if manifest.Database != (SchemaRange{Min: 10, Max: 44, Target: 44, RollbackFloor: 10}) || manifest.PostgreSQLMajor != 18 {
		t.Fatalf("database=%#v", manifest)
	}
	if manifest.Image != "" || manifest.ReleaseSHA256 != "" {
		t.Fatalf("unpublished image must stay omitted: %#v", manifest)
	}
	if manifest.ComposeSHA256 != testComposeDigest || manifest.MigrationManifestSHA256 != testMigrateDigest {
		t.Fatalf("source hashes=%#v", manifest)
	}
	if len(manifest.Artifacts) != 1 {
		t.Fatalf("artifacts=%#v", manifest.Artifacts)
	}
	artifact := manifest.Artifacts[0]
	if artifact.Component != "punaro-adapter" || artifact.OS != "darwin" || artifact.Arch != "arm64" || artifact.Path != "v0.1.0/punaro-adapter-darwin-arm64" || artifact.Length != 32 || artifact.Mode != 0o755 || artifact.SHA256 != testManifestDigest {
		t.Fatalf("artifact=%#v", artifact)
	}
}

func TestParseReleaseManifestAcceptsOptionalPinnedGatewayImage(t *testing.T) {
	body := strings.Replace(validReleaseManifestJSON(), `"postgres_major": 18,`, `"postgres_major": 18,
  "image": "ghcr.io/rock3r/punaro@sha256:`+testDigestA+`",
  "release_sha256": "`+testDigestA+`",`, 1)
	manifest, err := ParseReleaseManifest([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Image != "ghcr.io/rock3r/punaro@sha256:"+testDigestA || manifest.ReleaseSHA256 != testDigestA {
		t.Fatalf("image binding=%#v", manifest)
	}
}

func TestParseReleaseManifestRejectsMalformedAndNonCanonicalDocuments(t *testing.T) {
	valid := validReleaseManifestJSON()
	tests := map[string]string{
		"empty":                    "",
		"truncated":                `{"schema":1`,
		"trailing value":           valid + ` {}`,
		"unknown top-level":        strings.Replace(valid, `"schema": 1,`, `"schema": 1, "latest": true,`, 1),
		"duplicate release":        strings.Replace(valid, `"release": "v0.1.0",`, `"release": "v0.1.0", "release": "v0.2.0",`, 1),
		"schema 2":                 strings.Replace(valid, `"schema": 1`, `"schema": 2`, 1),
		"zero sequence":            strings.Replace(valid, `"sequence": 1`, `"sequence": 0`, 1),
		"local checkout release":   strings.Replace(valid, `"release": "v0.1.0"`, `"release": "v0.0.0-local"`, 1),
		"noncanonical time":        strings.Replace(valid, "2026-08-16T12:00:00Z", "2026-08-16T12:00:00+00:00", 1),
		"path with scheme":         strings.Replace(valid, "v0.1.0/punaro-adapter-darwin-arm64", "https://example/punaro-adapter", 1),
		"path with parent":         strings.Replace(valid, "v0.1.0/punaro-adapter-darwin-arm64", "v0.1.0/../punaro-adapter", 1),
		"path missing release":     strings.Replace(valid, "v0.1.0/punaro-adapter-darwin-arm64", "punaro-adapter-darwin-arm64", 1),
		"path extra component":     strings.Replace(valid, "v0.1.0/punaro-adapter-darwin-arm64", "v0.1.0/darwin/punaro-adapter", 1),
		"unknown component":        strings.Replace(valid, "punaro-adapter", "punaro-evil", 1),
		"unknown os":               strings.Replace(valid, `"os": "darwin"`, `"os": "freebsd"`, 1),
		"zero length":              strings.Replace(valid, `"length": 32`, `"length": 0`, 1),
		"writable mode":            strings.Replace(valid, `"mode": 493`, `"mode": 511`, 1),
		"uppercase digest":         strings.Replace(valid, testManifestDigest, strings.ToUpper(testManifestDigest), 1),
		"image without digest":     strings.Replace(valid, `"postgres_major": 18,`, `"postgres_major": 18, "image": "ghcr.io/rock3r/punaro:latest",`, 1),
		"image hash mismatch":      strings.Replace(valid, `"postgres_major": 18,`, `"postgres_major": 18, "image": "ghcr.io/rock3r/punaro@sha256:`+testDigestA+`", "release_sha256": "`+testDigestB+`",`, 1),
		"protocol max below min":   strings.Replace(valid, `"min": 1, "max": 1`, `"min": 2, "max": 1`, 1),
		"zero recovery protocol":   strings.Replace(valid, `"minimum_recovery_protocol": 1`, `"minimum_recovery_protocol": 0`, 1),
		"too many stepping stones": strings.Replace(valid, `"stepping_stones": []`, `"stepping_stones": ["v0.0.1","v0.0.2","v0.0.3","v0.0.4","v0.0.5","v0.0.6","v0.0.7","v0.0.8","v0.0.9","v0.0.10","v0.0.11","v0.0.12","v0.0.13","v0.0.14","v0.0.15","v0.0.16","v0.0.17"]`, 1),
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseReleaseManifest([]byte(body)); err == nil {
				t.Fatal("invalid release manifest accepted")
			}
		})
	}
}

func TestParseReleaseManifestRejectsOversizedDocument(t *testing.T) {
	body := append([]byte(validReleaseManifestJSON()), make([]byte, MaximumManifestBytes)...)
	if _, err := ParseReleaseManifest(body); err == nil {
		t.Fatal("oversized release manifest accepted")
	}
	bounded := []byte(validReleaseManifestJSON())
	bounded = append(bounded, bytes.Repeat([]byte(" "), MaximumManifestBytes-len(bounded))...)
	if _, err := ParseReleaseManifest(bounded); err != nil {
		t.Fatalf("exactly bounded manifest rejected: %v", err)
	}
}

func TestParseReleaseManifestRejectsDuplicateArtifactIdentity(t *testing.T) {
	body := strings.Replace(validReleaseManifestJSON(), `"artifacts": [`, `"artifacts": [
    {
      "component": "punaro-adapter",
      "os": "darwin",
      "arch": "arm64",
      "path": "v0.1.0/punaro-adapter-darwin-arm64-copy",
      "length": 16,
      "mode": 493,
      "sha256": "`+testDigestB+`"
    },`, 1)
	if _, err := ParseReleaseManifest([]byte(body)); err == nil {
		t.Fatal("duplicate component/os/arch accepted")
	}
}
