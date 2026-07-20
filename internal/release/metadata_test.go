package release

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
)

const (
	testDigestA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testDigestB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testDigestC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func validMetadataJSON() string {
	return `{
  "release": "v0.7.0",
  "image": "ghcr.io/rock3r/punaro@sha256:` + testDigestA + `",
  "schema": {"min": 6, "max": 7, "target": 7, "rollback_floor": 6},
  "postgres_major": 18,
  "release_sha256": "` + testDigestA + `",
  "compose_sha256": "` + testDigestB + `",
  "migration_manifest_sha256": "` + testDigestC + `"
}`
}

func TestParseBindsExactTargetReleaseMetadata(t *testing.T) {
	for _, currentSchema := range []int64{6, 7} {
		metadata, err := Parse([]byte(validMetadataJSON()), Environment{CurrentSchema: currentSchema, PostgreSQLMajor: 18})
		if err != nil {
			t.Fatal(err)
		}
		if metadata.Release != "v0.7.0" || metadata.Image != "ghcr.io/rock3r/punaro@sha256:"+testDigestA || metadata.Schema != (SchemaRange{Min: 6, Max: 7, Target: 7, RollbackFloor: 6}) || metadata.PostgreSQLMajor != 18 {
			t.Fatalf("metadata=%#v", metadata)
		}
		if metadata.ReleaseSHA256 != testDigestA || metadata.ComposeSHA256 != testDigestB || metadata.MigrationManifestSHA256 != testDigestC {
			t.Fatalf("artifact hashes were not bound: %#v", metadata)
		}
	}
}

func TestParseRequiresReleaseArtifactHashToMatchImageDigest(t *testing.T) {
	body := strings.Replace(validMetadataJSON(), `"release_sha256": "`+testDigestA+`"`, `"release_sha256": "`+testDigestB+`"`, 1)
	if _, err := Parse([]byte(body), Environment{CurrentSchema: 6, PostgreSQLMajor: 18}); err == nil {
		t.Fatal("release artifact hash was not bound to the pulled image digest")
	}
}

func TestParseRejectsMalformedAndNonCanonicalMetadata(t *testing.T) {
	valid := validMetadataJSON()
	tests := map[string]string{
		"empty":                  "",
		"truncated":              `{"release":"v0.7.0"`,
		"trailing value":         valid + ` {}`,
		"unknown top-level":      strings.Replace(valid, `"release": "v0.7.0",`, `"release": "v0.7.0", "signature": "unverified",`, 1),
		"unknown nested":         strings.Replace(valid, `"rollback_floor": 6`, `"rollback_floor": 6, "future": 7`, 1),
		"duplicate release":      strings.Replace(valid, `"release": "v0.7.0",`, `"release": "v0.7.0", "release": "v0.8.0",`, 1),
		"null":                   "null",
		"noncanonical release":   strings.Replace(valid, "v0.7.0", " v0.7.0", 1),
		"release too long":       strings.Replace(valid, "v0.7.0", strings.Repeat("r", 129), 1),
		"tagged image":           strings.Replace(valid, "ghcr.io/rock3r/punaro@sha256:"+testDigestA, "ghcr.io/rock3r/punaro:latest", 1),
		"uppercase image digest": strings.Replace(valid, testDigestA, strings.ToUpper(testDigestA), 1),
		"short release hash":     strings.Replace(valid, `"release_sha256": "`+testDigestA+`"`, `"release_sha256": "abcd"`, 1),
		"uppercase compose hash": strings.Replace(valid, testDigestB, strings.ToUpper(testDigestB), 1),
		"nonhex migration hash":  strings.Replace(valid, testDigestC, strings.Repeat("g", 64), 1),
		"zero schema min":        strings.Replace(valid, `"min": 6`, `"min": 0`, 1),
		"max below min":          strings.Replace(valid, `"max": 7`, `"max": 5`, 1),
		"target below min":       strings.Replace(valid, `"target": 7`, `"target": 5`, 1),
		"target above max":       strings.Replace(valid, `"target": 7`, `"target": 8`, 1),
		"rollback below min":     strings.Replace(valid, `"rollback_floor": 6`, `"rollback_floor": 5`, 1),
		"rollback above target":  strings.Replace(valid, `"rollback_floor": 6`, `"rollback_floor": 8`, 1),
		"zero postgres major":    strings.Replace(valid, `"postgres_major": 18`, `"postgres_major": 0`, 1),
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(body), Environment{CurrentSchema: 6, PostgreSQLMajor: 18}); err == nil {
				t.Fatal("invalid release metadata accepted")
			}
		})
	}
}

func TestParseRejectsOversizedMetadata(t *testing.T) {
	body := append([]byte(validMetadataJSON()), make([]byte, MaximumMetadataBytes)...)
	if _, err := Parse(body, Environment{CurrentSchema: 6, PostgreSQLMajor: 18}); err == nil {
		t.Fatal("oversized release metadata accepted")
	}
	bounded := []byte(validMetadataJSON())
	bounded = append(bounded, bytes.Repeat([]byte(" "), MaximumMetadataBytes-len(bounded))...)
	if _, err := Parse(bounded, Environment{CurrentSchema: 6, PostgreSQLMajor: 18}); err != nil {
		t.Fatalf("exactly bounded metadata rejected: %v", err)
	}
}

func TestParseRejectsSchemaDowngradeOrIncompatibleCurrentSchema(t *testing.T) {
	for name, current := range map[string]int64{
		"downgrade":       8,
		"below minimum":   5,
		"invalid current": 0,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(validMetadataJSON()), Environment{CurrentSchema: current, PostgreSQLMajor: 18}); err == nil {
				t.Fatal("incompatible schema boundary accepted")
			}
		})
	}
}

func TestParseRequiresExactPostgreSQLMajor(t *testing.T) {
	for _, major := range []int{0, 17, 19} {
		t.Run(strconv.Itoa(major), func(t *testing.T) {
			if _, err := Parse([]byte(validMetadataJSON()), Environment{CurrentSchema: 6, PostgreSQLMajor: major}); err == nil {
				t.Fatalf("PostgreSQL major %d accepted", major)
			}
		})
	}
}
