package release

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

func validCatalogJSON() string {
	return `{
  "schema": 1,
  "sequence": 4,
  "published_at": "2026-08-16T12:00:00Z",
  "expires_at": "2026-08-23T12:00:00Z",
  "current_release": "v0.1.0",
  "minimum_safe_sequence": 1,
  "releases": [
    {
      "release": "v0.1.0",
      "sequence": 1,
      "manifest_path": "v0.1.0/punaro-release.json",
      "manifest_length": 128,
      "manifest_sha256": "` + testManifestDigest + `"
    }
  ],
  "critical_blocks": []
}`
}

func TestParseCatalogBindsCurrentReleaseAndManifestDigest(t *testing.T) {
	catalog, err := ParseCatalog([]byte(validCatalogJSON()))
	if err != nil {
		t.Fatal(err)
	}
	if catalog.Schema != 1 || catalog.Sequence != 4 || catalog.CurrentRelease != "v0.1.0" || catalog.MinimumSafeSequence != 1 {
		t.Fatalf("catalog=%#v", catalog)
	}
	if catalog.PublishedAt != "2026-08-16T12:00:00Z" || catalog.ExpiresAt != "2026-08-23T12:00:00Z" {
		t.Fatalf("lifetime=%#v", catalog)
	}
	if len(catalog.Releases) != 1 || catalog.Releases[0].Release != "v0.1.0" || catalog.Releases[0].Sequence != 1 || catalog.Releases[0].ManifestPath != "v0.1.0/punaro-release.json" || catalog.Releases[0].ManifestLength != 128 || catalog.Releases[0].ManifestSHA256 != testManifestDigest {
		t.Fatalf("releases=%#v", catalog.Releases)
	}
	if !catalog.Allows("v0.1.0", 1, testManifestDigest) {
		t.Fatal("catalog must allow the listed current release")
	}
	if catalog.Allows("v0.1.0", 1, testDigestB) || catalog.Allows("v0.9.0", 9, testManifestDigest) {
		t.Fatal("catalog allowed an unnamed or digest-mismatched release")
	}
}

func TestCatalogFreshnessIsSeparateFromParse(t *testing.T) {
	catalog, err := ParseCatalog([]byte(validCatalogJSON()))
	if err != nil {
		t.Fatal(err)
	}
	if !catalog.Fresh(time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("in-window catalog reported stale")
	}
	if catalog.Fresh(time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)) {
		t.Fatal("expired catalog reported fresh")
	}
	if catalog.Fresh(time.Date(2026, 8, 16, 11, 59, 59, 0, time.UTC)) {
		t.Fatal("pre-publication catalog reported fresh")
	}
}

func TestParseCatalogRejectsMalformedAndNonCanonicalDocuments(t *testing.T) {
	valid := validCatalogJSON()
	tests := map[string]string{
		"empty":                 "",
		"unknown field":         strings.Replace(valid, `"schema": 1,`, `"schema": 1, "url": "https://example",`, 1),
		"duplicate sequence":    strings.Replace(valid, `"sequence": 4,`, `"sequence": 4, "sequence": 5,`, 1),
		"schema 2":              strings.Replace(valid, `"schema": 1`, `"schema": 2`, 1),
		"missing current":       strings.Replace(valid, `"current_release": "v0.1.0",`, `"current_release": "v9.9.9",`, 1),
		"zero catalog sequence": strings.Replace(valid, `"sequence": 4`, `"sequence": 0`, 1),
		"zero min safe":         strings.Replace(valid, `"minimum_safe_sequence": 1`, `"minimum_safe_sequence": 0`, 1),
		"min safe above listed": strings.Replace(valid, `"minimum_safe_sequence": 1`, `"minimum_safe_sequence": 2`, 1),
		"expiry before publish": strings.Replace(valid, "2026-08-23T12:00:00Z", "2026-08-16T11:00:00Z", 1),
		"lifetime over 30d":     strings.Replace(valid, "2026-08-23T12:00:00Z", "2026-09-16T12:00:01Z", 1),
		"manifest url":          strings.Replace(valid, "v0.1.0/punaro-release.json", "https://github.com/rock3r/punaro/releases/download/v0.1.0/punaro-release.json", 1),
		"manifest parent path":  strings.Replace(valid, "v0.1.0/punaro-release.json", "v0.1.0/../punaro-release.json", 1),
		"wrong filename":        strings.Replace(valid, "v0.1.0/punaro-release.json", "v0.1.0/latest.json", 1),
		"zero manifest length":  strings.Replace(valid, `"manifest_length": 128`, `"manifest_length": 0`, 1),
		"duplicate listed":      strings.Replace(valid, `"releases": [`, `"releases": [{"release":"v0.1.0","sequence":1,"manifest_path":"v0.1.0/punaro-release.json","manifest_length":128,"manifest_sha256":"`+testManifestDigest+`"},`, 1),
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCatalog([]byte(body)); err == nil {
				t.Fatal("invalid catalog accepted")
			}
		})
	}
}

func TestParseCatalogRejectsCriticallyBlockedCurrentRelease(t *testing.T) {
	body := strings.Replace(validCatalogJSON(), `"critical_blocks": []`, `"critical_blocks": [1]`, 1)
	if _, err := ParseCatalog([]byte(body)); err == nil {
		t.Fatal("catalog accepted a critically blocked current release")
	}
	catalog, err := ParseCatalog([]byte(validCatalogJSON()))
	if err != nil {
		t.Fatal(err)
	}
	catalog.CriticalBlocks = []int64{1}
	if catalog.Allows("v0.1.0", 1, testManifestDigest) {
		t.Fatal("critically blocked release remained allowed")
	}
}

func TestParseCatalogRejectsTooManyCriticalBlocks(t *testing.T) {
	blocks := make([]string, maxCatalogCriticalBlocks+1)
	for index := range blocks {
		blocks[index] = strconv.Itoa(index + 2)
	}
	body := strings.Replace(validCatalogJSON(), `"critical_blocks": []`, `"critical_blocks": [`+strings.Join(blocks, ",")+`]`, 1)
	if _, err := ParseCatalog([]byte(body)); err == nil {
		t.Fatal("catalog accepted too many critical blocks")
	}
}
