package release

import (
	"errors"
	"time"
)

const (
	maxCatalogReleases       = 32
	maxCatalogCriticalBlocks = 32
	maxCatalogLifetime       = 30 * 24 * time.Hour
)

// Catalog is the short-lived signed list of currently allowed releases.
type Catalog struct {
	Schema              int64            `json:"schema"`
	Sequence            int64            `json:"sequence"`
	PublishedAt         string           `json:"published_at"`
	ExpiresAt           string           `json:"expires_at"`
	CurrentRelease      string           `json:"current_release"`
	MinimumSafeSequence int64            `json:"minimum_safe_sequence"`
	Releases            []CatalogRelease `json:"releases"`
	CriticalBlocks      []int64          `json:"critical_blocks"`
}

// CatalogRelease names one immutable manifest still listed for automatic use.
type CatalogRelease struct {
	Release        string `json:"release"`
	Sequence       int64  `json:"sequence"`
	ManifestPath   string `json:"manifest_path"`
	ManifestLength int64  `json:"manifest_length"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

// ParseCatalog strictly parses one bounded public catalog. Expiry is not
// enforced here; Fresh reports whether automatic use is still allowed.
func ParseCatalog(body []byte) (Catalog, error) {
	catalog, err := decodeStrict[Catalog](body, MaximumManifestBytes)
	if err != nil || catalog.validate() != nil {
		return Catalog{}, errors.New("release catalog is invalid")
	}
	return catalog, nil
}

func (catalog Catalog) validate() error {
	if catalog.Schema != releaseDocumentSchema || catalog.Sequence < 1 || !validProductReleaseName(catalog.CurrentRelease) || catalog.MinimumSafeSequence < 1 {
		return errors.New("invalid catalog identity")
	}
	published, ok := parseCanonicalUTC(catalog.PublishedAt)
	if !ok {
		return errors.New("invalid catalog lifetime")
	}
	expires, ok := parseCanonicalUTC(catalog.ExpiresAt)
	if !ok || !expires.After(published) || expires.Sub(published) > maxCatalogLifetime {
		return errors.New("invalid catalog lifetime")
	}
	if len(catalog.Releases) == 0 || len(catalog.Releases) > maxCatalogReleases {
		return errors.New("invalid catalog releases")
	}
	seenName := map[string]struct{}{}
	seenSequence := map[int64]struct{}{}
	lowest := catalog.Releases[0].Sequence
	foundCurrent := false
	currentSequence := int64(0)
	for _, entry := range catalog.Releases {
		if err := entry.validate(); err != nil {
			return err
		}
		if _, exists := seenName[entry.Release]; exists {
			return errors.New("duplicate catalog release")
		}
		if _, exists := seenSequence[entry.Sequence]; exists {
			return errors.New("duplicate catalog release")
		}
		seenName[entry.Release] = struct{}{}
		seenSequence[entry.Sequence] = struct{}{}
		if entry.Sequence < lowest {
			lowest = entry.Sequence
		}
		if entry.Release == catalog.CurrentRelease {
			foundCurrent = true
			currentSequence = entry.Sequence
		}
	}
	if !foundCurrent || catalog.MinimumSafeSequence > lowest {
		return errors.New("invalid catalog coverage")
	}
	if len(catalog.CriticalBlocks) > maxCatalogCriticalBlocks {
		return errors.New("invalid critical blocks")
	}
	seenBlock := map[int64]struct{}{}
	for _, sequence := range catalog.CriticalBlocks {
		if sequence < 1 || sequence == currentSequence {
			return errors.New("invalid critical block")
		}
		if _, exists := seenBlock[sequence]; exists {
			return errors.New("invalid critical block")
		}
		seenBlock[sequence] = struct{}{}
	}
	return nil
}

func (entry CatalogRelease) validate() error {
	if !validProductReleaseName(entry.Release) || entry.Sequence < 1 || entry.ManifestLength < 1 || entry.ManifestLength > MaximumManifestBytes || !validSHA256(entry.ManifestSHA256) {
		return errors.New("invalid catalog release")
	}
	return validateManifestPath(entry.Release, entry.ManifestPath)
}

// Fresh reports whether the catalog is still inside its signed lifetime.
func (catalog Catalog) Fresh(now time.Time) bool {
	published, publishedOK := parseCanonicalUTC(catalog.PublishedAt)
	expires, expiresOK := parseCanonicalUTC(catalog.ExpiresAt)
	return publishedOK && expiresOK && !now.Before(published) && now.Before(expires)
}

// Allows reports whether a gateway-selected release is listed, digest-matched,
// at or above the minimum safe sequence, and not critically blocked.
func (catalog Catalog) Allows(release string, sequence int64, manifestSHA256 string) bool {
	if sequence < catalog.MinimumSafeSequence {
		return false
	}
	for _, blocked := range catalog.CriticalBlocks {
		if blocked == sequence {
			return false
		}
	}
	for _, entry := range catalog.Releases {
		if entry.Release == release && entry.Sequence == sequence && entry.ManifestSHA256 == manifestSHA256 {
			return true
		}
	}
	return false
}

func parseCanonicalUTC(value string) (time.Time, bool) {
	if !canonicalUTCTime(value) {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}
