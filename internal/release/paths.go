package release

import (
	"errors"
	"strings"
)

const (
	// GitHubReleaseOrigin is the fixed HTTPS origin bootstrap will use. Paths
	// beneath it are relative names; the gateway never supplies a URL.
	GitHubReleaseOrigin = "https://github.com/rock3r/punaro/releases/download"
	// CatalogReleaseName is the dedicated GitHub Release tag that holds the
	// short-lived signed catalog. It is not a product release.
	CatalogReleaseName   = "catalog"
	ReleaseManifestFile  = "punaro-release.json"
	ReleaseSignatureFile = "punaro-release.sig"
	CatalogFile          = "punaro-catalog.json"
	CatalogSignatureFile = "punaro-catalog.sig"

	maxPathComponent  = 128
	latestReleaseName = "latest"
)

var reservedReleaseNames = map[string]struct{}{
	latestReleaseName:  {},
	CatalogReleaseName: {},
}

func reservedReleaseName(name string) bool {
	_, reserved := reservedReleaseNames[name]
	return reserved
}

// ValidateRelativePath accepts one two-component path beneath the fixed
// origin. It rejects schemes, hosts, credentials, queries, fragments, parent
// directories, and the mutable GitHub "latest" pointer.
func ValidateRelativePath(path string) error {
	if path == "" || strings.ContainsAny(path, `:?#@\`) || strings.Contains(path, "://") || strings.HasPrefix(path, "/") {
		return errors.New("release path is invalid")
	}
	parts := strings.Split(path, "/")
	if len(parts) != 2 {
		return errors.New("release path is invalid")
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || len(part) > maxPathComponent || !releaseNamePattern.MatchString(part) {
			return errors.New("release path is invalid")
		}
	}
	if parts[0] == latestReleaseName {
		return errors.New("release path is invalid")
	}
	return nil
}

func validateArtifactPath(release, path string) error {
	if err := ValidateRelativePath(path); err != nil {
		return err
	}
	prefix := release + "/"
	if !strings.HasPrefix(path, prefix) {
		return errors.New("release path is invalid")
	}
	if _, _, _, err := parseArtifactFilename(strings.TrimPrefix(path, prefix)); err != nil {
		return err
	}
	return nil
}

func validateManifestPath(release, path string) error {
	if err := ValidateRelativePath(path); err != nil {
		return err
	}
	if path != release+"/"+ReleaseManifestFile {
		return errors.New("release path is invalid")
	}
	return nil
}
