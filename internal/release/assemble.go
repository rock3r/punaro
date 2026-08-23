package release

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// AssembleRequest is the local, content-free input for one unsigned publication.
type AssembleRequest struct {
	Directory               string
	Release                 string
	Sequence                int64
	PublishedAt             time.Time
	ExpiresAt               time.Time
	MinimumSafeSequence     int64
	CatalogSequence         int64
	Image                   string
	ComposeSHA256           string
	MigrationManifestSHA256 string
	Database                SchemaRange
	PostgreSQLMajor         int
	GatewayProtocol         ProtocolRange
	ClientProtocol          ProtocolRange
	MinimumRecoveryProtocol int64
	MinimumBootstrapRelease string
	SupportedFrom           []string
	SteppingStones          []string
	CriticalBlocks          []int64
	PreviousCatalog         *Catalog
}

// Assembled is the unsigned catalog/manifest pair written next to the artifacts.
type Assembled struct {
	Manifest     ReleaseManifest
	ManifestJSON []byte
	Catalog      Catalog
	CatalogJSON  []byte
}

// Assemble scans a directory of native artifacts and writes the unsigned
// catalog and manifest bootstrap will later verify. It performs no network I/O
// and does not sign.
func Assemble(request AssembleRequest) (Assembled, error) {
	if request.Directory == "" || !ValidProductReleaseName(request.Release) || request.Sequence < 1 || request.CatalogSequence < 1 {
		return Assembled{}, errors.New("release assembly is invalid")
	}
	publishedAt := request.PublishedAt.UTC().Format("2006-01-02T15:04:05Z")
	expiresAt := request.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z")
	artifacts, err := scanArtifacts(request.Directory, request.Release)
	if err != nil {
		return Assembled{}, err
	}
	manifest := ReleaseManifest{
		Schema:                  releaseDocumentSchema,
		Sequence:                request.Sequence,
		Release:                 request.Release,
		PublishedAt:             publishedAt,
		GatewayProtocol:         request.GatewayProtocol,
		ClientProtocol:          request.ClientProtocol,
		MinimumRecoveryProtocol: request.MinimumRecoveryProtocol,
		MinimumBootstrapRelease: request.MinimumBootstrapRelease,
		Database:                request.Database,
		PostgreSQLMajor:         request.PostgreSQLMajor,
		Image:                   request.Image,
		ComposeSHA256:           request.ComposeSHA256,
		MigrationManifestSHA256: request.MigrationManifestSHA256,
		Artifacts:               artifacts,
		SupportedFrom:           nonNilStrings(request.SupportedFrom),
		SteppingStones:          nonNilStrings(request.SteppingStones),
	}
	if manifest.Image != "" {
		_, digest, found := strings.Cut(manifest.Image, "@sha256:")
		if !found {
			return Assembled{}, errors.New("release assembly is invalid")
		}
		manifest.ReleaseSHA256 = digest
	}
	if err := manifest.validate(); err != nil {
		return Assembled{}, errors.New("release assembly is invalid")
	}
	manifestJSON, err := encodeDocument(manifest)
	if err != nil {
		return Assembled{}, err
	}
	sum := sha256.Sum256(manifestJSON)
	minimumSafe := request.MinimumSafeSequence
	if minimumSafe == 0 {
		minimumSafe = request.Sequence
		if request.PreviousCatalog != nil {
			minimumSafe = request.PreviousCatalog.MinimumSafeSequence
		}
	}
	criticalBlocks, releases, err := replacementCatalogEntries(request.PreviousCatalog, request.Release, request.Sequence, request.CatalogSequence, minimumSafe, request.CriticalBlocks, int64(len(manifestJSON)), hex.EncodeToString(sum[:]))
	if err != nil {
		return Assembled{}, errors.New("release assembly is invalid")
	}
	catalog := Catalog{
		Schema:              releaseDocumentSchema,
		Sequence:            request.CatalogSequence,
		PublishedAt:         publishedAt,
		ExpiresAt:           expiresAt,
		CurrentRelease:      request.Release,
		MinimumSafeSequence: minimumSafe,
		Releases:            releases,
		CriticalBlocks:      criticalBlocks,
	}
	if err := catalog.validate(); err != nil {
		return Assembled{}, errors.New("release assembly is invalid")
	}
	catalogJSON, err := encodeDocument(catalog)
	if err != nil {
		return Assembled{}, err
	}
	// #nosec G306 -- these documents are published next to the artifacts.
	if err := os.WriteFile(filepath.Join(request.Directory, ReleaseManifestFile), manifestJSON, 0o644); err != nil {
		return Assembled{}, err
	}
	// #nosec G306 -- these documents are published next to the artifacts.
	if err := os.WriteFile(filepath.Join(request.Directory, CatalogFile), catalogJSON, 0o644); err != nil {
		return Assembled{}, err
	}
	return Assembled{Manifest: manifest, ManifestJSON: manifestJSON, Catalog: catalog, CatalogJSON: catalogJSON}, nil
}

func replacementCatalogEntries(previous *Catalog, release string, sequence, catalogSequence, minimumSafe int64, requestedBlocks []int64, manifestLength int64, manifestSHA256 string) ([]int64, []CatalogRelease, error) {
	blocks := make([]int64, 0, len(requestedBlocks)+maxCatalogReleases)
	blocked := map[int64]bool{}
	for _, value := range requestedBlocks {
		if value < 1 || value == sequence || blocked[value] {
			return nil, nil, errors.New("invalid critical blocks")
		}
		blocked[value] = true
		if value < minimumSafe {
			continue
		}
		blocks = append(blocks, value)
	}
	if previous != nil {
		if previous.validate() != nil || catalogSequence <= previous.Sequence || minimumSafe < previous.MinimumSafeSequence {
			return nil, nil, errors.New("invalid previous catalog")
		}
		for _, value := range previous.CriticalBlocks {
			if value == sequence {
				return nil, nil, errors.New("current release is critically blocked")
			}
			if value < minimumSafe {
				continue
			}
			if !blocked[value] {
				blocked[value] = true
				blocks = append(blocks, value)
			}
		}
	}
	if len(blocks) > maxCatalogCriticalBlocks {
		return nil, nil, errors.New("too many critical blocks")
	}
	releases := make([]CatalogRelease, 0, maxCatalogReleases)
	if previous != nil {
		for _, entry := range previous.Releases {
			if sequence <= entry.Sequence || entry.Release == release {
				return nil, nil, errors.New("release sequence does not advance")
			}
			if entry.Sequence >= minimumSafe && !blocked[entry.Sequence] {
				releases = append(releases, entry)
			}
		}
	}
	releases = append(releases, CatalogRelease{Release: release, Sequence: sequence, ManifestPath: release + "/" + ReleaseManifestFile, ManifestLength: manifestLength, ManifestSHA256: manifestSHA256})
	if len(releases) > maxCatalogReleases {
		return nil, nil, errors.New("too many retained releases")
	}
	sort.Slice(releases, func(i, j int) bool { return releases[i].Sequence < releases[j].Sequence })
	sort.Slice(blocks, func(i, j int) bool { return blocks[i] < blocks[j] })
	return blocks, releases, nil
}

func scanArtifacts(directory, release string) ([]Artifact, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	var artifacts []Artifact
	for _, entry := range entries {
		if entry.IsDir() {
			return nil, errors.New("release assembly is invalid")
		}
		name := entry.Name()
		if name == ReleaseManifestFile || name == ReleaseSignatureFile || name == CatalogFile || name == CatalogSignatureFile {
			continue
		}
		component, osName, arch, err := parseArtifactFilename(name)
		if err != nil {
			return nil, errors.New("release assembly is invalid")
		}
		path := filepath.Join(directory, name)
		length, digest, err := hashRegularFile(path)
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, Artifact{
			Component: component,
			OS:        osName,
			Arch:      arch,
			Path:      release + "/" + name,
			Length:    length,
			Mode:      artifactModeExecutable,
			SHA256:    digest,
		})
	}
	if len(artifacts) == 0 {
		return nil, errors.New("release assembly is invalid")
	}
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Path < artifacts[j].Path })
	return artifacts, nil
}

func hashRegularFile(path string) (int64, string, error) {
	file, err := os.Open(path) // #nosec G304 -- assemble hashes explicit local artifact paths.
	if err != nil {
		return 0, "", err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return 0, "", errors.New("release assembly is invalid")
	}
	hash := sha256.New()
	written, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		return 0, "", errors.New("release assembly is invalid")
	}
	return written, hex.EncodeToString(hash.Sum(nil)), nil
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
