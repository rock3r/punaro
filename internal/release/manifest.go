package release

import (
	"errors"
	"strings"
	"time"
)

// MaximumManifestBytes bounds one public release manifest.
const MaximumManifestBytes = 64 << 10

const (
	releaseDocumentSchema  = 1
	maxArtifacts           = 64
	maxSteppingStones      = 16
	maxSupportedFrom       = 32
	artifactModeExecutable = 0o755
	maxArtifactBytes       = 256 << 20
)

// ProductionPostgreSQLMajor is the exact database major bound to artifacts
// built from this source revision and to the release manifests it assembles.
const ProductionPostgreSQLMajor = 18

// ProtocolRange is an inclusive wire-protocol interval.
type ProtocolRange struct {
	Min int64 `json:"min"`
	Max int64 `json:"max"`
}

// Artifact is one native file published beneath the fixed origin.
type Artifact struct {
	Component string `json:"component"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	Path      string `json:"path"`
	Length    int64  `json:"length"`
	Mode      int    `json:"mode"`
	SHA256    string `json:"sha256"`
}

// ReleaseManifest is the immutable public document for one named release.
// The name stays distinct from the existing gateway Metadata type.
type ReleaseManifest struct { //nolint:revive // distinct from postgres Manifest and gateway Metadata.
	Schema                  int64         `json:"schema"`
	Sequence                int64         `json:"sequence"`
	Release                 string        `json:"release"`
	PublishedAt             string        `json:"published_at"`
	GatewayProtocol         ProtocolRange `json:"gateway_protocol"`
	ClientProtocol          ProtocolRange `json:"client_protocol"`
	MinimumRecoveryProtocol int64         `json:"minimum_recovery_protocol"`
	MinimumBootstrapRelease string        `json:"minimum_bootstrap_release"`
	Database                SchemaRange   `json:"database"`
	PostgreSQLMajor         int           `json:"postgres_major"`
	Image                   string        `json:"image,omitempty"`
	ReleaseSHA256           string        `json:"release_sha256,omitempty"`
	ComposeSHA256           string        `json:"compose_sha256"`
	MigrationManifestSHA256 string        `json:"migration_manifest_sha256"`
	Artifacts               []Artifact    `json:"artifacts"`
	SupportedFrom           []string      `json:"supported_from"`
	SteppingStones          []string      `json:"stepping_stones"`
}

// ParseReleaseManifest strictly parses one bounded public release manifest.
func ParseReleaseManifest(body []byte) (ReleaseManifest, error) {
	manifest, err := decodeStrict[ReleaseManifest](body, MaximumManifestBytes)
	if err != nil || manifest.validate() != nil {
		return ReleaseManifest{}, errors.New("release manifest is invalid")
	}
	return manifest, nil
}

func (manifest ReleaseManifest) validate() error {
	if manifest.Schema != releaseDocumentSchema || manifest.Sequence < 1 || !ValidProductReleaseName(manifest.Release) || !canonicalUTCTime(manifest.PublishedAt) {
		return errors.New("invalid release identity")
	}
	if !validProtocolRange(manifest.GatewayProtocol) || !validProtocolRange(manifest.ClientProtocol) || manifest.MinimumRecoveryProtocol < 1 || !ValidProductReleaseName(manifest.MinimumBootstrapRelease) {
		return errors.New("invalid protocol bound")
	}
	if err := validPublishedDatabase(manifest.Database, manifest.PostgreSQLMajor); err != nil {
		return err
	}
	if (manifest.Image == "") != (manifest.ReleaseSHA256 == "") {
		return errors.New("invalid image binding")
	}
	if manifest.Image != "" && (!validImageDigest(manifest.Image) || !validSHA256(manifest.ReleaseSHA256) || !imageDigestEquals(manifest.Image, manifest.ReleaseSHA256)) {
		return errors.New("invalid image binding")
	}
	if !validSHA256(manifest.ComposeSHA256) || !validSHA256(manifest.MigrationManifestSHA256) {
		return errors.New("invalid source digest")
	}
	if len(manifest.Artifacts) == 0 || len(manifest.Artifacts) > maxArtifacts {
		return errors.New("invalid artifacts")
	}
	seenIdentity := map[string]struct{}{}
	seenPath := map[string]struct{}{}
	for _, artifact := range manifest.Artifacts {
		if err := artifact.validate(manifest.Release); err != nil {
			return err
		}
		identity := artifact.Component + "/" + artifact.OS + "/" + artifact.Arch
		if _, exists := seenIdentity[identity]; exists {
			return errors.New("duplicate artifact")
		}
		if _, exists := seenPath[artifact.Path]; exists {
			return errors.New("duplicate artifact")
		}
		seenIdentity[identity] = struct{}{}
		seenPath[artifact.Path] = struct{}{}
	}
	if err := validReleaseNameList(manifest.SupportedFrom, maxSupportedFrom); err != nil {
		return err
	}
	if err := validReleaseNameList(manifest.SteppingStones, maxSteppingStones); err != nil {
		return err
	}
	return nil
}

func (artifact Artifact) validate(release string) error {
	if !knownComponent(artifact.Component) || !knownOS(artifact.OS) || !knownArch(artifact.Arch) {
		return errors.New("invalid artifact identity")
	}
	if artifact.Length < 1 || artifact.Length > maxArtifactBytes || artifact.Mode != artifactModeExecutable || !validSHA256(artifact.SHA256) {
		return errors.New("invalid artifact binding")
	}
	if err := validateArtifactPath(release, artifact.Path); err != nil {
		return err
	}
	component, osName, arch, err := parseArtifactFilename(artifact.Path[len(release)+1:])
	if err != nil || component != artifact.Component || osName != artifact.OS || arch != artifact.Arch {
		return errors.New("invalid artifact path")
	}
	return nil
}

// ValidProductReleaseName reports whether name is a canonical immutable
// product release identity accepted by signed manifests and catalogs.
func ValidProductReleaseName(name string) bool {
	return releaseNamePattern.MatchString(name) && !reservedReleaseName(name)
}

func validProtocolRange(value ProtocolRange) bool {
	return value.Min >= 1 && value.Max >= value.Min
}

func validPublishedDatabase(schema SchemaRange, postgresMajor int) error {
	if schema.Min < 1 || schema.Max < schema.Min || schema.Target < schema.Min || schema.Target > schema.Max || schema.RollbackFloor < schema.Min || schema.RollbackFloor > schema.Target {
		return errors.New("invalid schema boundary")
	}
	if postgresMajor < 1 {
		return errors.New("invalid PostgreSQL major")
	}
	return nil
}

func imageDigestEquals(image, digest string) bool {
	_, imageDigest, found := strings.Cut(image, "@sha256:")
	return found && imageDigest == digest
}

func canonicalUTCTime(value string) bool {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Location() != time.UTC {
		return false
	}
	return parsed.Format("2006-01-02T15:04:05Z") == value
}

func validReleaseNameList(names []string, limit int) error {
	if len(names) > limit {
		return errors.New("invalid release list")
	}
	seen := map[string]struct{}{}
	for _, name := range names {
		if !ValidProductReleaseName(name) {
			return errors.New("invalid release list")
		}
		if _, exists := seen[name]; exists {
			return errors.New("invalid release list")
		}
		seen[name] = struct{}{}
	}
	return nil
}
