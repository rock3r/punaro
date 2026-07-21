package operator

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"

	"github.com/google/uuid"
)

var mailCutoverPublicationDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// MailCutoverPublication is the content-free, marker-last local authority
// publication. Its presence selects PostgreSQL and the migrated-credential
// transition runtime; absence selects the pre-cutover SQLite runtime.
type MailCutoverPublication struct {
	Version           int    `json:"version"`
	EpochID           string `json:"epoch_id"`
	TargetIdentity    string `json:"target_identity"`
	SourceFingerprint string `json:"source_fingerprint"`
}

// Validate rejects incomplete or noncanonical publication bindings.
func (p MailCutoverPublication) Validate() error {
	if p.Version != 1 || uuid.Validate(p.EpochID) != nil || !mailCutoverPublicationDigest.MatchString(p.TargetIdentity) || !mailCutoverPublicationDigest.MatchString(p.SourceFingerprint) {
		return errors.New("invalid mail cutover publication")
	}
	return nil
}

// PublishMailCutover atomically replaces the generated environment and
// Compose inputs, then publishes installation.json last. Exact retries recover
// crashes at any earlier publication boundary; changed retries fail closed.
func PublishMailCutover(directory string, publication MailCutoverPublication) (Installation, error) {
	return publishMailCutover(directory, publication, nil)
}

func publishMailCutover(directory string, publication MailCutoverPublication, afterStep func(string) error) (Installation, error) {
	if publication.Validate() != nil {
		return Installation{}, errors.New("mail cutover publication is invalid")
	}
	installation, err := Load(directory)
	if err != nil {
		return Installation{}, err
	}
	if installation.MailCutover != nil {
		if *installation.MailCutover != publication {
			return Installation{}, errors.New("mail cutover publication conflicts with the active marker")
		}
		if failures := CheckPaths(installation); len(failures) != 0 {
			return Installation{}, errors.New("published mail cutover files are inconsistent")
		}
		return installation, nil
	}
	installation.MailCutover = &publication
	envStage := filepath.Join(directory, ".punarod.env.mail-cutover")
	overrideStage := filepath.Join(directory, ".compose.operator.mail-cutover.yaml")
	markerStage := filepath.Join(directory, ".installation.mail-cutover.json")
	// Preserve an exact durable candidate across recovery retries. Once either
	// runtime file has switched, deleting this candidate would remove the only
	// proof that a marker-last recovery is safe.
	if _, statErr := os.Lstat(markerStage); errors.Is(statErr, os.ErrNotExist) {
		if err := writeExclusiveJSON(markerStage, installation); err != nil {
			return Installation{}, errors.New("mail cutover marker cannot be staged")
		}
	} else if statErr != nil {
		return Installation{}, errors.New("mail cutover publication staging cannot be recovered")
	} else {
		candidate, readErr := readInstallation(markerStage)
		if readErr != nil {
			return Installation{}, errors.New("mail cutover publication staging cannot be recovered")
		}
		candidateJSON, candidateErr := json.Marshal(candidate)
		installationJSON, installationErr := json.Marshal(installation)
		if candidateErr != nil || installationErr != nil || !bytes.Equal(candidateJSON, installationJSON) {
			return Installation{}, errors.New("mail cutover publication staging conflicts with the requested marker")
		}
	}
	if afterStep != nil {
		if err := afterStep("candidate"); err != nil {
			return Installation{}, err
		}
	}
	for _, path := range []string{envStage, overrideStage} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return Installation{}, errors.New("mail cutover publication staging cannot be recovered")
		}
	}
	if afterStep != nil {
		if err := afterStep("stages-cleared"); err != nil {
			return Installation{}, err
		}
	}
	if err := writeExclusive(envStage, []byte(daemonEnv(installation))); err != nil {
		return Installation{}, errors.New("mail cutover environment cannot be staged")
	}
	if afterStep != nil {
		if err := afterStep("environment-staged"); err != nil {
			return Installation{}, err
		}
	}
	if err := writeExclusive(overrideStage, []byte(composeOverride())); err != nil {
		return Installation{}, errors.New("mail cutover Compose override cannot be staged")
	}
	if afterStep != nil {
		if err := afterStep("override-staged"); err != nil {
			return Installation{}, err
		}
	}
	if err := syncDirectory(directory); err != nil {
		return Installation{}, errors.New("mail cutover staging cannot be made durable")
	}
	if afterStep != nil {
		if err := afterStep("staging-synced"); err != nil {
			return Installation{}, err
		}
		if err := afterStep("staged"); err != nil {
			return Installation{}, err
		}
	}
	if err := os.Rename(envStage, EnvFile(directory)); err != nil {
		return Installation{}, errors.New("mail cutover environment cannot be published")
	}
	if afterStep != nil {
		if err := afterStep("environment"); err != nil {
			return Installation{}, err
		}
	}
	if err := os.Rename(overrideStage, OverrideFile(directory)); err != nil {
		return Installation{}, errors.New("mail cutover Compose override cannot be published")
	}
	if afterStep != nil {
		if err := afterStep("override"); err != nil {
			return Installation{}, err
		}
	}
	if err := syncDirectory(directory); err != nil {
		return Installation{}, errors.New("mail cutover runtime publication durability failed")
	}
	if err := os.Rename(markerStage, ConfigFile(directory)); err != nil {
		return Installation{}, errors.New("mail cutover database is active; rerun publication recovery")
	}
	if err := syncDirectory(directory); err != nil {
		return Installation{}, errors.New("mail cutover marker durability failed")
	}
	if afterStep != nil {
		if err := afterStep("marker"); err != nil {
			return Installation{}, err
		}
	}
	return installation, nil
}

// LoadMailCutoverRecovery accepts only an exact marker-last publication
// interruption: trusted base installation, intact staged candidate marker, and
// generated files equal to either the old or exact candidate state.
func LoadMailCutoverRecovery(directory string) (Installation, error) {
	base, err := Load(directory)
	if err != nil {
		return Installation{}, err
	}
	failures := CheckPaths(base)
	if len(failures) == 0 {
		return base, nil
	}
	allowed := []string{"generated Compose override does not match installation configuration", "generated daemon environment does not match installation configuration"}
	for _, failure := range failures {
		if !slices.Contains(allowed, failure) {
			return Installation{}, errors.New("mail cutover recovery paths are not safe")
		}
	}
	markerStage := filepath.Join(directory, ".installation.mail-cutover.json")
	candidate, err := readInstallation(markerStage)
	if err != nil || candidate.MailCutover == nil || candidate.MailCutover.Validate() != nil {
		return Installation{}, errors.New("mail cutover recovery marker is unavailable")
	}
	candidate.Directory = directory
	baseComparable, candidateComparable := base, candidate
	baseComparable.MailCutover, candidateComparable.MailCutover = nil, nil
	if baseComparable != candidateComparable {
		return Installation{}, errors.New("mail cutover recovery marker does not match the installation")
	}
	for _, file := range []struct {
		path          string
		old, intended string
	}{
		{path: EnvFile(directory), old: daemonEnv(base), intended: daemonEnv(candidate)},
		{path: OverrideFile(directory), old: composeOverride(), intended: composeOverride()},
	} {
		if err := requireTrustedProtectedFile(file.path, 64<<10); err != nil {
			return Installation{}, errors.New("mail cutover recovery file is unavailable")
		}
		body, err := os.ReadFile(file.path) // #nosec G304 -- validated fixed generated path.
		if err != nil || string(body) != file.old && string(body) != file.intended {
			return Installation{}, errors.New("mail cutover recovery file does not match either durable state")
		}
	}
	return base, nil
}
