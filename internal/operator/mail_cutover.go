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
	if installation.RelayMachinesJSON == "" {
		return Installation{}, errors.New("mail cutover relay enrollment is unavailable")
	}
	installation.MailCutover = &publication
	return publishMailCutoverInstallation(directory, installation, afterStep)
}

// ConfigureMailCutoverRelayMachines durably records the exact non-secret
// static relay authority before any irreversible source transition begins.
func ConfigureMailCutoverRelayMachines(directory, enrollmentFile string) (Installation, error) {
	canonical, err := ReadRelayMachinesFile(enrollmentFile)
	if err != nil {
		return Installation{}, err
	}
	installation, err := LoadMailCutoverRecovery(directory)
	if err != nil {
		return Installation{}, err
	}
	if installation.RelayMachinesJSON != "" {
		if installation.RelayMachinesJSON != canonical {
			return Installation{}, errors.New("mail cutover relay enrollment conflicts with the installation")
		}
		return installation, nil
	}
	if installation.MailCutover != nil {
		return Installation{}, errors.New("active mail cutover relay enrollment cannot change")
	}
	installation.RelayMachinesJSON = canonical
	return publishMailCutoverInstallation(directory, installation, nil)
}

// ConfigureRelayMachines replaces the complete public relay enrollment set.
// It is the supported authority for adding or revoking a client from a unified
// installation; callers provide a protected declarative file rather than
// editing generated runtime configuration.
func ConfigureRelayMachines(directory, enrollmentFile string) (Installation, error) {
	canonical, err := ReadRelayMachinesFile(enrollmentFile)
	if err != nil {
		return Installation{}, err
	}
	installation, err := LoadMailCutoverRecovery(directory)
	if err != nil {
		return Installation{}, err
	}
	markerStage := filepath.Join(directory, ".installation.mail-cutover.json")
	if _, err := os.Lstat(markerStage); err == nil {
		candidate, err := readInstallation(markerStage)
		if err != nil || !candidate.RelayEnabled || candidate.RelayMachinesJSON != canonical {
			return Installation{}, errors.New("relay enrollment recovery requires the exact requested enrollment")
		}
		candidate.Directory = directory
		return publishMailCutoverInstallation(directory, candidate, nil)
	} else if !errors.Is(err, os.ErrNotExist) {
		return Installation{}, errors.New("relay enrollment recovery is unavailable")
	}
	if installation.RelayEnabled && installation.RelayMachinesJSON == canonical {
		return installation, nil
	}
	if _, err := validateStatic(InitOptions{Directory: directory, DataDir: installation.DataDir, BackupDir: installation.BackupDir, Image: installation.Image, OwnerDSNFile: installation.OwnerDSNFile, AppDSNFile: installation.AppDSNFile, OwnerName: installation.OwnerName, Ingress: installation.Ingress, HealthListenAddr: installation.HealthListenAddr, MemoryAPIEnabled: installation.MemoryAPIEnabled, MemoryMutationsEnabled: installation.MemoryMutationsEnabled, TrustedAttachmentsEnabled: installation.TrustedAttachmentsEnabled, TrustedAttachmentBlobDir: installation.TrustedAttachmentBlobDir, RelayEnabled: true, RelayMachinesJSON: canonical}); err != nil {
		return Installation{}, errors.New("relay enrollment is incompatible with the installation")
	}
	installation.RelayEnabled = true
	installation.RelayMachinesJSON = canonical
	return publishMailCutoverInstallation(directory, installation, nil)
}

// ReadRelayMachinesFile loads a protected, bounded relay enrollment file for
// either initial installation or an explicit mail-cutover transition.
func ReadRelayMachinesFile(enrollmentFile string) (string, error) {
	if !filepath.IsAbs(enrollmentFile) || filepath.Clean(enrollmentFile) != enrollmentFile || requireTrustedProtectedFile(enrollmentFile, maxRelayMachinesBytes) != nil {
		return "", errors.New("relay enrollment file is unavailable")
	}
	body, err := os.ReadFile(enrollmentFile) // #nosec G304 -- explicit protected operator input.
	if err != nil {
		return "", errors.New("relay enrollment file is unavailable")
	}
	canonical, err := canonicalRelayMachinesJSON(string(body))
	if err != nil {
		return "", err
	}
	return canonical, nil
}

func publishMailCutoverInstallation(directory string, installation Installation, afterStep func(string) error) (Installation, error) {
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
	markerStage := filepath.Join(directory, ".installation.mail-cutover.json")
	_, stageErr := os.Lstat(markerStage)
	if stageErr != nil && !errors.Is(stageErr, os.ErrNotExist) {
		return Installation{}, errors.New("mail cutover recovery marker is unavailable")
	}
	failures := CheckPaths(base)
	if len(failures) == 0 && errors.Is(stageErr, os.ErrNotExist) {
		return base, nil
	}
	allowed := []string{"generated Compose override does not match installation configuration", "generated daemon environment does not match installation configuration"}
	for _, failure := range failures {
		if !slices.Contains(allowed, failure) {
			return Installation{}, errors.New("mail cutover recovery paths are not safe")
		}
	}
	candidate, err := readInstallation(markerStage)
	if err != nil || candidate.MailCutover != nil && candidate.MailCutover.Validate() != nil || candidate.RelayMachinesJSON != "" && validateRelayMachinesJSON(candidate.RelayMachinesJSON) != nil {
		return Installation{}, errors.New("mail cutover recovery marker is unavailable")
	}
	candidate.Directory = directory
	baseComparable, candidateComparable := base, candidate
	baseComparable.MailCutover, candidateComparable.MailCutover = nil, nil
	baseComparable.RelayMachinesJSON, candidateComparable.RelayMachinesJSON = "", ""
	baseComparable.RelayEnabled, candidateComparable.RelayEnabled = false, false
	if baseComparable != candidateComparable {
		return Installation{}, errors.New("mail cutover recovery marker does not match the installation")
	}
	cutoverAdvance := base.MailCutover == nil && candidate.MailCutover != nil && base.RelayMachinesJSON == candidate.RelayMachinesJSON
	initialEnrollmentAdvance := base.MailCutover == nil && candidate.MailCutover == nil && base.RelayMachinesJSON == "" && candidate.RelayMachinesJSON != ""
	relayEnableAdvance := !base.RelayEnabled && candidate.RelayEnabled && base.RelayMachinesJSON == "" && candidate.RelayMachinesJSON != "" && sameMailCutoverPublication(base.MailCutover, candidate.MailCutover)
	// A live unified relay may change only its complete public enrollment set
	// before mail cutover. The staged candidate still has to match every other
	// installation invariant, so a crash can recover only this exact update.
	relayEnrollmentAdvance := base.RelayEnabled && candidate.RelayEnabled && base.RelayMachinesJSON != candidate.RelayMachinesJSON && sameMailCutoverPublication(base.MailCutover, candidate.MailCutover)
	if !cutoverAdvance && !initialEnrollmentAdvance && !relayEnableAdvance && !relayEnrollmentAdvance {
		return Installation{}, errors.New("mail cutover recovery marker transition is invalid")
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
		legacyOld, preTrustedAttachmentsOld, preMemoryAPIOld, preMemoryMutationsOld := "", "", "", ""
		if !base.TrustedAttachmentsEnabled {
			if file.path == EnvFile(directory) {
				preTrustedAttachmentsOld = preTrustedAttachmentsDaemonEnv(base)
			} else {
				preTrustedAttachmentsOld = preTrustedAttachmentsComposeOverride()
			}
		}
		if !base.TrustedAttachmentsEnabled && !base.MemoryMutationsEnabled {
			if file.path == EnvFile(directory) {
				preMemoryMutationsOld = preMemoryMutationsDaemonEnv(base)
			} else {
				preMemoryMutationsOld = preMemoryMutationsComposeOverride()
			}
		}
		if !base.TrustedAttachmentsEnabled && !base.MemoryAPIEnabled {
			if file.path == EnvFile(directory) {
				preMemoryAPIOld = preMemoryAPIDaemonEnv(base)
			} else {
				preMemoryAPIOld = preMemoryAPIComposeOverride()
			}
		}
		if !base.TrustedAttachmentsEnabled && !base.MemoryAPIEnabled && base.MailCutover == nil && base.RelayMachinesJSON == "" {
			if file.path == EnvFile(directory) {
				legacyOld = legacyDaemonEnv(base)
			} else {
				legacyOld = legacyComposeOverride()
			}
		}
		if err != nil || string(body) != file.old && string(body) != file.intended && string(body) != preTrustedAttachmentsOld && string(body) != preMemoryMutationsOld && string(body) != preMemoryAPIOld && string(body) != legacyOld {
			return Installation{}, errors.New("mail cutover recovery file does not match either durable state")
		}
	}
	return base, nil
}

func sameMailCutoverPublication(left, right *MailCutoverPublication) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}
