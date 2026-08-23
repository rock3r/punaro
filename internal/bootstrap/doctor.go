package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	punarodiagnostic "github.com/rock3r/punaro/internal/diagnostic"
	punarorelease "github.com/rock3r/punaro/internal/release"
)

const maximumDoctorSlotEntries = 128

const minimumDoctorFreeBytes uint64 = 512 << 20

// BootstrapProtocolVersion is the recovery/supervision protocol implemented
// by this bootstrap binary.
const BootstrapProtocolVersion int64 = 1

// DoctorRequest selects one bounded, read-only bootstrap inspection.
type DoctorRequest struct {
	Directory        string
	MachineID        string
	Origin           string
	Keys             map[string]ed25519.PublicKey
	GOOS             string
	GOARCH           string
	Now              time.Time
	HTTP             fetcher
	BootstrapRelease string
	FreeBytes        func(string) (uint64, error)
}

// Doctor verifies published slots, signed release authority, and service
// handoff without locking, repairing, downloading artifacts, or changing any
// bootstrap record.
func Doctor(ctx context.Context, request DoctorRequest) (punarodiagnostic.Report, error) {
	if request.Directory == "" || !filepath.IsAbs(request.Directory) || filepath.Clean(request.Directory) != request.Directory {
		return punarodiagnostic.Report{}, errors.New("bootstrap doctor request is invalid")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if request.Origin == "" {
		request.Origin = punarorelease.GitHubReleaseOrigin
	}
	if request.GOOS == "" {
		request.GOOS = runtime.GOOS
	}
	if request.GOARCH == "" {
		request.GOARCH = runtime.GOARCH
	}
	if request.Now.IsZero() {
		request.Now = time.Now().UTC()
	}
	identity := punarodiagnostic.Identity{MachineID: request.MachineID, Platform: request.GOOS + "-" + request.GOARCH}
	checks := make([]punarodiagnostic.Check, 0, 40)
	if err := requireTrustedBootstrapDirectory(request.Directory); err != nil {
		checks = append(checks, punarodiagnostic.Fail("bootstrap_directory", "repair_bootstrap_directory"))
		checks = append(checks, unavailableBootstrapStateChecks()...)
		return punarodiagnostic.New(punarodiagnostic.ComponentBootstrap, identity, checks)
	}
	checks = append(checks, punarodiagnostic.Pass("bootstrap_directory"))
	checks = append(checks, doctorLockCheck(request.Directory, lockFile, "bootstrap_lock", true))
	checks = append(checks, doctorLockCheck(request.Directory, runLeaseFile, "run_lock", false))
	freeBytes := request.FreeBytes
	if freeBytes == nil {
		freeBytes = doctorFreeBytes
	}
	available, diskErr := freeBytes(request.Directory)
	checks = append(checks, boolBootstrapCheck(diskErr == nil && available >= minimumDoctorFreeBytes, "disk_space", "free_bootstrap_disk_space"))

	keys := request.Keys
	if len(keys) == 0 {
		var err error
		keys, err = loadDirectoryKeys(request.Directory)
		if err != nil || len(keys) == 0 {
			checks = append(checks, punarodiagnostic.Fail("release_keys", "install_release_keys"))
		} else {
			checks = append(checks, punarodiagnostic.Pass("release_keys"))
		}
	} else {
		checks = append(checks, punarodiagnostic.Pass("release_keys"))
	}

	accepted, acceptedErr := loadAccepted(request.Directory)
	current, currentErr := readOptionalSlot(filepath.Join(request.Directory, currentSlot))
	previous, previousErr := readOptionalSlot(filepath.Join(request.Directory, previousSlot))
	if currentErr != nil || current.Release == "" {
		checks = append(checks, punarodiagnostic.Fail("current_slot", "reinstall_signed_release"))
	} else {
		checks = append(checks, punarodiagnostic.Pass("current_slot"))
		identity.Release = current.Release
		identity.ReleaseSequence = current.Sequence
	}
	switch {
	case previousErr != nil:
		checks = append(checks, punarodiagnostic.Fail("previous_slot", "repair_previous_slot"))
	case previous.Release == "":
		checks = append(checks, punarodiagnostic.OptionalUnavailable("previous_slot", "install_second_signed_release"))
	default:
		checks = append(checks, punarodiagnostic.Pass("previous_slot"))
	}
	if acceptedErr != nil || currentErr != nil || current.Release == "" || accepted.Release != current.Release || accepted.ReleaseSequence != current.Sequence || accepted.ManifestSHA256 != current.ManifestSHA256 {
		checks = append(checks, punarodiagnostic.Fail("accepted_state", "repair_bootstrap_state"))
	} else {
		checks = append(checks, punarodiagnostic.Pass("accepted_state"))
		identity.CatalogSequence = accepted.CatalogSequence
	}

	journal, journalErr := readJournal(request.Directory)
	if journalErr != nil || journal.Phase != "" {
		checks = append(checks, punarodiagnostic.Fail("journal_state", "resume_or_recover_bootstrap"))
	} else {
		checks = append(checks, punarodiagnostic.Pass("journal_state"))
	}
	recovery, recoveryErr := loadRecovery(request.Directory)
	if recoveryErr != nil || recovery.Mode == recoveryMode {
		checks = append(checks, punarodiagnostic.Fail("recovery_state", "recover_bootstrap"))
	} else {
		checks = append(checks, punarodiagnostic.Pass("recovery_state"))
	}
	checks = append(checks, absentBootstrapNodeCheck(request.Directory, candidateSlot, "candidate_state", "resume_or_recover_bootstrap"))
	checks = append(checks, absentBootstrapNodeCheck(request.Directory, swapSlot, "swap_state", "resume_or_recover_bootstrap"))

	catalog, catalogChecks, catalogOK := doctorCatalog(ctx, request, keys, accepted)
	checks = append(checks, catalogChecks...)
	var currentAdapterDigest string
	if currentErr == nil && current.Release != "" {
		var slotChecks []punarodiagnostic.Check
		currentAdapterDigest, slotChecks = doctorSlot(ctx, request, keys, catalog, catalogOK, "current", current, filepath.Join(request.Directory, currentSlot), true)
		checks = append(checks, slotChecks...)
	}
	if currentAdapterDigest != "" {
		identity.ArtifactDigest = "sha256:" + currentAdapterDigest
	}
	if previousErr == nil && previous.Release != "" {
		_, slotChecks := doctorSlot(ctx, request, keys, catalog, catalogOK, "previous", previous, filepath.Join(request.Directory, previousSlot), false)
		checks = append(checks, slotChecks...)
		if doctorSlotUsable(slotChecks, "previous") {
			checks = append(checks, punarodiagnostic.Pass("rollback_available"))
		} else {
			checks = append(checks, punarodiagnostic.Fail("rollback_available", "repair_previous_slot"))
		}
	} else {
		checks = append(checks, punarodiagnostic.OptionalUnavailable("previous_catalog_allowed", "install_second_signed_release"))
		checks = append(checks, punarodiagnostic.OptionalUnavailable("previous_critical_block", "install_second_signed_release"))
		checks = append(checks, punarodiagnostic.OptionalUnavailable("previous_manifest_signature", "install_second_signed_release"))
		checks = append(checks, punarodiagnostic.OptionalUnavailable("previous_platform_compatibility", "install_second_signed_release"))
		checks = append(checks, punarodiagnostic.OptionalUnavailable("previous_artifact_integrity", "install_second_signed_release"))
		checks = append(checks, punarodiagnostic.OptionalUnavailable("rollback_available", "install_second_signed_release"))
	}

	runningChecks := doctorRunningState(request, current, currentAdapterDigest)
	checks = append(checks, runningChecks...)
	return punarodiagnostic.New(punarodiagnostic.ComponentBootstrap, identity, checks)
}

func unavailableBootstrapStateChecks() []punarodiagnostic.Check {
	codes := []string{"bootstrap_lock", "run_lock", "disk_space", "release_keys", "accepted_state", "current_slot", "previous_slot", "journal_state", "recovery_state", "candidate_state", "swap_state", "catalog_reachability", "catalog_signature", "catalog_freshness", "catalog_sequence", "current_catalog_allowed", "current_critical_block", "current_manifest_signature", "current_platform_compatibility", "minimum_bootstrap_release", "minimum_recovery_protocol", "current_artifact_integrity", "previous_catalog_allowed", "previous_critical_block", "previous_manifest_signature", "previous_platform_compatibility", "previous_artifact_integrity", "rollback_available", "running_artifact", "supervisor_process", "candidate_health"}
	checks := make([]punarodiagnostic.Check, 0, len(codes))
	for _, code := range codes {
		checks = append(checks, punarodiagnostic.Unavailable(code, "repair_bootstrap_directory"))
	}
	return checks
}

func doctorLockCheck(directory, name, code string, requireAvailable bool) punarodiagnostic.Check {
	path := filepath.Join(directory, name)
	info, err := os.Lstat(path) // #nosec G703 -- fixed bootstrap child.
	if errors.Is(err, os.ErrNotExist) {
		return punarodiagnostic.Pass(code)
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return punarodiagnostic.Fail(code, "repair_bootstrap_lock_state")
	}
	file, err := os.Open(path) // #nosec G304 -- fixed validated bootstrap child, opened read-only.
	if err != nil {
		return punarodiagnostic.Fail(code, "repair_bootstrap_lock_state")
	}
	defer func() { _ = file.Close() }()
	lockErr := lockDirectoryFile(file)
	if lockErr == nil {
		unlockDirectoryFile(file)
	}
	if requireAvailable && lockErr != nil {
		return punarodiagnostic.Fail(code, "wait_for_bootstrap_operation")
	}
	return punarodiagnostic.Pass(code)
}

func absentBootstrapNodeCheck(directory, name, code, remediation string) punarodiagnostic.Check {
	_, err := os.Lstat(filepath.Join(directory, name)) // #nosec G703 -- fixed bootstrap child.
	if errors.Is(err, os.ErrNotExist) {
		return punarodiagnostic.Pass(code)
	}
	return punarodiagnostic.Fail(code, remediation)
}

func doctorCatalog(ctx context.Context, request DoctorRequest, keys map[string]ed25519.PublicKey, accepted acceptedState) (punarorelease.Catalog, []punarodiagnostic.Check, bool) {
	checks := make([]punarodiagnostic.Check, 0, 5)
	client := request.HTTP
	if client == nil {
		var err error
		client, err = newFetcher(request.Origin)
		if err != nil {
			return punarorelease.Catalog{}, []punarodiagnostic.Check{
				punarodiagnostic.Fail("catalog_reachability", "repair_release_origin"),
				punarodiagnostic.Unavailable("catalog_signature", "repair_release_origin"),
				punarodiagnostic.Unavailable("catalog_freshness", "repair_release_origin"),
				punarodiagnostic.Unavailable("catalog_sequence", "repair_release_origin"),
			}, false
		}
	}
	body, err := client.Get(ctx, punarorelease.CatalogReleaseName+"/"+punarorelease.CatalogFile, punarorelease.MaximumManifestBytes)
	if err != nil {
		return punarorelease.Catalog{}, []punarodiagnostic.Check{
			punarodiagnostic.Fail("catalog_reachability", "repair_release_origin"),
			punarodiagnostic.Unavailable("catalog_signature", "repair_release_origin"),
			punarodiagnostic.Unavailable("catalog_freshness", "repair_release_origin"),
			punarodiagnostic.Unavailable("catalog_sequence", "repair_release_origin"),
		}, false
	}
	signature, err := client.Get(ctx, punarorelease.CatalogReleaseName+"/"+punarorelease.CatalogSignatureFile, punarorelease.MaximumEnvelopeBytes)
	checks = append(checks, punarodiagnostic.Pass("catalog_reachability"))
	if err != nil || len(keys) == 0 || verifyDocument(body, signature, keys) != nil {
		return punarorelease.Catalog{}, append(checks,
			punarodiagnostic.Fail("catalog_signature", "repair_release_catalog"),
			punarodiagnostic.Unavailable("catalog_freshness", "repair_release_catalog"),
			punarodiagnostic.Unavailable("catalog_sequence", "repair_release_catalog"),
		), false
	}
	catalog, err := punarorelease.ParseCatalog(body)
	if err != nil {
		return punarorelease.Catalog{}, append(checks,
			punarodiagnostic.Fail("catalog_signature", "repair_release_catalog"),
			punarodiagnostic.Unavailable("catalog_freshness", "repair_release_catalog"),
			punarodiagnostic.Unavailable("catalog_sequence", "repair_release_catalog"),
		), false
	}
	checks = append(checks, punarodiagnostic.Pass("catalog_signature"))
	if catalog.Fresh(request.Now) {
		checks = append(checks, punarodiagnostic.Pass("catalog_freshness"))
	} else {
		checks = append(checks, punarodiagnostic.Fail("catalog_freshness", "refresh_release_catalog"))
	}
	if accepted.CatalogSequence == 0 || catalog.Sequence >= accepted.CatalogSequence {
		checks = append(checks, punarodiagnostic.Pass("catalog_sequence"))
	} else {
		checks = append(checks, punarodiagnostic.Fail("catalog_sequence", "repair_release_catalog"))
	}
	return catalog, checks, true
}

func doctorSlot(ctx context.Context, request DoctorRequest, keys map[string]ed25519.PublicKey, catalog punarorelease.Catalog, catalogOK bool, prefix string, slot slotState, directory string, required bool) (string, []punarodiagnostic.Check) {
	if slot.Release == localCheckoutRelease {
		digest, ok := verifyLocalCheckoutSlot(directory, request.GOOS, request.GOARCH, slot.ManifestSHA256)
		checks := []punarodiagnostic.Check{
			punarodiagnostic.Fail(prefix+"_critical_block", "install_signed_release"),
			punarodiagnostic.Fail(prefix+"_catalog_allowed", "install_signed_release"),
			punarodiagnostic.Unavailable(prefix+"_manifest_signature", "install_signed_release"),
			boolBootstrapCheck(ok, prefix+"_platform_compatibility", "install_platform_release"),
			boolBootstrapCheck(ok, prefix+"_artifact_integrity", "reinstall_signed_release"),
		}
		if prefix == "current" {
			checks = append(checks, punarodiagnostic.Unavailable("minimum_recovery_protocol", "install_signed_release"), punarodiagnostic.Unavailable("minimum_bootstrap_release", "install_signed_release"))
		}
		return digest, checks
	}
	if !catalogOK {
		checks := []punarodiagnostic.Check{
			punarodiagnostic.Unavailable(prefix+"_critical_block", "repair_release_catalog"),
			punarodiagnostic.Unavailable(prefix+"_catalog_allowed", "repair_release_catalog"),
			punarodiagnostic.Unavailable(prefix+"_manifest_signature", "repair_release_catalog"),
			punarodiagnostic.Unavailable(prefix+"_platform_compatibility", "repair_release_catalog"),
			punarodiagnostic.Unavailable(prefix+"_artifact_integrity", "repair_release_catalog"),
		}
		if prefix == "current" {
			checks = append(checks, punarodiagnostic.Unavailable("minimum_recovery_protocol", "repair_release_catalog"), punarodiagnostic.Unavailable("minimum_bootstrap_release", "repair_release_catalog"))
		}
		return "", checks
	}
	entry, found := catalogEntry(catalog, slot)
	blocked := catalogSequenceBlocked(catalog, slot.Sequence)
	if !found || !catalog.Allows(slot.Release, slot.Sequence, slot.ManifestSHA256) {
		blockCheck := punarodiagnostic.Pass(prefix + "_critical_block")
		if blocked {
			blockCheck = punarodiagnostic.Fail(prefix+"_critical_block", "install_unblocked_release")
		}
		checks := []punarodiagnostic.Check{
			blockCheck,
			punarodiagnostic.Fail(prefix+"_catalog_allowed", "install_allowed_release"),
			punarodiagnostic.Unavailable(prefix+"_manifest_signature", "install_allowed_release"),
			punarodiagnostic.Unavailable(prefix+"_platform_compatibility", "install_allowed_release"),
			punarodiagnostic.Unavailable(prefix+"_artifact_integrity", "install_allowed_release"),
		}
		if prefix == "current" {
			checks = append(checks, punarodiagnostic.Unavailable("minimum_recovery_protocol", "install_allowed_release"), punarodiagnostic.Unavailable("minimum_bootstrap_release", "install_allowed_release"))
		}
		return "", checks
	}
	checks := []punarodiagnostic.Check{punarodiagnostic.Pass(prefix + "_catalog_allowed"), punarodiagnostic.Pass(prefix + "_critical_block")}
	manifest, ok := doctorManifest(ctx, request, keys, entry, slot)
	if !ok {
		checks = append(checks,
			punarodiagnostic.Fail(prefix+"_manifest_signature", "repair_release_manifest"),
			punarodiagnostic.Unavailable(prefix+"_platform_compatibility", "repair_release_manifest"),
			punarodiagnostic.Unavailable(prefix+"_artifact_integrity", "repair_release_manifest"),
		)
		if prefix == "current" {
			checks = append(checks, punarodiagnostic.Unavailable("minimum_recovery_protocol", "repair_release_manifest"), punarodiagnostic.Unavailable("minimum_bootstrap_release", "repair_release_manifest"))
		}
		return "", checks
	}
	checks = append(checks, punarodiagnostic.Pass(prefix+"_manifest_signature"))
	compatibleArtifacts := platformArtifacts(manifest.Artifacts, request.GOOS, request.GOARCH)
	platformCompatible := len(compatibleArtifacts) > 0 && platformHasAdapter(compatibleArtifacts, request.GOOS, request.GOARCH)
	checks = append(checks, boolBootstrapCheck(platformCompatible, prefix+"_platform_compatibility", "install_platform_release"))
	if prefix == "current" {
		checks = append(checks,
			boolBootstrapCheck(manifest.MinimumRecoveryProtocol <= BootstrapProtocolVersion, "minimum_recovery_protocol", "upgrade_bootstrap_protocol"),
			boolBootstrapCheck(releaseAtLeast(request.BootstrapRelease, manifest.MinimumBootstrapRelease), "minimum_bootstrap_release", "upgrade_bootstrap_release"),
		)
	}
	digest, integrity := verifySignedSlot(directory, manifest, request.GOOS, request.GOARCH)
	check := boolBootstrapCheck(integrity, prefix+"_artifact_integrity", "reinstall_signed_release")
	if !required && !integrity {
		check.Required = true
	}
	checks = append(checks, check)
	return digest, checks
}

func catalogSequenceBlocked(catalog punarorelease.Catalog, sequence int64) bool {
	for _, blocked := range catalog.CriticalBlocks {
		if blocked == sequence {
			return true
		}
	}
	return false
}

func releaseAtLeast(current, minimum string) bool {
	currentVersion, currentPre, ok := parseDoctorRelease(current)
	if !ok {
		return false
	}
	minimumVersion, minimumPre, ok := parseDoctorRelease(minimum)
	if !ok {
		return false
	}
	for index := range currentVersion {
		if currentVersion[index] != minimumVersion[index] {
			return currentVersion[index] > minimumVersion[index]
		}
	}
	if currentPre == minimumPre {
		return true
	}
	if currentPre == "" {
		return true
	}
	if minimumPre == "" {
		return false
	}
	return comparePrerelease(currentPre, minimumPre) >= 0
}

func parseDoctorRelease(release string) ([3]int64, string, bool) {
	var version [3]int64
	if len(release) < 2 || release[0] != 'v' {
		return version, "", false
	}
	core := release[1:]
	if plus := strings.IndexByte(core, '+'); plus >= 0 {
		core = core[:plus]
	}
	pre := ""
	if dash := strings.IndexByte(core, '-'); dash >= 0 {
		pre, core = core[dash+1:], core[:dash]
		if !validDoctorPrerelease(pre) {
			return version, "", false
		}
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return version, "", false
	}
	for index, part := range parts {
		value, err := strconv.ParseInt(part, 10, 64)
		if err != nil || value < 0 || strconv.FormatInt(value, 10) != part {
			return version, "", false
		}
		version[index] = value
	}
	return version, pre, true
}

func validDoctorPrerelease(prerelease string) bool {
	if prerelease == "" {
		return false
	}
	for _, identifier := range strings.Split(prerelease, ".") {
		if identifier == "" {
			return false
		}
		numeric := true
		for _, character := range identifier {
			if character < '0' || character > '9' {
				numeric = false
			}
			if character != '-' && (character < '0' || character > '9') && (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') {
				return false
			}
		}
		if numeric && len(identifier) > 1 && identifier[0] == '0' {
			return false
		}
	}
	return true
}

func comparePrerelease(left, right string) int {
	leftParts, rightParts := strings.Split(left, "."), strings.Split(right, ".")
	for index := 0; index < len(leftParts) && index < len(rightParts); index++ {
		if leftParts[index] == rightParts[index] {
			continue
		}
		leftNumber, leftErr := strconv.ParseUint(leftParts[index], 10, 64)
		rightNumber, rightErr := strconv.ParseUint(rightParts[index], 10, 64)
		switch {
		case leftErr == nil && rightErr == nil:
			if leftNumber < rightNumber {
				return -1
			}
			return 1
		case leftErr == nil:
			return -1
		case rightErr == nil:
			return 1
		case leftParts[index] < rightParts[index]:
			return -1
		default:
			return 1
		}
	}
	if len(leftParts) < len(rightParts) {
		return -1
	}
	if len(leftParts) > len(rightParts) {
		return 1
	}
	return 0
}

func catalogEntry(catalog punarorelease.Catalog, slot slotState) (punarorelease.CatalogRelease, bool) {
	for _, entry := range catalog.Releases {
		if entry.Release == slot.Release && entry.Sequence == slot.Sequence && entry.ManifestSHA256 == slot.ManifestSHA256 {
			return entry, true
		}
	}
	return punarorelease.CatalogRelease{}, false
}

func doctorManifest(ctx context.Context, request DoctorRequest, keys map[string]ed25519.PublicKey, entry punarorelease.CatalogRelease, slot slotState) (punarorelease.ReleaseManifest, bool) {
	client := request.HTTP
	if client == nil {
		var err error
		client, err = newFetcher(request.Origin)
		if err != nil {
			return punarorelease.ReleaseManifest{}, false
		}
	}
	body, err := client.Get(ctx, entry.ManifestPath, entry.ManifestLength)
	if err != nil || int64(len(body)) != entry.ManifestLength {
		return punarorelease.ReleaseManifest{}, false
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != entry.ManifestSHA256 {
		return punarorelease.ReleaseManifest{}, false
	}
	signature, err := client.Get(ctx, entry.Release+"/"+punarorelease.ReleaseSignatureFile, punarorelease.MaximumEnvelopeBytes)
	if err != nil || len(keys) == 0 || verifyDocument(body, signature, keys) != nil {
		return punarorelease.ReleaseManifest{}, false
	}
	manifest, err := punarorelease.ParseReleaseManifest(body)
	if err != nil || manifest.Release != slot.Release || manifest.Sequence != slot.Sequence {
		return punarorelease.ReleaseManifest{}, false
	}
	return manifest, true
}

func verifySignedSlot(directory string, manifest punarorelease.ReleaseManifest, goos, goarch string) (string, bool) {
	artifacts := platformArtifacts(manifest.Artifacts, goos, goarch)
	if len(artifacts) == 0 || !platformHasAdapter(artifacts, goos, goarch) || len(artifacts)+1 > maximumDoctorSlotEntries {
		return "", false
	}
	expected := map[string]punarorelease.Artifact{}
	for _, artifact := range artifacts {
		name := filepath.Base(artifact.Path)
		if name != artifactName(artifact.Component, artifact.OS, artifact.Arch) {
			return "", false
		}
		expected[name] = artifact
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != len(expected)+1 || len(entries) > maximumDoctorSlotEntries {
		return "", false
	}
	var adapterDigest string
	for _, entry := range entries {
		if entry.Name() == slotRecord {
			continue
		}
		artifact, ok := expected[entry.Name()]
		if !ok {
			return "", false
		}
		digest, ok := hashExactArtifact(filepath.Join(directory, entry.Name()), artifact.Length, artifact.Mode)
		if !ok || digest != artifact.SHA256 {
			return "", false
		}
		if artifact.Component == adapterComponent {
			adapterDigest = digest
		}
	}
	return adapterDigest, adapterDigest != ""
}

func verifyLocalCheckoutSlot(directory, goos, goarch, expectedDigest string) (string, bool) {
	name := artifactName(adapterComponent, goos, goarch)
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 2 {
		return "", false
	}
	digest, ok := hashExactArtifact(filepath.Join(directory, name), -1, 0o755)
	return digest, ok && digest == expectedDigest
}

func hashExactArtifact(path string, expectedLength int64, expectedMode int) (string, bool) {
	info, err := os.Lstat(path) // #nosec G703 -- fixed manifest-selected slot child.
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || expectedLength >= 0 && info.Size() != expectedLength || runtime.GOOS != "windows" && int(info.Mode().Perm()) != expectedMode {
		return "", false
	}
	file, err := os.Open(path) // #nosec G304 -- fixed manifest-selected slot child.
	if err != nil {
		return "", false
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	written, err := io.Copy(hash, file)
	if err != nil || written != info.Size() {
		return "", false
	}
	return hex.EncodeToString(hash.Sum(nil)), true
}

func doctorRunningState(request DoctorRequest, current slotState, currentDigest string) []punarodiagnostic.Check {
	checks := make([]punarodiagnostic.Check, 0, 3)
	runningPath := filepath.Join(request.Directory, runningSlot, artifactName(adapterComponent, request.GOOS, request.GOARCH))
	runningDigest, runningOK := hashExactArtifact(runningPath, -1, 0o755)
	runningOK = runningOK && currentDigest != "" && runningDigest == currentDigest
	checks = append(checks, boolBootstrapCheck(runningOK, "running_artifact", "restart_adapter_service"))
	record, err := loadRunPID(request.Directory)
	processOK := err == nil && record.PID > 0 && filepath.Clean(record.Path) == runningPath && matchProcessImage(record.PID, record.Path) == processImageMatch
	checks = append(checks, boolBootstrapCheck(processOK, "supervisor_process", "restart_adapter_service"))
	_, readyErr := readReadyFile(filepath.Join(request.Directory, readyFile))
	checks = append(checks, boolBootstrapCheck(readyErr == nil && current.Release != "", "candidate_health", "restart_adapter_service"))
	return checks
}

func boolBootstrapCheck(ok bool, code, remediation string) punarodiagnostic.Check {
	if ok {
		return punarodiagnostic.Pass(code)
	}
	return punarodiagnostic.Fail(code, remediation)
}

func doctorSlotUsable(checks []punarodiagnostic.Check, prefix string) bool {
	for _, wanted := range []string{prefix + "_catalog_allowed", prefix + "_manifest_signature", prefix + "_artifact_integrity"} {
		found := false
		for _, check := range checks {
			if check.Code == wanted {
				found = check.Status == punarodiagnostic.StatusPass
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
