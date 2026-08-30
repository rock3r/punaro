package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	punarodiagnostic "github.com/rock3r/punaro/internal/diagnostic"
)

func TestDoctorVerifiesSignedSlotWithoutMutatingBootstrapState(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH})
	directory := privateDir(t)
	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	if _, err := Update(Request{Directory: directory, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: now}); err != nil {
		t.Fatal(err)
	}
	before := bootstrapTreeDigest(t, directory)
	report, err := Doctor(t.Context(), DoctorRequest{Directory: directory, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: now, BootstrapRelease: "v0.1.0", FreeBytes: func(string) (uint64, error) { return 1 << 40, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if report.Component != punarodiagnostic.ComponentBootstrap || report.Identity.Release != "v0.1.0" || report.Identity.ReleaseSequence != 1 || report.Identity.CatalogSequence != 1 || report.Identity.Protocol != BootstrapProtocolVersion || report.Identity.ArtifactDigest == "" {
		t.Fatalf("report=%#v", report)
	}
	for _, code := range []string{"bootstrap_directory", "bootstrap_lock", "run_lock", "disk_space", "release_keys", "catalog_signature", "catalog_freshness", "accepted_state", "current_slot", "current_catalog_allowed", "current_critical_block", "current_manifest_signature", "current_platform_compatibility", "current_artifact_integrity", "minimum_bootstrap_release", "minimum_recovery_protocol", "journal_state", "recovery_state"} {
		if doctorCheckStatus(report, code) != punarodiagnostic.StatusPass {
			t.Fatalf("check %s report=%#v", code, report)
		}
	}
	if after := bootstrapTreeDigest(t, directory); after != before {
		t.Fatalf("doctor mutated bootstrap state\nbefore=%s\nafter=%s", before, after)
	}
}

func TestDoctorAcceptsExplicitRollbackHighWaterStateWithoutMutation(t *testing.T) {
	origin, directory, now, _ := doctorRollbackFixture(t)
	if _, err := Rollback(directory); err != nil {
		t.Fatal(err)
	}
	assertDoctorAcceptsRollbackHighWater(t, origin, directory, now)
}

func TestDoctorAcceptsAutomaticRollbackHighWaterStateWithoutMutation(t *testing.T) {
	origin, directory, now, current := doctorRollbackFixture(t)
	unlocked, rolled, err := rollbackIfAllowed(t.Context(), RunRequest{
		Directory: directory,
		Origin:    origin.URL,
		Keys:      origin.Keys,
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
		Now:       now,
	}, current)
	if err != nil || !unlocked || rolled.Release != "v0.1.0" {
		t.Fatalf("automatic rollback unlocked=%t rolled=%#v err=%v", unlocked, rolled, err)
	}
	assertDoctorAcceptsRollbackHighWater(t, origin, directory, now)
}

func TestDoctorRejectsInvalidRollbackEvidenceWithoutMutation(t *testing.T) {
	tests := []struct {
		name               string
		body               func(*testing.T, slotState) []byte
		remove             bool
		autoRollbackStatus punarodiagnostic.Status
	}{
		{
			name: "missing",
			body: func(*testing.T, slotState) []byte {
				return nil
			},
			remove:             true,
			autoRollbackStatus: punarodiagnostic.StatusPass,
		},
		{
			name: "malformed",
			body: func(*testing.T, slotState) []byte {
				return []byte(`{"schema":1`)
			},
			autoRollbackStatus: punarodiagnostic.StatusFail,
		},
		{
			name: "oversized",
			body: func(*testing.T, slotState) []byte {
				return []byte(strings.Repeat("x", maximumDoctorStateBytes+1))
			},
			autoRollbackStatus: punarodiagnostic.StatusFail,
		},
		{
			name: "identity mismatch",
			body: func(t *testing.T, rolledAway slotState) []byte {
				t.Helper()
				body, err := json.Marshal(autoRollbackState{
					Schema:         1,
					Release:        rolledAway.Release,
					Sequence:       rolledAway.Sequence,
					ManifestSHA256: rolledAway.ManifestSHA256,
					Generation:     rolledAway.Generation + 1,
				})
				if err != nil {
					t.Fatal(err)
				}
				return body
			},
			autoRollbackStatus: punarodiagnostic.StatusPass,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			origin, directory, now, rolledAway := doctorRollbackFixture(t)
			if _, err := Rollback(directory); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, autoRollbackFile)
			if test.remove {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(path, test.body(t, rolledAway), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			before := bootstrapTreeDigest(t, directory)
			report, err := Doctor(t.Context(), DoctorRequest{Directory: directory, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: now, BootstrapRelease: "v0.1.0", FreeBytes: func(string) (uint64, error) { return 1 << 40, nil }})
			if err != nil {
				t.Fatal(err)
			}
			if doctorCheckStatus(report, "auto_rollback_state") != test.autoRollbackStatus || doctorCheckStatus(report, "accepted_state") != punarodiagnostic.StatusFail {
				t.Fatalf("invalid rollback evidence passed: report=%#v", report)
			}
			if after := bootstrapTreeDigest(t, directory); after != before {
				t.Fatalf("doctor mutated invalid rollback evidence\nbefore=%s\nafter=%s", before, after)
			}
		})
	}
}

func TestDoctorRejectsRollbackEvidenceWithoutCurrentSlot(t *testing.T) {
	origin, directory, now, _ := doctorRollbackFixture(t)
	if _, err := Rollback(directory); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(directory, currentSlot)); err != nil {
		t.Fatal(err)
	}
	before := bootstrapTreeDigest(t, directory)
	report, err := Doctor(t.Context(), DoctorRequest{Directory: directory, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: now, BootstrapRelease: "v0.1.0", FreeBytes: func(string) (uint64, error) { return 1 << 40, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if doctorCheckStatus(report, "current_slot") != punarodiagnostic.StatusFail || doctorCheckStatus(report, "accepted_state") != punarodiagnostic.StatusFail {
		t.Fatalf("rollback evidence without current slot passed: report=%#v", report)
	}
	if after := bootstrapTreeDigest(t, directory); after != before {
		t.Fatalf("doctor mutated missing-current evidence\nbefore=%s\nafter=%s", before, after)
	}
}

func TestDoctorRejectsRollbackHighWaterOlderThanCurrent(t *testing.T) {
	origin, directory, now, _ := doctorRollbackFixture(t)
	if _, err := Rollback(directory); err != nil {
		t.Fatal(err)
	}
	current, err := readSlot(filepath.Join(directory, currentSlot))
	if err != nil {
		t.Fatal(err)
	}
	current.Release = "v0.3.0"
	current.Sequence = 3
	current.ManifestSHA256 = strings.Repeat("d", 64)
	body, err := json.Marshal(current)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, currentSlot, slotRecord), body, 0o600); err != nil {
		t.Fatal(err)
	}
	before := bootstrapTreeDigest(t, directory)
	report, err := Doctor(t.Context(), DoctorRequest{Directory: directory, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: now, BootstrapRelease: "v0.1.0", FreeBytes: func(string) (uint64, error) { return 1 << 40, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if doctorCheckStatus(report, "accepted_state") != punarodiagnostic.StatusFail {
		t.Fatalf("accepted state older than current passed: report=%#v", report)
	}
	if after := bootstrapTreeDigest(t, directory); after != before {
		t.Fatalf("doctor mutated sequence-conflict evidence\nbefore=%s\nafter=%s", before, after)
	}
}

func doctorRollbackFixture(t *testing.T) (*signedOrigin, string, time.Time, slotState) {
	t.Helper()
	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	origin := newSignedOrigin(t, originSpec{payload: "previous-adapter", goos: runtime.GOOS, goarch: runtime.GOARCH, release: "v0.1.0", sequence: 1, catalogSequence: 1})
	directory := privateDir(t)
	request := Request{Directory: directory, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: now}
	if _, err := Update(request); err != nil {
		t.Fatal(err)
	}
	previous, err := readSlot(filepath.Join(directory, currentSlot))
	if err != nil {
		t.Fatal(err)
	}
	previousFiles := make(map[string][]byte)
	for name, body := range origin.Files {
		if strings.HasPrefix(name, previous.Release+"/") {
			previousFiles[name] = body
		}
	}
	origin.republish(t, originSpec{payload: "current-adapter", goos: runtime.GOOS, goarch: runtime.GOARCH, release: "v0.2.0", sequence: 2, catalogSequence: 2})
	for name, body := range previousFiles {
		origin.Files[name] = body
	}
	allowPreviousInCatalog(t, origin, previous.Release, previous.Sequence, previous.ManifestSHA256)
	if _, err := Update(request); err != nil {
		t.Fatal(err)
	}
	current, err := readSlot(filepath.Join(directory, currentSlot))
	if err != nil {
		t.Fatal(err)
	}
	return origin, directory, now, current
}

func assertDoctorAcceptsRollbackHighWater(t *testing.T, origin *signedOrigin, directory string, now time.Time) {
	t.Helper()
	accepted, err := loadAccepted(directory)
	if err != nil {
		t.Fatal(err)
	}
	before := bootstrapTreeDigest(t, directory)
	report, err := Doctor(t.Context(), DoctorRequest{Directory: directory, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: now, BootstrapRelease: "v0.1.0", FreeBytes: func(string) (uint64, error) { return 1 << 40, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if report.Identity.Release != "v0.1.0" || report.Identity.ReleaseSequence != 1 {
		t.Fatalf("identity=%#v", report.Identity)
	}
	if doctorCheckStatus(report, "accepted_state") != punarodiagnostic.StatusPass {
		t.Fatalf("accepted state did not recognize rollback high-water: report=%#v", report)
	}
	if doctorCheckStatus(report, "auto_rollback_state") != punarodiagnostic.StatusPass {
		t.Fatalf("auto-rollback state was not valid: report=%#v", report)
	}
	for _, code := range []string{"current_catalog_allowed", "current_manifest_signature", "current_platform_compatibility", "current_artifact_integrity", "previous_catalog_allowed", "previous_manifest_signature", "previous_platform_compatibility", "previous_artifact_integrity"} {
		if doctorCheckStatus(report, code) != punarodiagnostic.StatusPass {
			t.Fatalf("signed slot check %s did not pass: report=%#v", code, report)
		}
	}
	if report.Identity.CatalogSequence != accepted.CatalogSequence {
		t.Fatalf("catalog sequence=%d want=%d", report.Identity.CatalogSequence, accepted.CatalogSequence)
	}
	if after := bootstrapTreeDigest(t, directory); after != before {
		t.Fatalf("doctor mutated rollback state\nbefore=%s\nafter=%s", before, after)
	}
}

func TestDoctorHelperAndIsolationStayInsideDeadline(t *testing.T) {
	directory := privateDir(t)
	request, ok := encodeDoctorHelperRequest(DoctorRequest{Directory: directory, BootstrapRelease: "v0.1.0"})
	if !ok {
		t.Fatal("doctor helper request encoding failed")
	}
	var stdout strings.Builder
	if code := RunDoctorHelper([]string{"--request", request}, &stdout); code != 0 {
		t.Fatalf("doctor helper code=%d", code)
	}
	report, err := punarodiagnostic.Decode(strings.NewReader(stdout.String()))
	if err != nil || report.Component != punarodiagnostic.ComponentBootstrap {
		t.Fatalf("doctor helper report=%#v err=%v", report, err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	blocker := filepath.Join(t.TempDir(), "blocked-bootstrap-doctor")
	if err := os.WriteFile(blocker, []byte("#!/bin/sh\nexec sleep 10\n"), 0o700); err != nil { // #nosec G306 -- private executable deadline fixture.
		t.Fatal(err)
	}
	previous := doctorHelperExecutable
	doctorHelperExecutable = func() (string, error) { return blocker, nil }
	t.Cleanup(func() { doctorHelperExecutable = previous })
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := IsolatedDoctor(ctx, DoctorRequest{Directory: directory}); err == nil || time.Since(started) > time.Second {
		t.Fatalf("isolated doctor err=%v elapsed=%s", err, time.Since(started))
	}
}

func TestDoctorFailsUnsafeLockAndInsufficientPreflightDiskWithoutChangingEither(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH})
	directory := privateDir(t)
	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	if _, err := Update(Request{Directory: directory, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: now}); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(directory, lockFile)
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(directory, acceptedFile), lockPath); err != nil {
		t.Fatal(err)
	}
	before := bootstrapTreeDigest(t, directory)
	report, err := Doctor(t.Context(), DoctorRequest{Directory: directory, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: now, BootstrapRelease: "v0.1.0", FreeBytes: func(string) (uint64, error) { return 1, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if doctorCheckStatus(report, "bootstrap_lock") != punarodiagnostic.StatusFail || doctorCheckStatus(report, "disk_space") != punarodiagnostic.StatusFail {
		t.Fatalf("report=%#v", report)
	}
	if after := bootstrapTreeDigest(t, directory); after != before {
		t.Fatal("doctor modified unsafe lock or bootstrap state")
	}
}

func TestDoctorDetectsArtifactTamperAndDoesNotRepairInvalidJournal(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH})
	directory := privateDir(t)
	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	if _, err := Update(Request{Directory: directory, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: now}); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(directory, currentSlot, artifactName(adapterComponent, runtime.GOOS, runtime.GOARCH))
	if err := os.WriteFile(artifact, []byte(strings.Repeat("x", len(testArtifact))), 0o755); err != nil { // #nosec G306 -- executable artifact fixture.
		t.Fatal(err)
	}
	journalBody := []byte(`{"schema":1,"phase":"publishing","phase":"staging"}`)
	if err := os.WriteFile(filepath.Join(directory, journalFile), journalBody, 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Doctor(t.Context(), DoctorRequest{Directory: directory, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if doctorCheckStatus(report, "current_artifact_integrity") != punarodiagnostic.StatusFail || doctorCheckStatus(report, "journal_state") != punarodiagnostic.StatusFail || report.Healthy {
		t.Fatalf("report=%#v", report)
	}
	retained, err := os.ReadFile(filepath.Join(directory, journalFile)) // #nosec G304 -- private test fixture.
	if err != nil || string(retained) != string(journalBody) {
		t.Fatalf("journal=%q err=%v", retained, err)
	}
}

func TestVerifyLocalCheckoutSlotAcceptsAndProtectsClientArtifacts(t *testing.T) {
	directory := privateDir(t)
	artifacts := LocalCheckoutArtifacts{}
	for component, target := range map[string]*string{
		adapterComponent:            &artifacts.Adapter,
		"punaro-trusted-attachment": &artifacts.TrustedAttachment,
		"punaro-memory":             &artifacts.Memory,
		"punaro-enroll":             &artifacts.Enroll,
	} {
		path := filepath.Join(t.TempDir(), component)
		if err := os.WriteFile(path, []byte(component+"-body"), 0o700); err != nil { // #nosec G306 -- private executable fixture.
			t.Fatal(err)
		}
		*target = path
	}
	if err := SeedLocalCheckoutArtifacts(directory, artifacts, nil); err != nil {
		t.Fatal(err)
	}
	slot, err := readSlot(filepath.Join(directory, currentSlot))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := verifyLocalCheckoutSlot(t.Context(), filepath.Join(directory, currentSlot), runtime.GOOS, runtime.GOARCH, slot.ManifestSHA256); !ok {
		t.Fatal("seeded client artifacts failed local checkout verification")
	}
	memory := filepath.Join(directory, currentSlot, artifactName("punaro-memory", runtime.GOOS, runtime.GOARCH))
	if err := os.WriteFile(memory, []byte("tampered"), 0o755); err != nil { // #nosec G306 -- private executable fixture.
		t.Fatal(err)
	}
	if _, ok := verifyLocalCheckoutSlot(t.Context(), filepath.Join(directory, currentSlot), runtime.GOOS, runtime.GOARCH, slot.ManifestSHA256); ok {
		t.Fatal("tampered client artifact passed local checkout verification")
	}
}

func TestDoctorCancellationProducesExplicitPartialFailureWithoutMutation(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH})
	directory := privateDir(t)
	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	if _, err := Update(Request{Directory: directory, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: now}); err != nil {
		t.Fatal(err)
	}
	before := bootstrapTreeDigest(t, directory)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report, err := Doctor(ctx, DoctorRequest{Directory: directory, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: now, BootstrapRelease: "v0.1.0", FreeBytes: func(string) (uint64, error) { return 1 << 40, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if report.Healthy || doctorCheckStatus(report, "catalog_reachability") != punarodiagnostic.StatusFail || doctorCheckStatus(report, "current_slot") != punarodiagnostic.StatusFail || doctorCheckStatus(report, "accepted_state") != punarodiagnostic.StatusFail {
		t.Fatalf("report=%#v", report)
	}
	if after := bootstrapTreeDigest(t, directory); after != before {
		t.Fatal("cancelled doctor mutated bootstrap state")
	}
}

func TestDoctorRejectsOversizedAcceptedStateWithoutReadingIt(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH})
	directory := privateDir(t)
	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	if _, err := Update(Request{Directory: directory, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: now}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, acceptedFile), []byte(strings.Repeat("x", maximumDoctorStateBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Doctor(t.Context(), DoctorRequest{Directory: directory, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: now, FreeBytes: func(string) (uint64, error) { return 1 << 40, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if report.Healthy || doctorCheckStatus(report, "accepted_state") != punarodiagnostic.StatusFail {
		t.Fatalf("report=%#v", report)
	}
}

func TestHashExactArtifactHonorsCanceledContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "punaro-adapter")
	if err := os.WriteFile(path, []byte("artifact"), 0o755); err != nil { // #nosec G306 -- executable artifact fixture.
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if digest, ok := hashExactArtifact(ctx, path, int64(len("artifact")), 0o755); ok || digest != "" {
		t.Fatalf("canceled artifact hashing completed: digest=%q ok=%t", digest, ok)
	}
}

func TestReadDoctorDirectoryEntriesStopsAtLimit(t *testing.T) {
	directory := t.TempDir()
	for index := 0; index <= maximumDoctorSlotEntries; index++ {
		if err := os.Mkdir(filepath.Join(directory, fmt.Sprintf("entry-%03d", index)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if entries, ok := readDoctorDirectoryEntries(t.Context(), directory, maximumDoctorSlotEntries); ok || entries != nil {
		t.Fatalf("oversized slot directory accepted: entries=%d ok=%t", len(entries), ok)
	}
}

func TestDoctorRunPIDReadIsBoundedAndContextAware(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, runPIDFile)
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maximumDoctorStateBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := doctorLoadRunPID(t.Context(), directory); err == nil {
		t.Fatal("oversized run PID record was accepted")
	}
	if err := os.WriteFile(path, []byte(`{"schema":1,"pid":42,"path":"/tmp/punaro-adapter"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := doctorLoadRunPID(ctx, directory); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled run PID read error=%v", err)
	}
}

func TestDoctorReadyReadIsBoundedAndContextAware(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, readyFile)
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxReadyBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := doctorReadReadyFile(t.Context(), directory); err == nil {
		t.Fatal("oversized ready record was accepted")
	}
	if err := os.WriteFile(path, []byte(`{"schema":1,"status":"healthy"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := doctorReadReadyFile(ctx, directory); err == nil {
		t.Fatal("canceled ready read continued")
	}
}

func TestReleaseAtLeastUsesSemverPrereleaseOrdering(t *testing.T) {
	for name, test := range map[string]struct {
		current string
		minimum string
		want    bool
	}{
		"same alpha":                {"v0.1.0-alpha.1", "v0.1.0-alpha.1", true},
		"same semantic identity":    {"v1.2.3", "v1.2.3", true},
		"same invalid identity":     {"latest", "latest", false},
		"next alpha":                {"v0.1.0-alpha.2", "v0.1.0-alpha.1", true},
		"numeric identifiers":       {"v0.1.0-alpha.10", "v0.1.0-alpha.2", true},
		"numeric before text":       {"v0.1.0-1", "v0.1.0-alpha", false},
		"release after prerelease":  {"v0.1.0", "v0.1.0-rc.9", true},
		"prerelease before release": {"v0.1.0-rc.9", "v0.1.0", false},
		"older core":                {"v0.1.9", "v0.2.0-alpha.1", false},
		"leading zero invalid":      {"v0.1.0-alpha.01", "v0.1.0-alpha.1", false},
		"empty current invalid":     {"", "v0.1.0-alpha.1", false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := releaseAtLeast(test.current, test.minimum); got != test.want {
				t.Fatalf("releaseAtLeast(%q,%q)=%t want %t", test.current, test.minimum, got, test.want)
			}
		})
	}
}

func doctorCheckStatus(report punarodiagnostic.Report, code string) punarodiagnostic.Status {
	for _, check := range report.Checks {
		if check.Code == code {
			return check.Status
		}
	}
	return ""
}

func bootstrapTreeDigest(t *testing.T, directory string) string {
	t.Helper()
	var records []string
	err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		record := fmt.Sprintf("%s:%s:%o", relative, info.Mode().Type(), info.Mode().Perm())
		if info.Mode().IsRegular() {
			body, err := os.ReadFile(path) // #nosec G304,G122 -- private non-concurrent test fixture.
			if err != nil {
				return err
			}
			sum := sha256.Sum256(body)
			record += fmt.Sprintf(":%x", sum[:])
		}
		records = append(records, record)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(records)
	sum := sha256.Sum256([]byte(strings.Join(records, "\n")))
	return fmt.Sprintf("%x", sum[:])
}
