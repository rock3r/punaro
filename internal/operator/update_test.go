package operator

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	punaropostgres "github.com/rock3r/punaro/internal/postgres"
)

const updateTargetImage = "registry.example/punaro@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func installedUpdateRequest(t *testing.T) UpdateStage {
	t.Helper()
	options := validInitOptions(t)
	if _, err := Init(context.Background(), options, func(context.Context, string, string) (punaropostgres.Principal, error) {
		return punaropostgres.Principal{ID: "11111111-1111-4111-8111-111111111111", DisplayName: options.OwnerName}, nil
	}); err != nil {
		t.Fatal(err)
	}
	return UpdateStage{
		Directory:       options.Directory,
		UpdateID:        "019b4eb0-21f8-7d93-84df-10e6cf05ce53",
		PreviousRelease: "v0.6.0",
		PreviousImage:   testImage,
		TargetRelease:   "v0.7.0",
		TargetImage:     updateTargetImage,
	}
}

func TestStageUpdateIsPrivateDurableAndDoesNotPublish(t *testing.T) {
	request := installedUpdateRequest(t)
	beforeConfig, err := os.ReadFile(ConfigFile(request.Directory))
	if err != nil {
		t.Fatal(err)
	}
	beforeEnv, err := os.ReadFile(EnvFile(request.Directory))
	if err != nil {
		t.Fatal(err)
	}

	stage, err := StageUpdate(request)
	if err != nil {
		t.Fatal(err)
	}
	if stage.Published || stage.PreviousImage != request.PreviousImage || stage.TargetImage != request.TargetImage {
		t.Fatalf("stage=%#v", stage)
	}
	if filepath.Dir(stage.CandidateDirectory) != filepath.Join(request.Directory, updateStageDirectoryName) {
		t.Fatalf("candidate directory=%q", stage.CandidateDirectory)
	}
	for _, directory := range []string{filepath.Join(request.Directory, updateStageDirectoryName), stage.CandidateDirectory} {
		info, statErr := os.Lstat(directory)
		if statErr != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Fatalf("directory=%q mode=%v err=%v", directory, info.Mode(), statErr)
		}
	}
	candidate, err := readInstallation(ConfigFile(stage.CandidateDirectory))
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Image != request.TargetImage {
		t.Fatalf("candidate image=%q", candidate.Image)
	}
	candidateEnv, err := os.ReadFile(EnvFile(stage.CandidateDirectory))
	if err != nil || !strings.Contains(string(candidateEnv), "PUNARO_IMAGE="+request.TargetImage+"\n") {
		t.Fatalf("candidate env=%q err=%v", candidateEnv, err)
	}
	if candidateCompose, readErr := os.ReadFile(OverrideFile(stage.CandidateDirectory)); readErr != nil || string(candidateCompose) != composeOverride() {
		t.Fatalf("candidate compose invalid: %v", readErr)
	}
	afterConfig, _ := os.ReadFile(ConfigFile(request.Directory))
	afterEnv, _ := os.ReadFile(EnvFile(request.Directory))
	if string(afterConfig) != string(beforeConfig) || string(afterEnv) != string(beforeEnv) {
		t.Fatal("staging changed published configuration")
	}

	resumed, err := StageUpdate(request)
	if err != nil || resumed != stage {
		t.Fatalf("resume=%#v err=%v", resumed, err)
	}
	changed := request
	changed.TargetRelease = "v0.7.1"
	if _, err := StageUpdate(changed); !errors.Is(err, ErrUpdateStageConflict) {
		t.Fatalf("changed target error=%v", err)
	}
	other := request
	other.UpdateID = "019b4eb0-5317-79a6-a0de-fd97719910fb"
	if _, err := StageUpdate(other); !errors.Is(err, ErrUpdateStageConflict) {
		t.Fatalf("second update error=%v", err)
	}
}

func TestResumeUpdateStageNeverCreatesMissingAuthority(t *testing.T) {
	request := installedUpdateRequest(t)
	if _, err := ResumeUpdateStage(request); !errors.Is(err, ErrUpdateStageNotFound) {
		t.Fatalf("missing stage error=%v", err)
	}
	if _, err := os.Stat(filepath.Join(request.Directory, updateStageDirectoryName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("resume created a stage: %v", err)
	}
	want, err := StageUpdate(request)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ResumeUpdateStage(request)
	if err != nil || got != want {
		t.Fatalf("resume=%#v err=%v want=%#v", got, err, want)
	}
	existing, err := ExistingUpdateStage(request.Directory)
	if err != nil || existing != request {
		t.Fatalf("existing request=%#v err=%v want=%#v", existing, err, request)
	}
}

func TestUpdateRecoveryReceiptIsIndependentDurableAndExact(t *testing.T) {
	request := installedUpdateRequest(t)
	if _, err := StageUpdate(request); err != nil {
		t.Fatal(err)
	}
	backupDirectory := filepath.Join(t.TempDir(), "verified-backup")
	if err := os.Mkdir(backupDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	receipt := UpdateRecoveryReceipt{
		Version: 1, UpdateID: request.UpdateID, BackupID: "019b4eb0-b9fb-761e-9c88-30f59a659aa8", BackupDirectory: backupDirectory,
		InstallationID: "11111111-1111-4111-8111-111111111111", TimelineID: "22222222-2222-4222-8222-222222222222", ChangeSequence: 7,
		SourceSchema: 5, TargetRelease: request.TargetRelease, TargetImageDigest: "sha256:" + strings.Repeat("b", 64),
		ExportedSnapshotID: "000003A1-1", ManifestSHA256: strings.Repeat("c", 64),
	}
	digest, err := BindUpdateRecoveryReceipt(request, receipt)
	if err != nil || len(digest) != 64 {
		t.Fatalf("bind digest=%q err=%v", digest, err)
	}
	path := UpdateRecoveryReceiptFile(request.Directory)
	loaded, loadedDigest, err := LoadUpdateRecoveryReceipt(path)
	if err != nil || loaded != receipt || loadedDigest != digest {
		t.Fatalf("loaded=%#v digest=%q err=%v", loaded, loadedDigest, err)
	}
	if digest2, err := BindUpdateRecoveryReceipt(request, receipt); err != nil || digest2 != digest {
		t.Fatalf("idempotent bind digest=%q err=%v", digest2, err)
	}
	changed := receipt
	changed.BackupID = "019b4eb1-a74a-77bd-9402-b8fa0532c44f"
	if _, err := BindUpdateRecoveryReceipt(request, changed); err == nil {
		t.Fatal("receipt authority was replaced")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("receipt mode=%v err=%v", info.Mode(), err)
	}
}

func TestPublishUpdateMarkerIsLastAndEveryBoundaryResumes(t *testing.T) {
	for _, failAfter := range []string{publishStepEnvironment, publishStepCompose, publishStepInstallation} {
		t.Run(failAfter, func(t *testing.T) {
			request := installedUpdateRequest(t)
			if _, err := StageUpdate(request); err != nil {
				t.Fatal(err)
			}
			updatePublicationHook = func(step string) error {
				loaded, loadErr := Load(request.Directory)
				if loadErr != nil {
					t.Fatalf("load at %s: %v", step, loadErr)
				}
				wantImage := request.PreviousImage
				if step == publishStepInstallation {
					wantImage = request.TargetImage
				}
				if loaded.Image != wantImage {
					t.Fatalf("step=%s image=%q want=%q", step, loaded.Image, wantImage)
				}
				if step == failAfter {
					return errors.New("simulated crash")
				}
				return nil
			}
			if _, err := PublishUpdate(request); err == nil {
				t.Fatal("simulated publication crash was ignored")
			}
			updatePublicationHook = nil
			t.Cleanup(func() { updatePublicationHook = nil })

			published, err := PublishUpdate(request)
			if err != nil || published.Image != request.TargetImage {
				t.Fatalf("published=%#v err=%v", published, err)
			}
			if _, err := PublishUpdate(request); err != nil {
				t.Fatalf("idempotent publish: %v", err)
			}
			loaded, err := Load(request.Directory)
			if err != nil || loaded.Image != request.TargetImage || len(CheckPaths(loaded)) != 0 {
				t.Fatalf("loaded=%#v failures=%v err=%v", loaded, CheckPaths(loaded), err)
			}
			journal, err := readUpdateJournal(request.Directory)
			if err != nil || !journal.Published || journal.PreviousRelease != request.PreviousRelease || journal.PreviousImage != request.PreviousImage {
				t.Fatalf("journal=%#v err=%v", journal, err)
			}
		})
	}
}

func TestPublishPreviousUpdateReversesPublishedTargetForFencedRecovery(t *testing.T) {
	request := installedUpdateRequest(t)
	if _, err := PublishUpdate(request); err != nil {
		t.Fatal(err)
	}
	if err := PublishPreviousUpdate(request); err != nil {
		t.Fatal(err)
	}
	current, err := Load(request.Directory)
	if err != nil || current.Image != request.PreviousImage || len(CheckPaths(current)) != 0 {
		t.Fatalf("current=%#v err=%v", current, err)
	}
	if err := PublishPreviousUpdate(request); err != nil {
		t.Fatalf("idempotent previous publication: %v", err)
	}
}

func TestAbortStageRestoresPartialPublicationButRefusesPublishedUpdate(t *testing.T) {
	request := installedUpdateRequest(t)
	if _, err := StageUpdate(request); err != nil {
		t.Fatal(err)
	}
	updatePublicationHook = func(step string) error {
		if step == publishStepEnvironment {
			return errors.New("simulated crash")
		}
		return nil
	}
	if _, err := PublishUpdate(request); err == nil {
		t.Fatal("simulated crash was ignored")
	}
	updatePublicationHook = nil
	t.Cleanup(func() { updatePublicationHook = nil })
	if err := AbortStage(request); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(request.Directory, updateStageDirectoryName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stage survived abort: %v", err)
	}
	loaded, err := Load(request.Directory)
	if err != nil || loaded.Image != request.PreviousImage || len(CheckPaths(loaded)) != 0 {
		t.Fatalf("loaded=%#v failures=%v err=%v", loaded, CheckPaths(loaded), err)
	}

	if _, err := StageUpdate(request); err != nil {
		t.Fatal(err)
	}
	if _, err := PublishUpdate(request); err != nil {
		t.Fatal(err)
	}
	if err := AbortStage(request); !errors.Is(err, ErrUpdateAlreadyPublished) {
		t.Fatalf("published abort error=%v", err)
	}
}

func TestStageUpdateStrictlyValidatesRequestAndPublishedSource(t *testing.T) {
	base := installedUpdateRequest(t)
	tests := map[string]func(*UpdateStage){
		"relative directory": func(r *UpdateStage) { r.Directory = "relative" },
		"invalid update id":  func(r *UpdateStage) { r.UpdateID = "not-a-uuid" },
		"empty previous":     func(r *UpdateStage) { r.PreviousRelease = "" },
		"unsafe target":      func(r *UpdateStage) { r.TargetRelease = "v0.7.0\nBAD=1" },
		"same release":       func(r *UpdateStage) { r.TargetRelease = r.PreviousRelease },
		"same image":         func(r *UpdateStage) { r.TargetImage = r.PreviousImage },
		"tagged image":       func(r *UpdateStage) { r.TargetImage = "registry.example/punaro:latest" },
		"wrong previous":     func(r *UpdateStage) { r.PreviousImage = updateTargetImage; r.TargetImage = testImage },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := base
			mutate(&request)
			if _, err := StageUpdate(request); err == nil {
				t.Fatal("invalid update stage accepted")
			}
		})
	}
}

func TestCompleteStageRemovesOnlyPublishedExactJournal(t *testing.T) {
	request := installedUpdateRequest(t)
	if _, err := StageUpdate(request); err != nil {
		t.Fatal(err)
	}
	if err := CompleteStage(request); err == nil {
		t.Fatal("unpublished stage completed")
	}
	if _, err := PublishUpdate(request); err != nil {
		t.Fatal(err)
	}
	if err := CompleteStage(request); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(request.Directory, updateStageDirectoryName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed stage remains: %v", err)
	}
	if loaded, err := Load(request.Directory); err != nil || loaded.Image != request.TargetImage {
		t.Fatalf("published installation changed: %#v err=%v", loaded, err)
	}
}
