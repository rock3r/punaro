package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/rock3r/punaro/internal/operator"
	punaropostgres "github.com/rock3r/punaro/internal/postgres"
	punarorelease "github.com/rock3r/punaro/internal/release"
)

func TestUpdateLookupTreatsOnlyPreBridgeV5AsNoActiveUpdate(t *testing.T) {
	openErr := errors.New("administration unavailable")
	if err := classifyUpdateLookupOpenError(punaropostgres.SchemaState{Classification: punaropostgres.UpgradeRequired, Version: 5}, nil, openErr); !errors.Is(err, punaropostgres.ErrNotFound) {
		t.Fatalf("pre-bridge v5 error = %v", err)
	}
	if err := classifyUpdateLookupOpenError(punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 6}, nil, openErr); !errors.Is(err, openErr) {
		t.Fatalf("compatible schema hid administration error: %v", err)
	}
	inspectErr := errors.New("schema unavailable")
	if err := classifyUpdateLookupOpenError(punaropostgres.SchemaState{}, inspectErr, openErr); !errors.Is(err, openErr) {
		t.Fatalf("schema inspection error hid administration error: %v", err)
	}
}

func TestCompletedUpdateReconciliationRequiresExactPublishedOutcome(t *testing.T) {
	request := testUpdateRequest()
	metadata := punarorelease.Metadata{
		Release: request.TargetRelease, Image: request.TargetImage,
		Schema:          punarorelease.SchemaRange{Min: request.SchemaMin, Max: request.SchemaMax, Target: request.TargetSchema, RollbackFloor: request.RollbackFloor},
		PostgreSQLMajor: request.PostgresMajor, ReleaseSHA256: request.ReleaseSHA256,
		ComposeSHA256: request.ComposeSHA256, MigrationManifestSHA256: request.MigrationManifestSHA256,
	}
	transaction := punaropostgres.UpdateTransaction{UpdateRequest: request, Phase: punaropostgres.UpdateCommitted}
	if !completedUpdateMatches(transaction, metadata, request.TargetImage, false, "") {
		t.Fatal("exact committed outcome was not reconciled")
	}
	if completedUpdateMatches(transaction, metadata, request.SourceImage, false, "") {
		t.Fatal("committed outcome accepted unpublished target image")
	}
	metadata.ComposeSHA256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if completedUpdateMatches(transaction, metadata, request.TargetImage, false, "") {
		t.Fatal("committed outcome accepted changed release metadata")
	}
}

func TestUpdateResumeUsesLocallyVerifiedTargetWithoutRegistryPull(t *testing.T) {
	directory := testInstallation(t)
	installation, err := operator.Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	request := testUpdateRequest()
	request.SourceImage = installation.Image
	stage := operator.UpdateStage{Directory: directory, UpdateID: request.UpdateID, PreviousRelease: request.SourceRelease, PreviousImage: request.SourceImage, TargetRelease: request.TargetRelease, TargetImage: request.TargetImage}
	staged, err := operator.StageUpdate(stage)
	if err != nil {
		t.Fatal(err)
	}
	compose, err := os.ReadFile(operator.OverrideFile(staged.CandidateDirectory))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(compose)
	executor := &commandUpdateExecutor{installation: installation, request: request, stage: stage, metadata: punarorelease.Metadata{ComposeSHA256: hex.EncodeToString(digest[:])}}
	originalDocker := runUpdateDocker
	t.Cleanup(func() { runUpdateDocker = originalDocker })
	pulled := false
	runUpdateDocker = func(_ context.Context, _ string, _ []string, arguments ...string) ([]byte, error) {
		if len(arguments) > 0 && arguments[0] == "pull" {
			pulled = true
		}
		return []byte(request.TargetImage), nil
	}
	if err := executor.PrepareResume(context.Background(), punaropostgres.UpdateTransaction{UpdateRequest: request, Phase: punaropostgres.UpdateWritersStopped}); err != nil {
		t.Fatal(err)
	}
	if pulled {
		t.Fatal("durable update resume depended on a fresh registry pull")
	}
}

func TestCompatibleRecoveryDoctorsPreviousInstallationBeforePublishing(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	installation, err := operator.Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	request := testUpdateRequest()
	request.SourceImage = installation.Image
	stage := operator.UpdateStage{Directory: directory, UpdateID: request.UpdateID, PreviousRelease: request.SourceRelease, PreviousImage: request.SourceImage, TargetRelease: request.TargetRelease, TargetImage: request.TargetImage}
	staged, err := operator.StageUpdate(stage)
	if err != nil {
		t.Fatal(err)
	}
	startServices = func(context.Context, operator.Installation) error { return nil }
	probe = func(context.Context, string) error { return nil }
	maintenanceActive = func(context.Context, string) (bool, error) { return true, nil }
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: request.SourceSchema}, nil
	}
	executor := &commandUpdateExecutor{installation: installation, request: request, stage: stage, staged: staged}
	transaction := punaropostgres.UpdateTransaction{UpdateRequest: request, Phase: punaropostgres.UpdateRecoveryRequired}
	if err := executor.Recover(context.Background(), transaction, "compatible"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(directory, ".update")); err != nil {
		t.Fatalf("recovery removed stage before doctor: %v", err)
	}
	if err := executor.Doctor(context.Background(), transaction); err != nil {
		t.Fatalf("previous-image doctor failed: %v", err)
	}
	if err := executor.Publish(context.Background(), transaction, true); err != nil {
		t.Fatalf("compatible recovery publication failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(directory, ".update")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovery stage remains after publication: %v", err)
	}
}

func TestRestoredRecoveryDoctorsExactSourceSchemaBeforePublishing(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	installation, err := operator.Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	request := testUpdateRequest()
	request.SourceImage = installation.Image
	request.SourceSchema, request.TargetSchema, request.SchemaMin, request.SchemaMax, request.RollbackFloor = 5, 6, 5, 6, 5
	stage := operator.UpdateStage{Directory: directory, UpdateID: request.UpdateID, PreviousRelease: request.SourceRelease, PreviousImage: request.SourceImage, TargetRelease: request.TargetRelease, TargetImage: request.TargetImage}
	staged, err := operator.StageUpdate(stage)
	if err != nil {
		t.Fatal(err)
	}
	startServices = func(context.Context, operator.Installation) error { return nil }
	probe = func(context.Context, string) error { return nil }
	maintenanceActive = func(context.Context, string) (bool, error) { return true, nil }
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.UpgradeRequired, Version: 5}, nil
	}
	executor := &commandUpdateExecutor{installation: installation, request: request, stage: stage, staged: staged}
	transaction := punaropostgres.UpdateTransaction{UpdateRequest: request, Phase: punaropostgres.UpdateRecoveryRequired, BackupID: "019b4eb0-5317-79a6-a0de-fd97719910fb", BackupManifestSHA256: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}
	if err := executor.Recover(context.Background(), transaction, "restore"); err != nil {
		t.Fatal(err)
	}
	if err := executor.Doctor(context.Background(), transaction); err != nil {
		t.Fatalf("restored source-image doctor failed: %v", err)
	}
	if err := executor.Publish(context.Background(), transaction, true); err != nil {
		t.Fatalf("restored recovery publication failed: %v", err)
	}
}
