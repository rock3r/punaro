package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rock3r/punaro/internal/operator"
	punaropostgres "github.com/rock3r/punaro/internal/postgres"
	punarorelease "github.com/rock3r/punaro/internal/release"
)

type fakeV5UpdateBridge struct {
	update    punaropostgres.UpdateTransaction
	commit    punaropostgres.UpdateTransaction
	commitErr error
	abortErr  error
	aborts    int
}

func (bridge *fakeV5UpdateBridge) Update() punaropostgres.UpdateTransaction {
	return bridge.update
}

func (bridge *fakeV5UpdateBridge) CommitWritersStopped(context.Context) (punaropostgres.UpdateTransaction, error) {
	return bridge.commit, bridge.commitErr
}

func (bridge *fakeV5UpdateBridge) Abort() error {
	bridge.aborts++
	return bridge.abortErr
}

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

func TestUpdateSourcePolicyAllowsOnlySignedDirectSources(t *testing.T) {
	metadata := punarorelease.Metadata{SupportedFrom: []string{"v0.1.0-alpha.11"}}
	if err := validateUpdateSource(metadata, "v0.1.0-alpha.11"); err != nil {
		t.Fatalf("signed direct source rejected: %v", err)
	}
	if err := validateUpdateSource(metadata, "v0.1.0-alpha.10"); err == nil {
		t.Fatal("source absent from signed policy accepted")
	}
	if err := validateUpdateSource(punarorelease.Metadata{}, "v0.1.0-alpha.11"); err == nil {
		t.Fatal("empty first-install policy accepted as a server update edge")
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
	_, err = operator.StageUpdate(stage)
	if err != nil {
		t.Fatal(err)
	}
	executor := &commandUpdateExecutor{installation: installation, request: request, stage: stage, metadata: punarorelease.Metadata{ComposeSHA256: operator.ComposeManifestSHA256()}}
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

func TestAbortUnpublishedStartRemovesDurableHostStage(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	installation, err := operator.Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	request := testUpdateRequest()
	request.SourceImage = installation.Image
	stage := operator.UpdateStage{Directory: directory, UpdateID: request.UpdateID, PreviousRelease: request.SourceRelease, PreviousImage: request.SourceImage, TargetRelease: request.TargetRelease, TargetImage: request.TargetImage}
	if _, err := operator.StageUpdate(stage); err != nil {
		t.Fatal(err)
	}
	runUpdateDocker = func(context.Context, string, []string, ...string) ([]byte, error) {
		return []byte("punarod\n"), nil
	}
	executor := &commandUpdateExecutor{installation: installation, request: request, stage: stage}
	if err := executor.AbortUnpublishedStart(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(directory, ".update")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unpublished update stage remains after authorization failure: %v", err)
	}
}

func TestAbortUnpublishedStartPreservesStageWhenWriterStateIsUnknown(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	installation, err := operator.Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	request := testUpdateRequest()
	request.SourceImage = installation.Image
	stage := operator.UpdateStage{Directory: directory, UpdateID: request.UpdateID, PreviousRelease: request.SourceRelease, PreviousImage: request.SourceImage, TargetRelease: request.TargetRelease, TargetImage: request.TargetImage}
	if _, err := operator.StageUpdate(stage); err != nil {
		t.Fatal(err)
	}
	runUpdateDocker = func(context.Context, string, []string, ...string) ([]byte, error) {
		return nil, errors.New("injected Docker outage")
	}
	executor := &commandUpdateExecutor{installation: installation, request: request, stage: stage}
	if err := executor.AbortUnpublishedStart(context.Background()); err == nil {
		t.Fatal("unpublished stage was cleaned without knowing whether the writer was stopped")
	}
	if _, err := os.Stat(filepath.Join(directory, ".update")); err != nil {
		t.Fatalf("stage was not preserved while writer state was unknown: %v", err)
	}
}

func TestAbortUnpublishedStartRestoresOrphanedWriterBeforeRemovingStage(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	installation, err := operator.Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	request := testUpdateRequest()
	request.SourceImage = installation.Image
	stage := operator.UpdateStage{Directory: directory, UpdateID: request.UpdateID, PreviousRelease: request.SourceRelease, PreviousImage: request.SourceImage, TargetRelease: request.TargetRelease, TargetImage: request.TargetImage}
	if _, err := operator.StageUpdate(stage); err != nil {
		t.Fatal(err)
	}
	actions := []string{}
	startServices = func(context.Context, operator.Installation) error {
		actions = append(actions, "start_previous")
		return nil
	}
	probe = func(context.Context, string) error {
		actions = append(actions, "ready_previous")
		return nil
	}
	executor := &commandUpdateExecutor{installation: installation, request: request, stage: stage, orphanedWriters: true}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := executor.AbortUnpublishedStart(canceled); err != nil {
		t.Fatal(err)
	}
	if want := []string{"start_previous", "ready_previous"}; !slices.Equal(actions, want) {
		t.Fatalf("actions=%v want=%v", actions, want)
	}
	if _, err := os.Stat(filepath.Join(directory, ".update")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphaned update stage remains after writer recovery: %v", err)
	}
}

func TestAbortUnpublishedStartPreservesOrphanedStageWhenWriterCannotRecover(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	installation, err := operator.Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	request := testUpdateRequest()
	request.SourceImage = installation.Image
	stage := operator.UpdateStage{Directory: directory, UpdateID: request.UpdateID, PreviousRelease: request.SourceRelease, PreviousImage: request.SourceImage, TargetRelease: request.TargetRelease, TargetImage: request.TargetImage}
	if _, err := operator.StageUpdate(stage); err != nil {
		t.Fatal(err)
	}
	startServices = func(context.Context, operator.Installation) error { return errors.New("injected restart failure") }
	executor := &commandUpdateExecutor{installation: installation, request: request, stage: stage, orphanedWriters: true}
	if err := executor.AbortUnpublishedStart(context.Background()); err == nil {
		t.Fatal("orphaned stage cleanup succeeded without recovering the previous writer")
	}
	if _, err := os.Stat(filepath.Join(directory, ".update")); err != nil {
		t.Fatalf("orphaned stage was not preserved for recovery: %v", err)
	}
}

func TestRunUpdateAbortCleansConfirmedTransactionFreeStageWithoutReleaseAuthorization(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	installation, err := operator.Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	request := testUpdateRequest()
	request.SourceImage = installation.Image
	stage := operator.UpdateStage{Directory: directory, UpdateID: request.UpdateID, PreviousRelease: request.SourceRelease, PreviousImage: request.SourceImage, TargetRelease: request.TargetRelease, TargetImage: request.TargetImage}
	if _, err := operator.StageUpdate(stage); err != nil {
		t.Fatal(err)
	}
	actions := []string{}
	runUpdateDocker = func(context.Context, string, []string, ...string) ([]byte, error) { return nil, nil }
	startServices = func(context.Context, operator.Installation) error {
		actions = append(actions, "start_previous")
		return nil
	}
	probe = func(context.Context, string) error {
		actions = append(actions, "ready_previous")
		return nil
	}
	reconcileUpdateTransaction = func(ctx context.Context, _ operator.Installation, updateID string) (punaropostgres.UpdateTransaction, error) {
		if ctx.Err() != nil {
			t.Fatalf("cleanup context is unavailable: %v", ctx.Err())
		}
		if updateID != "" && updateID != request.UpdateID {
			t.Fatalf("unexpected update ID %q", updateID)
		}
		return punaropostgres.UpdateTransaction{}, punaropostgres.ErrNotFound
	}
	var stdout, stderr bytes.Buffer
	if code := runUpdate([]string{"--directory", directory, "--abort"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), `"status": "unpublished_stage_aborted"`) {
		t.Fatalf("cleanup code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !slices.Equal(actions, []string{"start_previous", "ready_previous"}) {
		t.Fatalf("actions=%v", actions)
	}
	if _, err := os.Stat(filepath.Join(directory, ".update")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("transaction-free stage remains after cleanup: %v", err)
	}
}

func TestCleanupUnpublishedUpdatePreservesStageWithDurableTransaction(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	installation, err := operator.Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	request := testUpdateRequest()
	request.SourceImage = installation.Image
	stage := operator.UpdateStage{Directory: directory, UpdateID: request.UpdateID, PreviousRelease: request.SourceRelease, PreviousImage: request.SourceImage, TargetRelease: request.TargetRelease, TargetImage: request.TargetImage}
	if _, err := operator.StageUpdate(stage); err != nil {
		t.Fatal(err)
	}
	reconcileUpdateTransaction = func(_ context.Context, _ operator.Installation, updateID string) (punaropostgres.UpdateTransaction, error) {
		if updateID == request.UpdateID {
			return punaropostgres.UpdateTransaction{UpdateRequest: request, Phase: punaropostgres.UpdateFenced}, nil
		}
		return punaropostgres.UpdateTransaction{}, punaropostgres.ErrNotFound
	}
	if _, err := cleanupUnpublishedUpdate(context.Background(), installation); err == nil {
		t.Fatal("cleanup removed a stage with durable database state")
	}
	if _, err := os.Stat(filepath.Join(directory, ".update")); err != nil {
		t.Fatalf("durable stage was not preserved: %v", err)
	}
}

func TestAbortPendingStartRecoversFailedBridgeRollbackWhenTransactionIsAbsent(t *testing.T) {
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
	if _, err := operator.StageUpdate(stage); err != nil {
		t.Fatal(err)
	}
	actions := []string{}
	startServices = func(context.Context, operator.Installation) error {
		actions = append(actions, "start_previous")
		return nil
	}
	probe = func(context.Context, string) error {
		actions = append(actions, "ready_previous")
		return nil
	}
	reconcileUpdateTransaction = func(ctx context.Context, _ operator.Installation, updateID string) (punaropostgres.UpdateTransaction, error) {
		if ctx.Err() != nil || updateID != request.UpdateID {
			t.Fatalf("reconciliation context=%v update_id=%q", ctx.Err(), updateID)
		}
		return punaropostgres.UpdateTransaction{}, punaropostgres.ErrNotFound
	}
	bridge := &fakeV5UpdateBridge{abortErr: errors.New("injected rollback failure")}
	executor := &commandUpdateExecutor{installation: installation, request: request, stage: stage, bridge: bridge}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := executor.AbortPendingStart(canceled); err == nil {
		t.Fatal("failed bridge rollback lost its original error")
	}
	if executor.bridge != nil || bridge.aborts != 1 || !slices.Equal(actions, []string{"start_previous", "ready_previous"}) {
		t.Fatalf("bridge_present=%t aborts=%d actions=%v", executor.bridge != nil, bridge.aborts, actions)
	}
	if _, err := os.Stat(filepath.Join(directory, ".update")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unpublished update stage remains after confirmed-absent rollback recovery: %v", err)
	}
}

func TestAbortPendingStartPreservesFailedBridgeRollbackWhenDurabilityIsUnknown(t *testing.T) {
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
	if _, err := operator.StageUpdate(stage); err != nil {
		t.Fatal(err)
	}
	reconcileUpdateTransaction = func(context.Context, operator.Installation, string) (punaropostgres.UpdateTransaction, error) {
		return punaropostgres.UpdateTransaction{}, errors.New("injected database outage")
	}
	bridge := &fakeV5UpdateBridge{abortErr: errors.New("injected rollback failure")}
	executor := &commandUpdateExecutor{installation: installation, request: request, stage: stage, bridge: bridge}
	if err := executor.AbortPendingStart(context.Background()); err == nil {
		t.Fatal("unknown bridge rollback outcome unexpectedly recovered")
	}
	if _, err := os.Stat(filepath.Join(directory, ".update")); err != nil {
		t.Fatalf("stage was not preserved while rollback durability was unknown: %v", err)
	}
}

func TestV5BridgeCommitReconcilesDurableWritersStoppedOutcome(t *testing.T) {
	preserveDependencies(t)
	request := testUpdateRequest()
	request.SourceSchema, request.TargetSchema, request.SchemaMin, request.SchemaMax, request.RollbackFloor = 5, 6, 5, 6, 5
	transaction := punaropostgres.UpdateTransaction{UpdateRequest: request, Phase: punaropostgres.UpdateFenced}
	durable := transaction
	durable.Phase = punaropostgres.UpdateWritersStopped
	bridge := &fakeV5UpdateBridge{update: transaction, commit: durable, commitErr: punaropostgres.ErrV5UpdateBridgeOutcomeUncertain}
	reconcileUpdateTransaction = func(_ context.Context, _ operator.Installation, updateID string) (punaropostgres.UpdateTransaction, error) {
		if updateID != request.UpdateID {
			t.Fatalf("reconciled update ID=%q", updateID)
		}
		return durable, nil
	}
	executor := &commandUpdateExecutor{request: request, bridge: bridge}
	advanced, err := executor.Advance(context.Background(), transaction, punaropostgres.UpdateWritersStopped, nil)
	if err != nil || advanced != durable || executor.bridge != nil || bridge.aborts != 0 {
		t.Fatalf("advanced=%#v err=%v bridge_present=%t aborts=%d", advanced, err, executor.bridge != nil, bridge.aborts)
	}
}

func TestV5BridgeCommitFailureRestoresWriterAndRemovesUnpublishedStage(t *testing.T) {
	for _, test := range []struct {
		name       string
		commitErr  error
		durableErr error
		wantAborts int
	}{
		{name: "precommit", commitErr: errors.New("commit staging failed"), wantAborts: 1},
		{name: "uncertain absent", commitErr: punaropostgres.ErrV5UpdateBridgeOutcomeUncertain, durableErr: punaropostgres.ErrNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			preserveDependencies(t)
			directory := testInstallation(t)
			installation, err := operator.Load(directory)
			if err != nil {
				t.Fatal(err)
			}
			request := testUpdateRequest()
			request.SourceImage = installation.Image
			request.SourceSchema, request.TargetSchema, request.SchemaMin, request.SchemaMax, request.RollbackFloor = 5, 6, 5, 6, 5
			transaction := punaropostgres.UpdateTransaction{UpdateRequest: request, Phase: punaropostgres.UpdateFenced}
			stage := operator.UpdateStage{Directory: directory, UpdateID: request.UpdateID, PreviousRelease: request.SourceRelease, PreviousImage: request.SourceImage, TargetRelease: request.TargetRelease, TargetImage: request.TargetImage}
			if _, err := operator.StageUpdate(stage); err != nil {
				t.Fatal(err)
			}
			startServices = func(context.Context, operator.Installation) error { return nil }
			probe = func(context.Context, string) error { return nil }
			reconcileUpdateTransaction = func(ctx context.Context, _ operator.Installation, _ string) (punaropostgres.UpdateTransaction, error) {
				if ctx.Err() != nil {
					t.Fatalf("bridge reconciliation reused canceled operation context: %v", ctx.Err())
				}
				return punaropostgres.UpdateTransaction{}, test.durableErr
			}
			bridge := &fakeV5UpdateBridge{update: transaction, commitErr: test.commitErr}
			executor := &commandUpdateExecutor{installation: installation, request: request, stage: stage, bridge: bridge}
			canceled, cancel := context.WithCancel(context.Background())
			cancel()
			advanced, err := executor.Advance(canceled, transaction, punaropostgres.UpdateWritersStopped, nil)
			if err == nil || advanced != transaction || executor.bridge != nil || bridge.aborts != test.wantAborts {
				t.Fatalf("advanced=%#v err=%v bridge_present=%t aborts=%d", advanced, err, executor.bridge != nil, bridge.aborts)
			}
			if _, err := os.Stat(filepath.Join(directory, ".update")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unpublished update stage remains after bridge failure recovery: %v", err)
			}
		})
	}
}

func TestV5BridgeUncertainCommitPreservesStageWhenDurableStateIsUnavailable(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	installation, err := operator.Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	request := testUpdateRequest()
	request.SourceImage = installation.Image
	request.SourceSchema, request.TargetSchema, request.SchemaMin, request.SchemaMax, request.RollbackFloor = 5, 6, 5, 6, 5
	transaction := punaropostgres.UpdateTransaction{UpdateRequest: request, Phase: punaropostgres.UpdateFenced}
	stage := operator.UpdateStage{Directory: directory, UpdateID: request.UpdateID, PreviousRelease: request.SourceRelease, PreviousImage: request.SourceImage, TargetRelease: request.TargetRelease, TargetImage: request.TargetImage}
	if _, err := operator.StageUpdate(stage); err != nil {
		t.Fatal(err)
	}
	reconcileUpdateTransaction = func(context.Context, operator.Installation, string) (punaropostgres.UpdateTransaction, error) {
		return punaropostgres.UpdateTransaction{}, errors.New("injected database outage")
	}
	bridge := &fakeV5UpdateBridge{update: transaction, commitErr: punaropostgres.ErrV5UpdateBridgeOutcomeUncertain}
	executor := &commandUpdateExecutor{installation: installation, request: request, stage: stage, bridge: bridge}
	if _, err := executor.Advance(context.Background(), transaction, punaropostgres.UpdateWritersStopped, nil); err == nil {
		t.Fatal("uncertain bridge outcome passed without durable reconciliation")
	}
	if _, err := os.Stat(filepath.Join(directory, ".update")); err != nil {
		t.Fatalf("stage was not preserved while bridge durability was unknown: %v", err)
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

func TestLoadSignedUpdateMetadataProjectsVerifiedManifest(t *testing.T) {
	manifestPath, signaturePath, keysPath := signedUpdateFiles(t)
	metadata, err := loadSignedUpdateMetadata(manifestPath, signaturePath, keysPath, punarorelease.Environment{CurrentSchema: 44, PostgreSQLMajor: 18})
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Release != "v0.1.0" || metadata.Image != cliTestImage || metadata.Schema != (punarorelease.SchemaRange{Min: 1, Max: 44, Target: 44, RollbackFloor: 1}) || metadata.PostgreSQLMajor != 18 {
		t.Fatalf("metadata=%#v", metadata)
	}
	if metadata.ReleaseSHA256 != cliTestImage[len("registry.example/punaro@sha256:"):] || metadata.ComposeSHA256 != operator.ComposeManifestSHA256() || metadata.MigrationManifestSHA256 != punaropostgres.MigrationManifestSHA256() {
		t.Fatalf("metadata digests=%#v", metadata)
	}
	if len(metadata.SupportedFrom) != 1 || metadata.SupportedFrom[0] != "v0.0.9" {
		t.Fatalf("metadata supported sources=%#v", metadata.SupportedFrom)
	}
}

func TestTargetReleaseMustMatchEmbeddedUpdaterRelease(t *testing.T) {
	metadata := punarorelease.Metadata{Release: "v0.1.0"}
	if !targetReleaseMatchesUpdater(metadata, "v0.1.0") {
		t.Fatal("exact target-release updater was rejected")
	}
	if targetReleaseMatchesUpdater(metadata, "v0.0.9") {
		t.Fatal("source-release updater was accepted for the target manifest")
	}
	if targetReleaseMatchesUpdater(metadata, "") {
		t.Fatal("unidentified updater was accepted for the target manifest")
	}
}

func TestAuthorizeUpdateStartRequiresFreshCatalogForNewTransaction(t *testing.T) {
	manifestPath, signaturePath, keysPath := signedUpdateFiles(t)
	release, err := loadSignedUpdateRelease(manifestPath, signaturePath, keysPath, punarorelease.Environment{CurrentSchema: 44, PostgreSQLMajor: 18})
	if err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(filepath.Dir(manifestPath), punarorelease.CatalogFile)
	catalogSignaturePath := filepath.Join(filepath.Dir(manifestPath), punarorelease.CatalogSignatureFile)
	directory := filepath.Dir(manifestPath)
	now := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	if err := authorizeUpdateStartForTest(punaropostgres.UpdateRequest{}, directory, catalogPath, catalogSignaturePath, release, now, 1); err != nil {
		t.Fatalf("fresh signed catalog rejected: %v", err)
	}
	guard, revalidate, err := authorizeUpdateStart(punaropostgres.UpdateRequest{}, directory, catalogPath, catalogSignaturePath, release, now, 1)
	if err != nil {
		t.Fatalf("fresh signed catalog could not be retained for pre-fence recheck: %v", err)
	}
	if err := revalidate(time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)); err == nil {
		guard()
		t.Fatal("catalog expiry during preflight was not rejected before fencing")
	}
	guard()
	if err := authorizeUpdateStartForTest(punaropostgres.UpdateRequest{}, directory, "", "", release, now, 1); !errors.Is(err, errUpdateCatalogRequired) {
		t.Fatalf("missing catalog error=%v", err)
	}
	if err := authorizeUpdateStartForTest(punaropostgres.UpdateRequest{UpdateID: "durable-update"}, "", "", "", signedUpdateRelease{}, now, 100); err != nil {
		t.Fatalf("exact durable resume required a fresh catalog: %v", err)
	}
	for _, floor := range []int64{0, -1} {
		if err := authorizeUpdateStartForTest(punaropostgres.UpdateRequest{}, directory, catalogPath, catalogSignaturePath, release, now, floor); !errors.Is(err, errUpdateCatalogFloor) {
			t.Fatalf("invalid embedded floor %d error=%v", floor, err)
		}
		if err := authorizeUpdateStartForTest(punaropostgres.UpdateRequest{UpdateID: "durable-update"}, "", "", "", signedUpdateRelease{}, now, floor); !errors.Is(err, errUpdateCatalogFloor) {
			t.Fatalf("invalid embedded floor %d allowed durable resume: %v", floor, err)
		}
	}

	wrongBinding := release
	wrongBinding.manifestSHA256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if err := authorizeUpdateStartForTest(punaropostgres.UpdateRequest{}, directory, catalogPath, catalogSignaturePath, wrongBinding, now, 1); err == nil {
		t.Fatal("catalog accepted a different manifest binding")
	}
	if err := authorizeUpdateStartForTest(punaropostgres.UpdateRequest{}, directory, catalogPath, catalogSignaturePath, release, time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC), 1); err == nil {
		t.Fatal("expired catalog authorized a new update")
	}

	catalogBody, err := os.ReadFile(catalogPath) // #nosec G304 -- fixed test fixture path.
	if err != nil {
		t.Fatal(err)
	}
	catalogBody = bytes.Replace(catalogBody, []byte(`"current_release":"v0.1.0"`), []byte(`"current_release":"v0.1.1"`), 1)
	if err := os.WriteFile(catalogPath, catalogBody, 0o600); err != nil { // #nosec G703 -- fixed test fixture path.
		t.Fatal(err)
	}
	if err := authorizeUpdateStartForTest(punaropostgres.UpdateRequest{}, directory, catalogPath, catalogSignaturePath, release, now, 1); err == nil {
		t.Fatal("tampered catalog authorized a new update")
	}

	manifestPath, signaturePath, keysPath = signedUpdateFiles(t)
	release, err = loadSignedUpdateRelease(manifestPath, signaturePath, keysPath, punarorelease.Environment{CurrentSchema: 44, PostgreSQLMajor: 18})
	if err != nil {
		t.Fatal(err)
	}
	directory = filepath.Dir(manifestPath)
	catalogPath = filepath.Join(directory, punarorelease.CatalogFile)
	catalogSignaturePath = filepath.Join(directory, punarorelease.CatalogSignatureFile)
	if err := operator.AcceptServerCatalogSequence(directory, 2, 0); err != nil {
		t.Fatal(err)
	}
	if err := authorizeUpdateStartForTest(punaropostgres.UpdateRequest{}, directory, catalogPath, catalogSignaturePath, release, now, 1); err == nil {
		t.Fatal("older still-fresh catalog replayed below the durable high-water")
	}
}

func authorizeUpdateStartForTest(request punaropostgres.UpdateRequest, directory, catalogPath, catalogSignaturePath string, release signedUpdateRelease, now time.Time, embeddedMinimum int64) error {
	unlock, revalidate, err := authorizeUpdateStart(request, directory, catalogPath, catalogSignaturePath, release, now, embeddedMinimum)
	if err == nil {
		err = revalidate(now)
	}
	if unlock != nil {
		unlock()
	}
	return err
}

func TestLoadSignedUpdateMetadataRejectsTamperAndUnsafeFiles(t *testing.T) {
	manifestPath, signaturePath, keysPath := signedUpdateFiles(t)
	manifestBody, err := os.ReadFile(manifestPath) // #nosec G304 -- fixed test fixture path.
	if err != nil {
		t.Fatal(err)
	}
	manifestBody = bytes.Replace(manifestBody, []byte(`"release":"v0.1.0"`), []byte(`"release":"v0.1.1"`), 1)
	if err := os.WriteFile(manifestPath, manifestBody, 0o600); err != nil { // #nosec G703 -- test helper returned this path beneath t.TempDir.
		t.Fatal(err)
	}
	if _, err := loadSignedUpdateMetadata(manifestPath, signaturePath, keysPath, punarorelease.Environment{CurrentSchema: 44, PostgreSQLMajor: 18}); err == nil {
		t.Fatal("tampered release manifest accepted")
	}

	if runtime.GOOS != "windows" {
		manifestPath, signaturePath, keysPath = signedUpdateFiles(t)
		if err := os.Chmod(signaturePath, 0o644); err != nil { // #nosec G302 -- deliberately unsafe test fixture verifies rejection.
			t.Fatal(err)
		}
		if _, err := loadSignedUpdateMetadata(manifestPath, signaturePath, keysPath, punarorelease.Environment{CurrentSchema: 44, PostgreSQLMajor: 18}); err == nil {
			t.Fatal("group/world-readable release signature accepted")
		}
	}

	manifestPath, signaturePath, keysPath = signedUpdateFiles(t)
	if err := os.Link(keysPath, keysPath+".link"); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSignedUpdateMetadata(manifestPath, signaturePath, keysPath, punarorelease.Environment{CurrentSchema: 44, PostgreSQLMajor: 18}); err == nil {
		t.Fatal("multiply linked release trust root accepted")
	}

	manifestPath, signaturePath, keysPath = signedUpdateFiles(t)
	unsafeDirectory := filepath.Join(filepath.Dir(keysPath), "unsafe")
	if err := os.Mkdir(unsafeDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafeDirectory, 0o777); err != nil { // #nosec G302 -- deliberately unsafe ancestor verifies rejection.
		t.Fatal(err)
	}
	unsafeKeysPath := filepath.Join(unsafeDirectory, "punaro-release.pub")
	keysBody, err := os.ReadFile(keysPath) // #nosec G304 -- fixed test fixture path beneath t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unsafeKeysPath, keysBody, 0o600); err != nil { // #nosec G703 -- test path is fixed beneath t.TempDir.
		t.Fatal(err)
	}
	if _, err := loadSignedUpdateMetadata(manifestPath, signaturePath, unsafeKeysPath, punarorelease.Environment{CurrentSchema: 44, PostgreSQLMajor: 18}); err == nil {
		t.Fatal("release trust root beneath writable ancestor accepted")
	}
}

func TestUpdateRejectsLegacyUnsignedMetadataFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runUpdate([]string{"--directory", "/private/tmp/punaro", "--release-metadata", "/private/tmp/release.json"}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit code=%d", code)
	}
}

func signedUpdateFiles(t *testing.T) (string, string, string) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil { // #nosec G302 -- private test fixture directory.
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "punaro-linux-amd64"), []byte("operator"), 0o600); err != nil {
		t.Fatal(err)
	}
	assembled, err := punarorelease.Assemble(punarorelease.AssembleRequest{
		Directory:               directory,
		Release:                 "v0.1.0",
		Sequence:                1,
		PublishedAt:             time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC),
		ExpiresAt:               time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC),
		MinimumSafeSequence:     1,
		CatalogSequence:         1,
		Image:                   cliTestImage,
		ComposeSHA256:           operator.ComposeManifestSHA256(),
		MigrationManifestSHA256: punaropostgres.MigrationManifestSHA256(),
		Database:                punarorelease.SchemaRange{Min: 1, Max: 44, Target: 44, RollbackFloor: 1},
		PostgreSQLMajor:         18,
		GatewayProtocol:         punarorelease.ProtocolRange{Min: 1, Max: 1},
		ClientProtocol:          punarorelease.ProtocolRange{Min: 1, Max: 1},
		MinimumRecoveryProtocol: 1,
		MinimumBootstrapRelease: "v0.1.0",
		SupportedFrom:           []string{"v0.0.9"},
	})
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := punarorelease.Sign(assembled.ManifestJSON, "punaro-release-1", private)
	if err != nil {
		t.Fatal(err)
	}
	signatureBody, err := punarorelease.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	keysBody, err := punarorelease.EncodePublicKeys("punaro-release-1", public)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(directory, punarorelease.ReleaseManifestFile)
	if err := os.Chmod(manifestPath, 0o600); err != nil {
		t.Fatal(err)
	}
	signaturePath := filepath.Join(directory, punarorelease.ReleaseSignatureFile)
	if err := os.WriteFile(signaturePath, signatureBody, 0o600); err != nil {
		t.Fatal(err)
	}
	catalogEnvelope, err := punarorelease.Sign(assembled.CatalogJSON, "punaro-release-1", private)
	if err != nil {
		t.Fatal(err)
	}
	catalogSignatureBody, err := punarorelease.EncodeEnvelope(catalogEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(directory, punarorelease.CatalogFile)
	if err := os.Chmod(catalogPath, 0o600); err != nil {
		t.Fatal(err)
	}
	catalogSignaturePath := filepath.Join(directory, punarorelease.CatalogSignatureFile)
	if err := os.WriteFile(catalogSignaturePath, catalogSignatureBody, 0o600); err != nil {
		t.Fatal(err)
	}
	keysPath := filepath.Join(directory, "punaro-release.pub")
	if err := os.WriteFile(keysPath, keysBody, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{manifestPath, signaturePath, catalogPath, catalogSignaturePath, keysPath} {
		protectUpdateFixtureFile(t, path)
	}
	return manifestPath, signaturePath, keysPath
}
