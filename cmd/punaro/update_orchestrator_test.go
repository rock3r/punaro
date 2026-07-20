package main

import (
	"context"
	"errors"
	"reflect"
	"testing"

	punaropostgres "github.com/rock3r/punaro/internal/postgres"
)

type fakeUpdateExecutor struct {
	active  punaropostgres.UpdateTransaction
	actions []string
	failAt  string
}

func (fake *fakeUpdateExecutor) action(name string) error {
	fake.actions = append(fake.actions, name)
	if fake.failAt == name {
		return errors.New("injected failure")
	}
	return nil
}

func (fake *fakeUpdateExecutor) Active(context.Context) (punaropostgres.UpdateTransaction, error) {
	if fake.active.UpdateID == "" {
		return punaropostgres.UpdateTransaction{}, punaropostgres.ErrNotFound
	}
	return fake.active, nil
}
func (fake *fakeUpdateExecutor) PreflightAndPull(context.Context) error {
	return fake.action("preflight_pull")
}
func (fake *fakeUpdateExecutor) PrepareResume(context.Context, punaropostgres.UpdateTransaction) error {
	return fake.action("resume_preflight")
}
func (fake *fakeUpdateExecutor) Fence(_ context.Context, request punaropostgres.UpdateRequest) (punaropostgres.UpdateTransaction, error) {
	if err := fake.action("fence"); err != nil {
		return punaropostgres.UpdateTransaction{}, err
	}
	fake.active = punaropostgres.UpdateTransaction{UpdateRequest: request, Phase: punaropostgres.UpdateFenced}
	return fake.active, nil
}
func (fake *fakeUpdateExecutor) StopWriters(context.Context) error {
	return fake.action("stop_writers")
}
func (fake *fakeUpdateExecutor) Backup(context.Context, punaropostgres.UpdateTransaction) (punaropostgres.UpdateBackupMarker, error) {
	if err := fake.action("backup"); err != nil {
		return punaropostgres.UpdateBackupMarker{}, err
	}
	return punaropostgres.UpdateBackupMarker{UpdateID: fake.active.UpdateID}, nil
}
func (fake *fakeUpdateExecutor) Migrate(context.Context, punaropostgres.UpdateTransaction) error {
	return fake.action("migrate")
}
func (fake *fakeUpdateExecutor) StartCandidate(context.Context, punaropostgres.UpdateTransaction) error {
	return fake.action("candidate_ready")
}
func (fake *fakeUpdateExecutor) Doctor(context.Context, punaropostgres.UpdateTransaction) error {
	return fake.action("doctor")
}
func (fake *fakeUpdateExecutor) Publish(context.Context, punaropostgres.UpdateTransaction, bool) error {
	return fake.action("publish")
}
func (fake *fakeUpdateExecutor) AbortToPrevious(context.Context, punaropostgres.UpdateTransaction) error {
	return fake.action("abort_previous")
}
func (fake *fakeUpdateExecutor) Recover(context.Context, punaropostgres.UpdateTransaction, string) error {
	return fake.action("recover")
}
func (fake *fakeUpdateExecutor) Advance(_ context.Context, _ punaropostgres.UpdateTransaction, to punaropostgres.UpdatePhase, _ *punaropostgres.UpdateBackupMarker) (punaropostgres.UpdateTransaction, error) {
	if err := fake.action("advance_" + string(to)); err != nil {
		return fake.active, err
	}
	fake.active.Phase = to
	return fake.active, nil
}

func testUpdateRequest() punaropostgres.UpdateRequest {
	return punaropostgres.UpdateRequest{
		UpdateID: "019b4eb0-21f8-7d93-84df-10e6cf05ce53", SourceRelease: "v0.6.0", TargetRelease: "v0.7.0",
		SourceImage:  "ghcr.io/rock3r/punaro@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TargetImage:  "ghcr.io/rock3r/punaro@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		SourceSchema: 6, TargetSchema: 6, PostgresMajor: 17,
		SchemaMin: 6, SchemaMax: 6, RollbackFloor: 6,
		ReleaseSHA256:           "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		ComposeSHA256:           "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		MigrationManifestSHA256: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
	}
}

func TestExecuteUpdateOrdersIrreversibleProofsBeforeCommit(t *testing.T) {
	fake := &fakeUpdateExecutor{}
	transaction, err := executeUpdate(context.Background(), updateExecution{Request: testUpdateRequest()}, fake)
	if err != nil || transaction.Phase != punaropostgres.UpdateCommitted {
		t.Fatalf("transaction=%#v err=%v", transaction, err)
	}
	want := []string{"preflight_pull", "fence", "resume_preflight", "stop_writers", "advance_writers_stopped", "backup", "advance_backup_verified", "advance_migration_started", "migrate", "advance_migrated", "candidate_ready", "advance_candidate_ready", "doctor", "advance_doctor_passed", "publish", "advance_config_published", "advance_committed"}
	if !reflect.DeepEqual(fake.actions, want) {
		t.Fatalf("actions=%v want=%v", fake.actions, want)
	}
}

func TestExecuteUpdateResumesWithoutRepeatingCompletedExternalWork(t *testing.T) {
	request := testUpdateRequest()
	fake := &fakeUpdateExecutor{active: punaropostgres.UpdateTransaction{UpdateRequest: request, Phase: punaropostgres.UpdateMigrated}}
	transaction, err := executeUpdate(context.Background(), updateExecution{Request: request}, fake)
	if err != nil || transaction.Phase != punaropostgres.UpdateCommitted {
		t.Fatalf("transaction=%#v err=%v", transaction, err)
	}
	if len(fake.actions) < 2 || fake.actions[0] != "resume_preflight" || fake.actions[1] != "candidate_ready" {
		t.Fatalf("resume repeated prior work: %v", fake.actions)
	}
}

func TestExecuteUpdateFailureNeverGuessesExternalSuccess(t *testing.T) {
	request := testUpdateRequest()
	fake := &fakeUpdateExecutor{active: punaropostgres.UpdateTransaction{UpdateRequest: request, Phase: punaropostgres.UpdateMigrated}, failAt: "candidate_ready"}
	transaction, err := executeUpdate(context.Background(), updateExecution{Request: request}, fake)
	if err == nil || transaction.Phase != punaropostgres.UpdateMigrated {
		t.Fatalf("transaction=%#v err=%v", transaction, err)
	}
}

func TestExecuteUpdateAmbiguousMigratorFailureRemainsExactlyResumable(t *testing.T) {
	request := testUpdateRequest()
	fake := &fakeUpdateExecutor{active: punaropostgres.UpdateTransaction{UpdateRequest: request, Phase: punaropostgres.UpdateMigrationStarted}, failAt: "migrate"}
	transaction, err := executeUpdate(context.Background(), updateExecution{Request: request}, fake)
	if err == nil || transaction.Phase != punaropostgres.UpdateMigrationStarted || !reflect.DeepEqual(fake.actions, []string{"resume_preflight", "migrate"}) {
		t.Fatalf("transaction=%#v actions=%v err=%v", transaction, fake.actions, err)
	}
}

func TestExecuteUpdateExplicitRecoveryMovesIrreversibleFailureIntoRecovery(t *testing.T) {
	request := testUpdateRequest()
	fake := &fakeUpdateExecutor{active: punaropostgres.UpdateTransaction{UpdateRequest: request, Phase: punaropostgres.UpdateMigrated}}
	transaction, err := executeUpdate(context.Background(), updateExecution{Request: request, RecoveryMode: "compatible"}, fake)
	if err != nil || transaction.Phase != punaropostgres.UpdateRecovered {
		t.Fatalf("transaction=%#v err=%v", transaction, err)
	}
	want := []string{"advance_recovery_required", "recover", "advance_recovery_ready", "recover", "doctor", "advance_recovery_doctor_passed", "recover", "publish", "advance_recovery_config_published", "advance_recovered"}
	if !reflect.DeepEqual(fake.actions, want) {
		t.Fatalf("actions=%v want=%v", fake.actions, want)
	}
}

func TestExecuteUpdateRejectsChangedResumeAndLateAbort(t *testing.T) {
	request := testUpdateRequest()
	changed := request
	changed.TargetRelease = "v0.8.0"
	fake := &fakeUpdateExecutor{active: punaropostgres.UpdateTransaction{UpdateRequest: request, Phase: punaropostgres.UpdateWritersStopped}}
	if _, err := executeUpdate(context.Background(), updateExecution{Request: changed}, fake); err == nil {
		t.Fatal("changed target resumed existing update")
	}
	fake = &fakeUpdateExecutor{active: punaropostgres.UpdateTransaction{UpdateRequest: request, Phase: punaropostgres.UpdateMigrationStarted}}
	if _, err := executeUpdate(context.Background(), updateExecution{Request: request, Abort: true}, fake); err == nil {
		t.Fatal("post-migration abort succeeded")
	}
}

func TestExecuteUpdatePreMigrationAbortRestartsOldBeforeRelease(t *testing.T) {
	request := testUpdateRequest()
	fake := &fakeUpdateExecutor{active: punaropostgres.UpdateTransaction{UpdateRequest: request, Phase: punaropostgres.UpdateBackupVerified}}
	transaction, err := executeUpdate(context.Background(), updateExecution{Request: request, Abort: true}, fake)
	if err != nil || transaction.Phase != punaropostgres.UpdateAborted || !reflect.DeepEqual(fake.actions, []string{"abort_previous", "advance_aborted"}) {
		t.Fatalf("transaction=%#v actions=%v err=%v", transaction, fake.actions, err)
	}
}
