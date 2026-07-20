package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	punarobackup "github.com/rock3r/punaro/internal/backup"
	"github.com/rock3r/punaro/internal/operator"
	punaropostgres "github.com/rock3r/punaro/internal/postgres"
	punarorelease "github.com/rock3r/punaro/internal/release"
)

const minimumUpdateFreeBytes = uint64(512 << 20)

const updateMigratorOwnerDSNPath = "/run/secrets/punaro-owner-dsn"

var runUpdateDocker = func(ctx context.Context, directory string, environment []string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "docker", arguments...) // #nosec G204 -- fixed executable with validated generated paths and digest-pinned image arguments.
	command.Dir = directory
	command.Env = environment
	return command.CombinedOutput()
}

type commandUpdateExecutor struct {
	installation   operator.Installation
	metadata       punarorelease.Metadata
	request        punaropostgres.UpdateRequest
	stage          operator.UpdateStage
	staged         operator.StagedUpdate
	bridge         *punaropostgres.V5UpdateBridge
	recovery       *operator.Installation
	recoverySchema int64
}

func runUpdate(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("update", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "absolute installation directory")
	metadataPath := flags.String("release-metadata", "", "protected target release metadata JSON")
	sourceRelease := flags.String("source-release", "", "current release name for installations predating release locks")
	abort := flags.Bool("abort", false, "restart the previous image and abort before migration")
	recovery := flags.String("recover", "", "post-migration recovery choice: compatible or restore")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *directory == "" || *metadataPath == "" || (*recovery != "" && *recovery != "compatible" && *recovery != "restore") || (*abort && *recovery != "") {
		return 2
	}
	installation, err := operator.Load(*directory)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "punaro update refused: installation configuration is unavailable")
		return 1
	}
	schema, err := inspectSchema(context.Background(), installation.AppDSNFile)
	if err != nil || (schema.Classification != punaropostgres.Compatible && (schema.Classification != punaropostgres.UpgradeRequired || schema.Version != 5)) {
		_, _ = fmt.Fprintln(stderr, "punaro update refused: source schema is not an intact supported update boundary")
		return 1
	}
	major, err := updatePostgresMajor(context.Background(), installation.AppDSNFile)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "punaro update refused: PostgreSQL major is unavailable")
		return 1
	}
	body, err := readReleaseMetadata(*metadataPath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "punaro update refused: target release metadata is unavailable or unsafe")
		return 1
	}
	metadata, err := punarorelease.Parse(body, punarorelease.Environment{CurrentSchema: schema.Version, PostgreSQLMajor: major})
	if err != nil || metadata.MigrationManifestSHA256 != punaropostgres.MigrationManifestSHA256() {
		_, _ = fmt.Fprintln(stderr, "punaro update refused: target release metadata does not match this updater")
		return 1
	}
	active, activeErr := loadUpdateTransaction(context.Background(), installation, "")
	if activeErr != nil && !errors.Is(activeErr, punaropostgres.ErrNotFound) {
		_, _ = fmt.Fprintln(stderr, "punaro update refused: durable update state is unavailable")
		return 1
	}
	var request punaropostgres.UpdateRequest
	var stage operator.UpdateStage
	if activeErr == nil {
		if (*sourceRelease != "" && *sourceRelease != active.SourceRelease) || !metadataMatchesUpdateRequest(metadata, active.UpdateRequest) {
			_, _ = fmt.Fprintln(stderr, "punaro update refused: supplied release does not match the active update transaction")
			return 1
		}
		*sourceRelease = active.SourceRelease
		request = active.UpdateRequest
		stage = operator.UpdateStage{Directory: installation.Directory, UpdateID: active.UpdateID, PreviousRelease: active.SourceRelease, PreviousImage: active.SourceImage, TargetRelease: active.TargetRelease, TargetImage: active.TargetImage}
	}
	if errors.Is(activeErr, punaropostgres.ErrNotFound) {
		latest, latestErr := loadLatestUpdateTransaction(context.Background(), installation)
		if latestErr == nil && (*sourceRelease == "" || *sourceRelease == latest.SourceRelease) && completedUpdateMatches(latest, metadata, installation.Image, *abort, *recovery) {
			stage := operator.UpdateStage{Directory: installation.Directory, UpdateID: latest.UpdateID, PreviousRelease: latest.SourceRelease, PreviousImage: latest.SourceImage, TargetRelease: latest.TargetRelease, TargetImage: latest.TargetImage}
			if latest.Phase == punaropostgres.UpdateCommitted || latest.Phase == punaropostgres.UpdateRecovered || latest.Phase == punaropostgres.UpdateAborted {
				cleanupErr := operator.AbortStage(stage)
				if latest.Phase == punaropostgres.UpdateCommitted {
					cleanupErr = operator.CompleteStage(stage)
				}
				if cleanupErr != nil {
					_, _ = fmt.Fprintln(stderr, "punaro update reached a terminal outcome, but durable host-stage cleanup is incomplete; rerun the exact command")
					return 1
				}
			}
			return writeJSON(stdout, stderr, map[string]any{"status": latest.Phase, "update_id": latest.UpdateID, "target_release": latest.TargetRelease, "target_image": latest.TargetImage})
		}
		if latestErr == nil && *sourceRelease == "" {
			switch {
			case latest.Phase == punaropostgres.UpdateCommitted && installation.Image == latest.TargetImage:
				*sourceRelease = latest.TargetRelease
			case (latest.Phase == punaropostgres.UpdateRecovered || latest.Phase == punaropostgres.UpdateAborted) && installation.Image == latest.SourceImage:
				*sourceRelease = latest.SourceRelease
			}
		}
		existing, stageErr := operator.ExistingUpdateStage(installation.Directory)
		if stageErr == nil {
			if existing.PreviousImage != installation.Image || existing.TargetRelease != metadata.Release || existing.TargetImage != metadata.Image || (*sourceRelease != "" && *sourceRelease != existing.PreviousRelease) {
				_, _ = fmt.Fprintln(stderr, "punaro update refused: durable host stage does not match the requested release")
				return 1
			}
			*sourceRelease = existing.PreviousRelease
			stage = existing
		} else if !errors.Is(stageErr, operator.ErrUpdateStageNotFound) {
			_, _ = fmt.Fprintln(stderr, "punaro update refused: durable host stage is unavailable")
			return 1
		}
	}
	if *sourceRelease == "" {
		_, _ = fmt.Fprintln(stderr, "punaro update requires --source-release for this installation")
		return 2
	}
	if request.UpdateID == "" {
		updateID := uuid.NewString()
		if stage.UpdateID != "" {
			updateID = stage.UpdateID
		}
		request = punaropostgres.UpdateRequest{
			UpdateID: updateID, SourceRelease: *sourceRelease, TargetRelease: metadata.Release,
			SourceImage: installation.Image, TargetImage: metadata.Image,
			SourceSchema: schema.Version, TargetSchema: metadata.Schema.Target,
			SchemaMin: metadata.Schema.Min, SchemaMax: metadata.Schema.Max, RollbackFloor: metadata.Schema.RollbackFloor,
			PostgresMajor: major, ReleaseSHA256: metadata.ReleaseSHA256, ComposeSHA256: metadata.ComposeSHA256,
			MigrationManifestSHA256: metadata.MigrationManifestSHA256,
		}
	}
	if stage.UpdateID == "" {
		stage = operator.UpdateStage{Directory: installation.Directory, UpdateID: request.UpdateID, PreviousRelease: request.SourceRelease, PreviousImage: request.SourceImage, TargetRelease: request.TargetRelease, TargetImage: request.TargetImage}
	}
	executor := &commandUpdateExecutor{
		installation: installation, metadata: metadata, request: request,
		stage: stage,
	}
	transaction, err := executeUpdate(context.Background(), updateExecution{Request: request, Abort: *abort, RecoveryMode: *recovery}, executor)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "punaro update incomplete: phase=%s; reason=%v; rerun the exact command or select the documented recovery path\n", transaction.Phase, err)
		return 1
	}
	return writeJSON(stdout, stderr, map[string]any{"status": transaction.Phase, "update_id": transaction.UpdateID, "target_release": transaction.TargetRelease, "target_image": transaction.TargetImage})
}

func updatePostgresMajor(ctx context.Context, dsnFile string) (int, error) {
	database, err := punaropostgres.OpenApplication(ctx, punaropostgres.Config{DSNFile: dsnFile})
	if err != nil {
		return 0, err
	}
	defer func() { _ = database.Close() }()
	return database.PostgreSQLMajor(ctx)
}

func readReleaseMetadata(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("release metadata path is invalid")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > punarorelease.MaximumMetadataBytes || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("release metadata file is unsafe")
	}
	file, err := os.Open(path) // #nosec G304 -- explicit protected release metadata path.
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("release metadata changed during open")
	}
	body, err := io.ReadAll(io.LimitReader(file, punarorelease.MaximumMetadataBytes+1))
	if err != nil || len(body) > punarorelease.MaximumMetadataBytes {
		return nil, errors.New("release metadata is too large")
	}
	return body, nil
}

func loadUpdateTransaction(ctx context.Context, installation operator.Installation, updateID string) (punaropostgres.UpdateTransaction, error) {
	admin, err := punaropostgres.OpenAdministration(ctx, punaropostgres.Config{DSNFile: installation.OwnerDSNFile})
	if err != nil {
		state, inspectErr := inspectSchema(ctx, installation.AppDSNFile)
		return punaropostgres.UpdateTransaction{}, classifyUpdateLookupOpenError(state, inspectErr, err)
	}
	defer func() { _ = admin.Close() }()
	if updateID != "" {
		return admin.Update(ctx, updateID)
	}
	return admin.ActiveUpdate(ctx)
}

func loadLatestUpdateTransaction(ctx context.Context, installation operator.Installation) (punaropostgres.UpdateTransaction, error) {
	admin, err := punaropostgres.OpenAdministration(ctx, punaropostgres.Config{DSNFile: installation.OwnerDSNFile})
	if err != nil {
		state, inspectErr := inspectSchema(ctx, installation.AppDSNFile)
		return punaropostgres.UpdateTransaction{}, classifyUpdateLookupOpenError(state, inspectErr, err)
	}
	defer func() { _ = admin.Close() }()
	return admin.LatestUpdate(ctx)
}

func completedUpdateMatches(transaction punaropostgres.UpdateTransaction, metadata punarorelease.Metadata, publishedImage string, abort bool, recovery string) bool {
	request := transaction.UpdateRequest
	if !metadataMatchesUpdateRequest(metadata, request) {
		return false
	}
	switch transaction.Phase {
	case punaropostgres.UpdateCommitted:
		return !abort && recovery == "" && publishedImage == request.TargetImage
	case punaropostgres.UpdateRecovered:
		return !abort && recovery != "" && publishedImage == request.SourceImage
	case punaropostgres.UpdateAborted:
		return abort && recovery == "" && publishedImage == request.SourceImage
	default:
		return false
	}
}

func metadataMatchesUpdateRequest(metadata punarorelease.Metadata, request punaropostgres.UpdateRequest) bool {
	return request.TargetRelease == metadata.Release && request.TargetImage == metadata.Image &&
		request.SchemaMin == metadata.Schema.Min && request.SchemaMax == metadata.Schema.Max && request.TargetSchema == metadata.Schema.Target && request.RollbackFloor == metadata.Schema.RollbackFloor &&
		request.PostgresMajor == metadata.PostgreSQLMajor && request.ReleaseSHA256 == metadata.ReleaseSHA256 && request.ComposeSHA256 == metadata.ComposeSHA256 && request.MigrationManifestSHA256 == metadata.MigrationManifestSHA256
}

func classifyUpdateLookupOpenError(state punaropostgres.SchemaState, inspectErr, openErr error) error {
	if inspectErr == nil && state.Classification == punaropostgres.UpgradeRequired && state.Version == 5 {
		return punaropostgres.ErrNotFound
	}
	return openErr
}

func (executor *commandUpdateExecutor) Active(ctx context.Context) (punaropostgres.UpdateTransaction, error) {
	transaction, err := loadUpdateTransaction(ctx, executor.installation, executor.request.UpdateID)
	if errors.Is(err, punaropostgres.ErrNotFound) {
		return loadUpdateTransaction(ctx, executor.installation, "")
	}
	return transaction, err
}

func (executor *commandUpdateExecutor) PreflightAndPull(ctx context.Context) error {
	if failures := operator.CheckPaths(executor.installation); len(failures) != 0 {
		return errors.New("installation paths are unsafe")
	}
	base := strings.TrimRight(executor.installation.HealthURL, "/")
	orphanedBridge := false
	if probe(ctx, base+"/healthz") != nil || probe(ctx, base+"/readyz") != nil {
		staged, stageErr := operator.ResumeUpdateStage(executor.stage)
		stopped, stopErr := executor.configuredWritersStopped(ctx)
		if stageErr != nil || stopErr != nil || !stopped {
			return errors.New("current stack is unhealthy")
		}
		executor.staged = staged
		orphanedBridge = true
	}
	appIdentity, appErr := postgresDatabaseIdentity(ctx, executor.installation.AppDSNFile)
	ownerIdentity, ownerErr := postgresOwnerDatabaseIdentity(ctx, executor.installation.OwnerDSNFile)
	owner, inspectErr := inspectOwner(ctx, executor.installation.AppDSNFile)
	if appErr != nil || ownerErr != nil || appIdentity != ownerIdentity || inspectErr != nil || owner.ID != executor.installation.OwnerPrincipalID {
		return errors.New("installation database identity changed")
	}
	for _, path := range []string{executor.installation.DataDir, executor.installation.BackupDir} {
		available, err := operator.UpdateAvailableBytes(path)
		if err != nil || available < minimumUpdateFreeBytes {
			return errors.New("update disk capacity is insufficient")
		}
	}
	return executor.prepareTarget(ctx, !orphanedBridge)
}

func (executor *commandUpdateExecutor) PrepareResume(ctx context.Context, transaction punaropostgres.UpdateTransaction) error {
	if err := executor.prepareTarget(ctx, false); err != nil {
		return err
	}
	if transaction.Phase == punaropostgres.UpdateCommitted || transaction.Phase == punaropostgres.UpdateRecovered {
		_ = operator.CompleteStage(executor.stage)
	}
	return nil
}

func (executor *commandUpdateExecutor) prepareTarget(ctx context.Context, pull bool) error {
	if pull {
		_, err := runUpdateDocker(ctx, executor.installation.Directory, updateDockerEnvironment(os.Environ(), executor.installation.Directory), "pull", executor.request.TargetImage)
		if err != nil {
			return errors.New("target image pull failed")
		}
	}
	output, err := runUpdateDocker(ctx, executor.installation.Directory, updateDockerEnvironment(os.Environ(), executor.installation.Directory), "image", "inspect", "--format", "{{json .RepoDigests}}", executor.request.TargetImage)
	if err != nil || !bytes.Contains(output, []byte(strings.Split(executor.request.TargetImage, "@")[1])) {
		return errors.New("pulled target digest cannot be verified locally")
	}
	staged, err := operator.StageUpdate(executor.stage)
	if err != nil {
		return err
	}
	executor.staged = staged
	composeBody, err := os.ReadFile(operator.OverrideFile(staged.CandidateDirectory)) // #nosec G304 -- fixed file in validated operator stage.
	if err != nil {
		return errors.New("candidate Compose artifact is unavailable")
	}
	digest := sha256.Sum256(composeBody)
	if hex.EncodeToString(digest[:]) != executor.metadata.ComposeSHA256 {
		return errors.New("candidate Compose artifact does not match release metadata")
	}
	return nil
}

func (executor *commandUpdateExecutor) Fence(ctx context.Context, request punaropostgres.UpdateRequest) (punaropostgres.UpdateTransaction, error) {
	if request.SourceSchema == 5 && request.TargetSchema == 6 {
		bridge, err := punaropostgres.BeginV5UpdateBridge(ctx, punaropostgres.Config{DSNFile: executor.installation.OwnerDSNFile}, request)
		if err != nil {
			return punaropostgres.UpdateTransaction{}, err
		}
		executor.bridge = bridge
		return bridge.Update(), nil
	}
	admin, err := punaropostgres.OpenAdministration(ctx, punaropostgres.Config{DSNFile: executor.installation.OwnerDSNFile})
	if err != nil {
		return punaropostgres.UpdateTransaction{}, err
	}
	defer func() { _ = admin.Close() }()
	return admin.BeginUpdate(ctx, request)
}

func (executor *commandUpdateExecutor) StopWriters(ctx context.Context) error {
	arguments, err := updateComposeArgs(executor.installation, "stop", "--timeout", "30", "punarod")
	if err != nil {
		return err
	}
	_, err = runUpdateDocker(ctx, executor.installation.Directory, updateDockerEnvironment(os.Environ(), executor.installation.Directory), arguments...)
	if err != nil {
		return errors.New("writer stop failed")
	}
	stopped, err := executor.configuredWritersStopped(ctx)
	if err != nil || !stopped {
		return errors.New("configured writer did not stop")
	}
	return nil
}

func (executor *commandUpdateExecutor) configuredWritersStopped(ctx context.Context) (bool, error) {
	arguments, err := updateComposeArgs(executor.installation, "ps", "--status", "running", "--services")
	if err != nil {
		return false, err
	}
	output, err := runUpdateDocker(ctx, executor.installation.Directory, updateDockerEnvironment(os.Environ(), executor.installation.Directory), arguments...)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(output)) == "", nil
}

func updateComposeArgs(installation operator.Installation, tail ...string) ([]string, error) {
	project, err := operator.ComposeProjectName(installation)
	if err != nil {
		return nil, err
	}
	arguments := []string{"compose", "--project-name", project, "--env-file", operator.EnvFile(installation.Directory), "-f", operator.OverrideFile(installation.Directory)}
	return append(arguments, tail...), nil
}

func (executor *commandUpdateExecutor) Backup(ctx context.Context, transaction punaropostgres.UpdateTransaction) (punaropostgres.UpdateBackupMarker, error) {
	receiptPath := operator.UpdateRecoveryReceiptFile(executor.installation.Directory)
	if receipt, _, err := operator.LoadUpdateRecoveryReceipt(receiptPath); err == nil {
		binding := receiptUpdateBinding(receipt)
		manifest, verifyErr := punarobackup.VerifyForUpdate(receipt.BackupDirectory, binding)
		marker := receiptUpdateMarker(receipt)
		if verifyErr != nil || receipt.BackupID != manifest.BackupID || !updateBackupMarkerMatchesTransaction(marker, transaction) {
			return punaropostgres.UpdateBackupMarker{}, errors.New("durable update recovery receipt does not match this transaction")
		}
		return marker, nil
	} else if _, statErr := os.Lstat(receiptPath); !errors.Is(statErr, os.ErrNotExist) {
		return punaropostgres.UpdateBackupMarker{}, errors.New("durable update recovery receipt is unavailable or unsafe")
	}
	_, path, marker, err := createUpdateBackup(ctx, executor.installation, transaction)
	if err != nil {
		return punaropostgres.UpdateBackupMarker{}, err
	}
	canonicalBackup, err := filepath.EvalSymlinks(path)
	if err != nil {
		return punaropostgres.UpdateBackupMarker{}, errors.New("verified update backup path cannot be resolved")
	}
	receipt := operator.UpdateRecoveryReceipt{
		Version: 1, UpdateID: marker.UpdateID, BackupID: marker.BackupID, BackupDirectory: canonicalBackup,
		InstallationID: marker.InstallationID, TimelineID: marker.TimelineID, ChangeSequence: marker.ChangeSequence,
		SourceSchema: marker.SourceSchema, TargetRelease: marker.TargetRelease, TargetImageDigest: marker.TargetImageDigest,
		ExportedSnapshotID: marker.ExportedSnapshotID, ManifestSHA256: marker.ManifestSHA256,
	}
	if _, err := operator.BindUpdateRecoveryReceipt(executor.stage, receipt); err != nil {
		return punaropostgres.UpdateBackupMarker{}, err
	}
	return marker, nil
}

func receiptUpdateBinding(receipt operator.UpdateRecoveryReceipt) punarobackup.UpdateBinding {
	return punarobackup.UpdateBinding{UpdateID: receipt.UpdateID, SourceSchema: receipt.SourceSchema, InstallationID: receipt.InstallationID, TimelineID: receipt.TimelineID, ChangeSequence: receipt.ChangeSequence, TargetRelease: receipt.TargetRelease, TargetImageDigest: receipt.TargetImageDigest, ExportedSnapshotID: receipt.ExportedSnapshotID, ManifestSHA256: receipt.ManifestSHA256}
}

func receiptUpdateMarker(receipt operator.UpdateRecoveryReceipt) punaropostgres.UpdateBackupMarker {
	return punaropostgres.UpdateBackupMarker{UpdateID: receipt.UpdateID, BackupID: receipt.BackupID, InstallationID: receipt.InstallationID, TimelineID: receipt.TimelineID, ChangeSequence: receipt.ChangeSequence, SourceSchema: receipt.SourceSchema, TargetRelease: receipt.TargetRelease, TargetImageDigest: receipt.TargetImageDigest, ExportedSnapshotID: receipt.ExportedSnapshotID, ManifestSHA256: receipt.ManifestSHA256}
}

func updateBackupMarkerMatchesTransaction(marker punaropostgres.UpdateBackupMarker, transaction punaropostgres.UpdateTransaction) bool {
	_, targetDigest, found := strings.Cut(transaction.TargetImage, "@")
	return found && marker.UpdateID == transaction.UpdateID && marker.InstallationID != "" && marker.TimelineID != "" &&
		marker.SourceSchema == transaction.SourceSchema && marker.TargetRelease == transaction.TargetRelease && marker.TargetImageDigest == targetDigest
}

func (executor *commandUpdateExecutor) Migrate(ctx context.Context, transaction punaropostgres.UpdateTransaction) error {
	authorization := punaropostgres.UpdateMigrationAuthorization{UpdateID: transaction.UpdateID, BackupID: transaction.BackupID, TargetRelease: transaction.TargetRelease, TargetImage: transaction.TargetImage, TargetSchema: transaction.TargetSchema, ExportedSnapshotID: transaction.BackupSnapshotID, ManifestSHA256: transaction.BackupManifestSHA256}
	arguments, err := updateMigratorContainerArgs(executor.installation, authorization)
	if err != nil {
		return err
	}
	migrateCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	if _, err := runUpdateDocker(migrateCtx, executor.installation.Directory, updateDockerEnvironment(os.Environ(), executor.installation.Directory), arguments...); err != nil {
		return errors.New("target migrator container failed")
	}
	return nil
}

func updateMigratorContainerArgs(installation operator.Installation, authorization punaropostgres.UpdateMigrationAuthorization) ([]string, error) {
	if authorization.Validate() != nil || len(operator.CheckPaths(installation)) != 0 {
		return nil, errors.New("target migrator inputs are unavailable or unsafe")
	}
	uid, uidErr := strconv.ParseUint(installation.RuntimeUID, 10, 32)
	gid, gidErr := strconv.ParseUint(installation.RuntimeGID, 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 || gid == 0 {
		return nil, errors.New("target migrator runtime identity is invalid")
	}
	ownerDSNFile, err := filepath.EvalSymlinks(installation.OwnerDSNFile)
	if err != nil || !filepath.IsAbs(ownerDSNFile) || strings.ContainsAny(ownerDSNFile, ",\r\n") {
		return nil, errors.New("target migrator owner credential path is invalid")
	}
	return []string{
		"run", "--rm", "--network", "host", "--read-only",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
		"--user", installation.RuntimeUID + ":" + installation.RuntimeGID,
		"--mount", "type=bind,src=" + ownerDSNFile + ",dst=" + updateMigratorOwnerDSNPath + ",readonly",
		"--entrypoint", "/usr/local/bin/punaro-migrate", authorization.TargetImage,
		"--owner-dsn-file", updateMigratorOwnerDSNPath,
		"--update-id", authorization.UpdateID,
		"--backup-id", authorization.BackupID,
		"--target-release", authorization.TargetRelease,
		"--target-image", authorization.TargetImage,
		"--target-schema", strconv.FormatInt(authorization.TargetSchema, 10),
		"--exported-snapshot-id", authorization.ExportedSnapshotID,
		"--manifest-sha256", authorization.ManifestSHA256,
	}, nil
}

func updateDockerEnvironment(environment []string, directory string) []string {
	sanitized := composeEnvironment(environment, directory)
	result := make([]string, 0, len(sanitized))
	for _, entry := range sanitized {
		name, _, found := strings.Cut(entry, "=")
		upper := strings.ToUpper(name)
		if !found || strings.HasPrefix(upper, "PG") || strings.HasPrefix(upper, "DOCKER_") {
			continue
		}
		result = append(result, entry)
	}
	return result
}

func (executor *commandUpdateExecutor) StartCandidate(ctx context.Context, _ punaropostgres.UpdateTransaction) error {
	candidate, err := operator.Load(executor.staged.CandidateDirectory)
	if err != nil {
		return err
	}
	if err := startServices(ctx, candidate); err != nil {
		return err
	}
	return waitForReady(ctx, candidate)
}

func waitForReady(ctx context.Context, installation operator.Installation) error {
	deadline := time.Now().Add(30 * time.Second)
	readyURL := strings.TrimRight(installation.HealthURL, "/") + "/readyz"
	for {
		if probe(ctx, readyURL) == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("candidate readiness deadline exceeded")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (executor *commandUpdateExecutor) Doctor(ctx context.Context, _ punaropostgres.UpdateTransaction) error {
	var candidate operator.Installation
	if executor.recovery != nil {
		candidate = *executor.recovery
		state, err := inspectSchema(ctx, candidate.AppDSNFile)
		active, maintenanceErr := maintenanceActive(ctx, candidate.AppDSNFile)
		owner, ownerErr := inspectOwner(ctx, candidate.AppDSNFile)
		base := strings.TrimRight(candidate.HealthURL, "/")
		if err != nil || state.Version != executor.recoverySchema || maintenanceErr != nil || !active ||
			len(operator.CheckPaths(candidate)) != 0 || verifyInstallationPair(ctx, candidate.AppDSNFile, candidate.OwnerDSNFile) != nil ||
			ownerErr != nil || owner.ID != candidate.OwnerPrincipalID || probe(ctx, base+"/healthz") != nil || probe(ctx, base+"/readyz") != nil {
			return errors.New("recovery doctor failed")
		}
		return nil
	}
	var err error
	candidate, err = operator.Load(executor.staged.CandidateDirectory)
	if err != nil {
		return err
	}
	result := diagnose(ctx, candidate)
	if !result.Healthy {
		return errors.New("candidate doctor failed")
	}
	return nil
}

func (executor *commandUpdateExecutor) Publish(_ context.Context, _ punaropostgres.UpdateTransaction, recovery bool) error {
	if recovery {
		if executor.recovery == nil {
			return errors.New("recovery installation is unavailable")
		}
		if executor.recovery.Directory == executor.stage.Directory {
			return operator.PublishPreviousUpdate(executor.stage)
		}
		return nil
	}
	_, err := operator.PublishUpdate(executor.stage)
	return err
}

func (executor *commandUpdateExecutor) AbortToPrevious(ctx context.Context, _ punaropostgres.UpdateTransaction) error {
	if err := startServices(ctx, executor.installation); err != nil {
		return err
	}
	if err := waitForReady(ctx, executor.installation); err != nil {
		return err
	}
	if !diagnose(ctx, executor.installation).Healthy {
		return errors.New("previous image doctor failed")
	}
	return operator.AbortStage(executor.stage)
}

func (executor *commandUpdateExecutor) Recover(ctx context.Context, transaction punaropostgres.UpdateTransaction, mode string) error {
	switch mode {
	case "compatible":
		if executor.installation.Image != transaction.SourceImage && executor.installation.Image != transaction.TargetImage {
			return errors.New("previous image is not schema-compatible; restore the bound backup")
		}
		executor.recoverySchema = transaction.TargetSchema
	case "restore":
		state, err := inspectSchema(ctx, executor.installation.AppDSNFile)
		if err != nil || state.Version != transaction.SourceSchema || executor.installation.Image != transaction.SourceImage || transaction.BackupID == "" || transaction.BackupManifestSHA256 == "" {
			return errors.New("restored installation does not match the bound update backup")
		}
		executor.recoverySchema = transaction.SourceSchema
	default:
		return errors.New("update recovery mode is invalid")
	}
	if err := operator.RestorePreviousUpdate(executor.stage); err != nil {
		return err
	}
	previous, err := operator.Load(executor.stage.Directory)
	if err != nil || previous.Image != transaction.SourceImage {
		return errors.New("previous recovery configuration is unavailable")
	}
	executor.installation = previous
	if err := startServices(ctx, executor.installation); err != nil {
		return err
	}
	if err := waitForReady(ctx, executor.installation); err != nil {
		return err
	}
	executor.recovery = &executor.installation
	return nil
}

func (executor *commandUpdateExecutor) Advance(ctx context.Context, transaction punaropostgres.UpdateTransaction, to punaropostgres.UpdatePhase, marker *punaropostgres.UpdateBackupMarker) (punaropostgres.UpdateTransaction, error) {
	if executor.bridge != nil && transaction.Phase == punaropostgres.UpdateFenced && to == punaropostgres.UpdateWritersStopped {
		advanced, err := executor.bridge.CommitWritersStopped(ctx)
		executor.bridge = nil
		return advanced, err
	}
	admin, err := punaropostgres.OpenAdministration(ctx, punaropostgres.Config{DSNFile: executor.installation.OwnerDSNFile})
	if err != nil {
		return transaction, err
	}
	defer func() { _ = admin.Close() }()
	advanced, err := admin.AdvanceUpdate(ctx, transaction.UpdateID, transaction.Phase, to, marker)
	if err == nil && to == punaropostgres.UpdateCommitted {
		if cleanupErr := operator.CompleteStage(executor.stage); cleanupErr != nil {
			return advanced, cleanupErr
		}
	}
	if err == nil && (to == punaropostgres.UpdateRecovered || to == punaropostgres.UpdateAborted) {
		if cleanupErr := operator.AbortStage(executor.stage); cleanupErr != nil {
			return advanced, cleanupErr
		}
	}
	return advanced, err
}
