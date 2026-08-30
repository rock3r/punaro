package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rock3r/punaro/internal/adapter"
	punarobackup "github.com/rock3r/punaro/internal/backup"
	punarodiagnostic "github.com/rock3r/punaro/internal/diagnostic"
	"github.com/rock3r/punaro/internal/ingress"
	"github.com/rock3r/punaro/internal/operator"
	punaropostgres "github.com/rock3r/punaro/internal/postgres"
	"github.com/rock3r/punaro/internal/relay"
)

const cliTestImage = "registry.example/punaro@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestRealPostgresBackupRestoreCleanStackAndRetry(t *testing.T) {
	sourceOwnerDSN := os.Getenv("PUNARO_TEST_RESTORE_SOURCE_OWNER_DSN")
	sourceAppDSN := os.Getenv("PUNARO_TEST_RESTORE_SOURCE_APP_DSN")
	targetOwnerDSN := os.Getenv("PUNARO_TEST_RESTORE_TARGET_OWNER_DSN")
	targetAppDSN := os.Getenv("PUNARO_TEST_RESTORE_TARGET_APP_DSN")
	if sourceOwnerDSN == "" || sourceAppDSN == "" || targetOwnerDSN == "" || targetAppDSN == "" {
		t.Skip("set the PUNARO_TEST_RESTORE_* DSNs to run the real backup/restore gate")
	}
	ctx := context.Background()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil { // #nosec G302 -- private integration-test root.
		t.Fatal(err)
	}
	writeDSN := func(name, dsn string) string {
		path := filepath.Join(root, name)
		// #nosec G703 -- name is a fixed integration-test fixture label.
		if err := os.WriteFile(path, []byte(dsn+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	sourceOwner := writeDSN("source-owner.dsn", sourceOwnerDSN)
	sourceApp := writeDSN("source-app.dsn", sourceAppDSN)
	targetOwner := writeDSN("target-owner.dsn", targetOwnerDSN)
	targetApp := writeDSN("target-app.dsn", targetAppDSN)
	if state, err := punaropostgres.MigratePristinePair(ctx, punaropostgres.Config{DSNFile: sourceApp}, punaropostgres.Config{DSNFile: sourceOwner}); err != nil || state.Classification != punaropostgres.Compatible {
		t.Fatalf("source migration state=%#v err=%v", state, err)
	}
	if state, err := punaropostgres.MigratePristinePair(ctx, punaropostgres.Config{DSNFile: targetApp}, punaropostgres.Config{DSNFile: targetOwner}); err != nil || state.Classification != punaropostgres.Compatible {
		t.Fatalf("target migration state=%#v err=%v", state, err)
	}
	// Return the target to a role-proven pristine state for pg_restore.
	targetDB, err := sql.Open("pgx", targetOwnerDSN)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := targetDB.ExecContext(ctx, `DROP SCHEMA IF EXISTS fleet, auth, relay, attachment, brain, jobs, audit CASCADE`); err != nil {
		_ = targetDB.Close()
		t.Fatal(err)
	}
	if err := targetDB.Close(); err != nil {
		t.Fatal(err)
	}

	sourceData := filepath.Join(root, "source-data")
	sourceBackups := filepath.Join(root, "source-backups")
	targetBackups := filepath.Join(root, "target-backups")
	for _, directory := range []string{filepath.Join(sourceData, "blobs", "ready"), sourceBackups, targetBackups} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(sourceData, "blobs", "ready", "test"), []byte("blob"), 0o600); err != nil {
		t.Fatal(err)
	}
	sourceInstallation, err := operator.Init(ctx, operator.InitOptions{
		Directory: filepath.Join(root, "source-installation"), DataDir: sourceData, BackupDir: sourceBackups,
		Image: cliTestImage, OwnerDSNFile: sourceOwner, AppDSNFile: sourceApp, OwnerName: "Restore integration owner",
		Ingress: ingress.Policy{Mode: ingress.Internet, ListenAddr: "127.0.0.1:8080", PublicURL: "https://punaro.example"},
	}, func(initCtx context.Context, dsnFile, name string) (punaropostgres.Principal, error) {
		admin, openErr := punaropostgres.OpenAdministration(initCtx, punaropostgres.Config{DSNFile: dsnFile})
		if openErr != nil {
			return punaropostgres.Principal{}, openErr
		}
		defer func() { _ = admin.Close() }()
		return admin.BootstrapOwner(initCtx, name)
	})
	if err != nil {
		t.Fatal(err)
	}
	sourceDB, err := sql.Open("pgx", sourceOwnerDSN)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sourceDB.ExecContext(ctx, `INSERT INTO attachment.ready_blob_manifest(storage_path,size_bytes,sha256) VALUES ('ready/test',4,'fa2c8cc4f28176bbeed4b736df569a34c79cd3723e9ec42f9674b4d46ac6b8b8')`); err != nil {
		_ = sourceDB.Close()
		t.Fatal(err)
	}
	if err := sourceDB.Close(); err != nil {
		t.Fatal(err)
	}
	manifest, backupDirectory, err := createBackup(ctx, sourceInstallation)
	if err != nil {
		t.Fatalf("real backup: %v", err)
	}
	request := restoreRequest{
		BackupDirectory: backupDirectory,
		Directory:       filepath.Join(root, "target-installation"),
		DataDir:         filepath.Join(root, "target-data"),
		BackupDir:       targetBackups,
		OwnerDSNFile:    targetOwner,
		AppDSNFile:      targetApp,
	}
	restored, err := restoreBackup(ctx, request)
	if err != nil {
		t.Fatalf("real restore: %v target=%s manifest=%#v", err, restoreTargetDiagnostic(ctx, targetOwner, targetApp, sourceOwnerDSN, targetOwnerDSN), manifest.State)
	}
	if restored.InstallationID != manifest.State.InstallationID || restored.TimelineID == manifest.State.TimelineID || restored.ChangeSequence != manifest.State.ChangeSequence {
		t.Fatalf("restored state=%#v manifest=%#v", restored, manifest.State)
	}
	loaded, err := operator.Load(request.Directory)
	if err != nil || loaded.OwnerPrincipalID != sourceInstallation.OwnerPrincipalID || loaded.DataDir != request.DataDir || loaded.OwnerDSNFile != targetOwner || loaded.AppDSNFile != targetApp {
		t.Fatalf("restored installation=%#v err=%v", loaded, err)
	}
	if body, err := os.ReadFile(filepath.Join(request.DataDir, "blobs", "ready", "test")); err != nil || string(body) != "blob" { // #nosec G304 -- fixed integration-test restore child.
		t.Fatalf("restored blob=%q err=%v", body, err)
	}
	if retried, err := restoreBackup(ctx, request); err != nil || retried != restored {
		t.Fatalf("same-command resume state=%#v err=%v", retried, err)
	}
}

func TestRealV5UpdateBackupReceiptRestoreAndRecoveryRetry(t *testing.T) {
	sourceOwnerDSN := os.Getenv("PUNARO_TEST_UPDATE_SOURCE_OWNER_DSN")
	sourceAppDSN := os.Getenv("PUNARO_TEST_UPDATE_SOURCE_APP_DSN")
	targetOwnerDSN := os.Getenv("PUNARO_TEST_UPDATE_TARGET_OWNER_DSN")
	targetAppDSN := os.Getenv("PUNARO_TEST_UPDATE_TARGET_APP_DSN")
	if sourceOwnerDSN == "" || sourceAppDSN == "" || targetOwnerDSN == "" || targetAppDSN == "" {
		t.Skip("set the PUNARO_TEST_UPDATE_* DSNs to run the v5 update recovery gate")
	}
	ctx := context.Background()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil { // #nosec G302 -- private integration-test root.
		t.Fatal(err)
	}
	writeDSN := func(name, dsn string) string {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(dsn+"\n"), 0o600); err != nil { // #nosec G703 -- fixed fixture labels.
			t.Fatal(err)
		}
		return path
	}
	sourceOwner := writeDSN("update-source-owner.dsn", sourceOwnerDSN)
	sourceApp := writeDSN("update-source-app.dsn", sourceAppDSN)
	targetOwner := writeDSN("update-target-owner.dsn", targetOwnerDSN)
	targetApp := writeDSN("update-target-app.dsn", targetAppDSN)
	stageV5Database(ctx, t, sourceOwnerDSN)

	sourceData := filepath.Join(root, "update-source-data")
	sourceBackups := filepath.Join(root, "update-source-backups")
	targetBackups := filepath.Join(root, "update-target-backups")
	for _, directory := range []string{filepath.Join(sourceData, "blobs", "ready"), sourceBackups, targetBackups} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	sourceInstallation, err := operator.Init(ctx, operator.InitOptions{
		Directory: filepath.Join(root, "update-source-installation"), DataDir: sourceData, BackupDir: sourceBackups,
		Image: cliTestImage, OwnerDSNFile: sourceOwner, AppDSNFile: sourceApp, OwnerName: "Update restore integration owner",
		Ingress: ingress.Policy{Mode: ingress.Internet, ListenAddr: "127.0.0.1:8080", PublicURL: "https://punaro.example"},
	}, func(initCtx context.Context, _ string, name string) (punaropostgres.Principal, error) {
		database, openErr := sql.Open("pgx", sourceOwnerDSN)
		if openErr != nil {
			return punaropostgres.Principal{}, openErr
		}
		defer func() { _ = database.Close() }()
		owner := punaropostgres.Principal{ID: "019b4eb0-c447-7c76-b73f-f442bab67061", Kind: punaropostgres.PrincipalKindOwner, DisplayName: name}
		if _, insertErr := database.ExecContext(initCtx, `INSERT INTO auth.principals(id,kind,display_name) VALUES ($1,'owner',$2)`, owner.ID, owner.DisplayName); insertErr != nil {
			return punaropostgres.Principal{}, insertErr
		}
		if _, insertErr := database.ExecContext(initCtx, `INSERT INTO auth.installation_owner(principal_id) VALUES ($1)`, owner.ID); insertErr != nil {
			return punaropostgres.Principal{}, insertErr
		}
		return owner, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sourceDB, err := sql.Open("pgx", sourceOwnerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sourceDB.Close() }()
	var postgresMajor int
	if err := sourceDB.QueryRowContext(ctx, `SELECT current_setting('server_version_num')::integer / 10000`).Scan(&postgresMajor); err != nil {
		t.Fatal(err)
	}
	targetImage := "registry.example/punaro@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	updateRequest := punaropostgres.UpdateRequest{
		UpdateID: "019b4eb0-798c-7a52-8d29-8560fcbb2083", SourceRelease: "v0.6.0", TargetRelease: "v0.7.0",
		SourceImage: cliTestImage, TargetImage: targetImage, SourceSchema: 5, TargetSchema: 6, SchemaMin: 5, SchemaMax: 6, RollbackFloor: 5,
		PostgresMajor: postgresMajor, ReleaseSHA256: strings.Repeat("b", 64), ComposeSHA256: strings.Repeat("c", 64),
		MigrationManifestSHA256: punaropostgres.MigrationManifestSHA256(),
	}
	bridge, err := punaropostgres.BeginV5UpdateBridge(ctx, punaropostgres.Config{DSNFile: sourceOwner}, updateRequest)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := bridge.CommitWritersStopped(ctx)
	if err != nil || transaction.Phase != punaropostgres.UpdateWritersStopped {
		t.Fatalf("v5 bridge transaction=%#v err=%v", transaction, err)
	}
	stage := operator.UpdateStage{Directory: sourceInstallation.Directory, UpdateID: updateRequest.UpdateID, PreviousRelease: updateRequest.SourceRelease, PreviousImage: updateRequest.SourceImage, TargetRelease: updateRequest.TargetRelease, TargetImage: updateRequest.TargetImage}
	staged, err := operator.StageUpdate(stage)
	if err != nil {
		t.Fatal(err)
	}
	executor := &commandUpdateExecutor{installation: sourceInstallation, request: updateRequest, stage: stage, staged: staged}
	marker, err := executor.Backup(ctx, transaction)
	if err != nil {
		t.Fatalf("v5 update backup: %v", err)
	}
	receiptFile := operator.UpdateRecoveryReceiptFile(sourceInstallation.Directory)
	if _, _, err := operator.LoadUpdateRecoveryReceipt(receiptFile); err != nil {
		t.Fatalf("independent recovery receipt: %v", err)
	}
	sourceAdmin, err := punaropostgres.OpenAdministration(ctx, punaropostgres.Config{DSNFile: sourceOwner})
	if err != nil {
		t.Fatal(err)
	}
	if transaction, err = sourceAdmin.AdvanceUpdate(ctx, transaction.UpdateID, punaropostgres.UpdateWritersStopped, punaropostgres.UpdateBackupVerified, &marker); err != nil || transaction.Phase != punaropostgres.UpdateBackupVerified {
		_ = sourceAdmin.Close()
		t.Fatalf("record v5 backup marker transaction=%#v err=%v", transaction, err)
	}
	if err := sourceAdmin.Close(); err != nil {
		t.Fatal(err)
	}
	receipt, _, err := operator.LoadUpdateRecoveryReceipt(receiptFile)
	if err != nil {
		t.Fatal(err)
	}
	restore := restoreRequest{
		BackupDirectory: receipt.BackupDirectory, RecoveryReceipt: receiptFile,
		Directory: filepath.Join(root, "update-target-installation"), DataDir: filepath.Join(root, "update-target-data"), BackupDir: targetBackups,
		OwnerDSNFile: targetOwner, AppDSNFile: targetApp,
	}
	restored, err := restoreBackup(ctx, restore)
	if err != nil {
		t.Fatalf("receipt-bound v5 restore: %v", err)
	}
	if retried, retryErr := restoreBackup(ctx, restore); retryErr != nil || retried != restored {
		t.Fatalf("receipt-bound restore retry=%#v err=%v", retried, retryErr)
	}
	targetAdmin, err := punaropostgres.OpenAdministration(ctx, punaropostgres.Config{DSNFile: targetOwner})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = targetAdmin.Close() }()
	active, err := targetAdmin.ActiveUpdate(ctx)
	if err != nil || active.UpdateID != updateRequest.UpdateID || active.Phase != punaropostgres.UpdateRecoveryRequired || active.BackupManifestSHA256 != marker.ManifestSHA256 {
		t.Fatalf("restored active update=%#v err=%v", active, err)
	}
	for _, transition := range [][2]punaropostgres.UpdatePhase{{punaropostgres.UpdateRecoveryRequired, punaropostgres.UpdateRecoveryReady}, {punaropostgres.UpdateRecoveryReady, punaropostgres.UpdateRecoveryDoctor}, {punaropostgres.UpdateRecoveryDoctor, punaropostgres.UpdateRecoveryConfig}, {punaropostgres.UpdateRecoveryConfig, punaropostgres.UpdateRecovered}} {
		active, err = targetAdmin.AdvanceUpdate(ctx, active.UpdateID, transition[0], transition[1], nil)
		if err != nil || active.Phase != transition[1] {
			t.Fatalf("recovery transition %s -> %s active=%#v err=%v", transition[0], transition[1], active, err)
		}
	}
}

func stageV5Database(ctx context.Context, t *testing.T, ownerDSN string) {
	t.Helper()
	database, err := sql.Open("pgx", ownerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	migrations := punaropostgres.CurrentManifest().Migrations[:5]
	for index, migration := range migrations {
		tx, beginErr := database.BeginTx(ctx, nil)
		if beginErr != nil {
			t.Fatal(beginErr)
		}
		if index == 0 {
			_, err = tx.ExecContext(ctx, `CREATE SCHEMA jobs; CREATE TABLE jobs.schema_migrations (version bigint PRIMARY KEY,name text NOT NULL,checksum char(64) NOT NULL,compatibility_floor bigint NOT NULL,status text NOT NULL CHECK (status IN ('applying','applied')),started_at timestamptz NOT NULL DEFAULT statement_timestamp(),applied_at timestamptz)`)
		} else {
			_, err = tx.ExecContext(ctx, `INSERT INTO jobs.schema_migrations(version,name,checksum,compatibility_floor,status) VALUES ($1,$2,$3,$4,'applying')`, migration.Version, migration.Name, migration.Checksum, migration.CompatibilityFloor)
		}
		if err == nil && index == 0 {
			_, err = tx.ExecContext(ctx, `INSERT INTO jobs.schema_migrations(version,name,checksum,compatibility_floor,status) VALUES ($1,$2,$3,$4,'applying')`, migration.Version, migration.Name, migration.Checksum, migration.CompatibilityFloor)
		}
		if err == nil {
			_, err = tx.ExecContext(ctx, migration.SQL)
		}
		if err == nil {
			_, err = tx.ExecContext(ctx, `UPDATE jobs.schema_migrations SET status='applied',applied_at=statement_timestamp() WHERE version=$1 AND status='applying'`, migration.Version)
		}
		if err != nil {
			_ = tx.Rollback()
			t.Fatalf("stage v5 migration %d: %v", migration.Version, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
}

func restoreTargetDiagnostic(ctx context.Context, ownerDSNFile, appDSNFile, sourceOwnerDSN, ownerDSN string) string {
	db, err := sql.Open("pgx", ownerDSN)
	if err != nil {
		return "open-failed"
	}
	defer func() { _ = db.Close() }()
	var installationID, timelineID string
	var changeSequence, eventCount int64
	if err := db.QueryRowContext(ctx, `SELECT installation_id::text,timeline_id::text,change_sequence FROM jobs.server_state WHERE singleton`).Scan(&installationID, &timelineID, &changeSequence); err != nil {
		return "state-unavailable"
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM jobs.restore_events`).Scan(&eventCount); err != nil {
		return "events-unavailable"
	}
	appState, appErr := inspectSchema(ctx, appDSNFile)
	admin, adminErr := punaropostgres.OpenAdministration(ctx, punaropostgres.Config{DSNFile: ownerDSNFile})
	if admin != nil {
		_ = admin.Close()
	}
	return fmt.Sprintf("installation=%s timeline=%s sequence=%d events=%d app-state=%s/%d app-err=%v admin-err=%v catalog-diff=%s", installationID, timelineID, changeSequence, eventCount, appState.Classification, appState.Version, appErr, adminErr, restoreCatalogDifference(ctx, sourceOwnerDSN, ownerDSN))
}

func restoreCatalogDifference(ctx context.Context, sourceDSN, targetDSN string) string {
	queries := []string{
		`SELECT format('namespace:%s:%s:%s',nspname,pg_get_userbyid(nspowner),COALESCE(nspacl::text,'')) FROM pg_namespace WHERE nspname IN ('auth','relay','attachment','brain','jobs','audit') ORDER BY nspname`,
		`SELECT format('relation:%s:%s:%s:%s',class.oid::regclass::text,class.relkind,pg_get_userbyid(class.relowner),COALESCE(class.relacl::text,'')) FROM pg_class AS class JOIN pg_namespace AS namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname IN ('auth','relay','attachment','brain','jobs','audit') ORDER BY class.oid::regclass::text`,
		`SELECT format('routine:%s:%s:%s:%s:%s:%s',proc.oid::regprocedure::text,md5(proc.prosrc),pg_get_userbyid(proc.proowner),proc.proconfig::text,proc.prosecdef,COALESCE(proc.proacl::text,'')) FROM pg_proc AS proc JOIN pg_namespace AS namespace ON namespace.oid=proc.pronamespace WHERE namespace.nspname IN ('auth','relay','attachment','brain','jobs','audit') ORDER BY proc.oid::regprocedure::text`,
		`SELECT format('constraint:%s:%s:%s:%s:%s',conrelid::regclass::text,conname,contype,conkey::text,COALESCE(pg_get_expr(conbin,conrelid),'')) FROM pg_constraint JOIN pg_namespace ON pg_namespace.oid=connamespace WHERE nspname IN ('auth','relay','attachment','brain','jobs','audit') ORDER BY conrelid::regclass::text,conname`,
		`SELECT format('column:%s:%s:%s:%s:%s:%s',attribute.attrelid::regclass::text,attribute.attname,attribute.atttypid::regtype::text,attribute.atttypmod,attribute.attnotnull,COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),'')) FROM pg_attribute AS attribute JOIN pg_class AS class ON class.oid=attribute.attrelid JOIN pg_namespace AS namespace ON namespace.oid=class.relnamespace LEFT JOIN pg_attrdef AS default_value ON default_value.adrelid=attribute.attrelid AND default_value.adnum=attribute.attnum WHERE namespace.nspname IN ('auth','relay','attachment','brain','jobs','audit') AND attribute.attnum>0 AND NOT attribute.attisdropped ORDER BY attribute.attrelid::regclass::text,attribute.attnum`,
		`SELECT format('index:%s:%s',indexrelid::regclass::text,pg_get_indexdef(indexrelid)) FROM pg_index JOIN pg_class AS class ON class.oid=indrelid JOIN pg_namespace AS namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname IN ('auth','relay','attachment','brain','jobs','audit') ORDER BY indexrelid::regclass::text`,
		`SELECT format('trigger:%s:%s:%s:%s',tgrelid::regclass::text,tgname,tgenabled,pg_get_triggerdef(pg_trigger.oid)) FROM pg_trigger JOIN pg_class AS class ON class.oid=tgrelid JOIN pg_namespace AS namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname IN ('auth','relay','attachment','brain','jobs','audit') AND NOT tgisinternal ORDER BY tgrelid::regclass::text,tgname`,
		`SELECT format('migration:%s:%s:%s:%s',version,name,checksum,status) FROM jobs.schema_migrations ORDER BY version`,
	}
	read := func(dsn string) (map[string]bool, error) {
		db, err := sql.Open("pgx", dsn)
		if err != nil {
			return nil, err
		}
		defer func() { _ = db.Close() }()
		result := map[string]bool{}
		for _, query := range queries {
			rows, err := db.QueryContext(ctx, query)
			if err != nil {
				return nil, err
			}
			for rows.Next() {
				var line string
				if err := rows.Scan(&line); err != nil {
					_ = rows.Close()
					return nil, err
				}
				result[line] = true
			}
			if err := rows.Close(); err != nil {
				return nil, err
			}
		}
		return result, nil
	}
	source, sourceErr := read(sourceDSN)
	target, targetErr := read(targetDSN)
	if sourceErr != nil || targetErr != nil {
		return fmt.Sprintf("unavailable:%v/%v", sourceErr, targetErr)
	}
	differences := make([]string, 0)
	for line := range source {
		if !target[line] {
			differences = append(differences, "source:"+line)
		}
	}
	for line := range target {
		if !source[line] {
			differences = append(differences, "target:"+line)
		}
	}
	slices.Sort(differences)
	joined := strings.Join(differences, ";")
	if len(joined) > 16<<10 {
		joined = joined[:16<<10]
	}
	return joined
}

func testInstallation(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{"data", "backup"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"owner.dsn", "app.dsn"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("postgres://invalid\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	directory := filepath.Join(root, "installation")
	_, err := operator.Init(context.Background(), operator.InitOptions{Directory: directory, DataDir: filepath.Join(root, "data"), BackupDir: filepath.Join(root, "backup"), Image: cliTestImage, OwnerDSNFile: filepath.Join(root, "owner.dsn"), AppDSNFile: filepath.Join(root, "app.dsn"), OwnerName: "owner", Ingress: ingress.Policy{Mode: ingress.Internet, ListenAddr: "127.0.0.1:8080", PublicURL: "https://punaro.example"}}, func(context.Context, string, string) (punaropostgres.Principal, error) {
		return punaropostgres.Principal{ID: "11111111-1111-4111-8111-111111111111"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestBackupBlobRootUsesConfiguredTrustedAttachmentDirectory(t *testing.T) {
	installation := operator.Installation{DataDir: "/var/lib/punaro-data", TrustedAttachmentsEnabled: true, TrustedAttachmentBlobDir: "/var/lib/punaro-data/attachments"}
	if got, want := backupBlobRoot(installation), installation.TrustedAttachmentBlobDir; got != want {
		t.Fatalf("blob root=%q want=%q", got, want)
	}
	installation.TrustedAttachmentsEnabled = false
	if got, want := backupBlobRoot(installation), "/var/lib/punaro-data/blobs"; got != want {
		t.Fatalf("legacy blob root=%q want=%q", got, want)
	}
}

func preserveDependencies(t *testing.T) {
	t.Helper()
	originalInspect, originalOwner, originalMigrate, originalMaintenance := inspectSchema, inspectOwner, migratePristinePair, maintenanceActive
	originalCreate, originalRecover := createOwner, recoverInstallationOwner
	originalVerify := verifyInstallationPair
	originalStart, originalProbe, originalIssue, originalListClients, originalRevokeClient := startServices, probe, issueEnrollment, listClients, revokeClient
	originalBackup, originalListBackups, originalVerifyBackup, originalRestore := createOperatorBackup, listOperatorBackups, verifyOperatorBackup, restoreOperatorBackup
	originalServerDoctorInspect, originalServerDoctorLoad := serverDoctorInspect, serverDoctorLoad
	originalUpdateStageCheck, originalCatalogAcceptanceCheck := serverDoctorUpdateStageCheck, serverDoctorCatalogAcceptanceCheck
	originalMailCutoverPreflight := inspectMailCutoverPreflight
	originalReconcileUpdateTransaction := reconcileUpdateTransaction
	originalRunUpdateDocker := runUpdateDocker
	t.Cleanup(func() {
		inspectSchema, inspectOwner, migratePristinePair, maintenanceActive = originalInspect, originalOwner, originalMigrate, originalMaintenance
		createOwner, recoverInstallationOwner = originalCreate, originalRecover
		verifyInstallationPair = originalVerify
		startServices, probe = originalStart, originalProbe
		issueEnrollment = originalIssue
		listClients, revokeClient = originalListClients, originalRevokeClient
		createOperatorBackup, listOperatorBackups, verifyOperatorBackup, restoreOperatorBackup = originalBackup, originalListBackups, originalVerifyBackup, originalRestore
		serverDoctorInspect = originalServerDoctorInspect
		serverDoctorLoad = originalServerDoctorLoad
		serverDoctorUpdateStageCheck = originalUpdateStageCheck
		serverDoctorCatalogAcceptanceCheck = originalCatalogAcceptanceCheck
		inspectMailCutoverPreflight = originalMailCutoverPreflight
		reconcileUpdateTransaction = originalReconcileUpdateTransaction
		runUpdateDocker = originalRunUpdateDocker
	})
	inspectOwner = func(context.Context, string) (punaropostgres.Principal, error) {
		return punaropostgres.Principal{ID: "11111111-1111-4111-8111-111111111111", DisplayName: "owner"}, nil
	}
	verifyInstallationPair = func(context.Context, string, string) error { return nil }
	migratePristinePair = func(context.Context, string, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 5}, nil
	}
	maintenanceActive = func(context.Context, string) (bool, error) { return false, nil }
	serverDoctorInspect = func(context.Context, operator.Installation, string, bool, string) serverDoctorState {
		return healthyServerDoctorState()
	}
	serverDoctorUpdateStageCheck = directServerDoctorUpdateStage
	serverDoctorCatalogAcceptanceCheck = func(context.Context, string, int64) knownDoctorBool { return known(true, true) }
}

func TestServerDoctorDeadlineIncludesInstallationLoad(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	loadCalled := false
	serverDoctorLoad = func(ctx context.Context, gotDirectory string) (operator.Installation, error) {
		loadCalled = true
		deadline, ok := ctx.Deadline()
		if !ok || gotDirectory != directory || time.Until(deadline) <= 0 || time.Until(deadline) > 2*time.Second {
			t.Fatalf("directory=%q deadline=%v ok=%v", gotDirectory, deadline, ok)
		}
		return operator.Installation{}, context.DeadlineExceeded
	}
	serverDoctorInspect = func(context.Context, operator.Installation, string, bool, string) serverDoctorState {
		t.Fatal("doctor inspection ran after installation load failed")
		return serverDoctorState{}
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"doctor", "--directory", directory, "--machine-id", "punaro-lxc", "--timeout", "1s"}, &stdout, &stderr); code != 1 || !loadCalled {
		t.Fatalf("code=%d load_called=%v stdout=%q stderr=%q", code, loadCalled, stdout.String(), stderr.String())
	}
	report, err := punarodiagnostic.Decode(bytes.NewReader(stdout.Bytes()))
	if err != nil || report.Component != punarodiagnostic.ComponentServer || report.Healthy {
		t.Fatalf("report=%#v err=%v", report, err)
	}
}

func healthyServerDoctorState() serverDoctorState {
	return serverDoctorState{
		MachineID: "punaro-lxc", Release: "v0.1.0-alpha.1", ReleaseSequence: 1, CatalogSequence: 1, Protocol: 1,
		InstalledRelease: knownDoctorBool{Known: true, OK: true}, OperatorBinaryRelease: knownDoctorBool{Known: true, OK: true}, RunningImage: knownDoctorBool{Known: true, OK: true},
		ComposeBinding: knownDoctorBool{Known: true, OK: true}, MigrationBinding: knownDoctorBool{Known: true, OK: true},
		PostgresMajor: 18, ExpectedPostgresMajor: 18, PostgresKnown: true, Storage: knownDoctorBool{Known: true, OK: true},
		BackupAvailable: knownDoctorBool{Known: true, OK: true}, BackupFresh: knownDoctorBool{Known: true, OK: true},
		UpdateTransaction: knownDoctorBool{Known: true, OK: true}, RecoveryReceipt: knownDoctorBool{Known: true, OK: true}, UpdateRecovery: knownDoctorBool{Known: true, OK: true}, DatabasePrivate: knownDoctorBool{Known: true, OK: true},
		HealthPrivate: knownDoctorBool{Known: true, OK: true}, AdminPrivate: knownDoctorBool{Known: true, OK: true},
		BlobPrivate: knownDoctorBool{Known: true, OK: true}, TunnelRoute: knownDoctorBool{Known: true, OK: true},
		TunnelOrigin: knownDoctorBool{Known: true, OK: true}, AccessAdmission: knownDoctorBool{Known: true, OK: true},
		RelayEnrollment: knownDoctorBool{Known: true, OK: true}, RelayProtocol: knownDoctorBool{Known: true, OK: true}, GatewayInstalled: knownDoctorBool{Known: true, OK: true},
		GatewayEnabled: knownDoctorBool{Known: true, OK: true}, GatewayRunning: knownDoctorBool{Known: true, OK: true}, GatewayExecutable: knownDoctorBool{Known: true, OK: true},
		GatewayExitStatus: knownDoctorBool{Known: true, OK: true}, GatewayRestartState: knownDoctorBool{Known: true, OK: true}, GatewayRelease: knownDoctorBool{Known: true, OK: true},
	}
}

func TestServerDoctorComposeBindingAcceptsGeneratedReleaseArtifact(t *testing.T) {
	directory := testInstallation(t)
	previous := serverDoctorFileDigest
	serverDoctorFileDigest = directServerDoctorFileDigest
	t.Cleanup(func() { serverDoctorFileDigest = previous })
	binding := fileDigestMatches(t.Context(), operator.OverrideFile(directory), operator.ComposeManifestSHA256())
	if !binding.Known || !binding.OK {
		t.Fatalf("generated release Compose binding=%#v", binding)
	}
}

func TestInstalledReleaseUsesTaggedRepositoryIdentityWhenDigestIsNotKnownAtBuildTime(t *testing.T) {
	digest := strings.Repeat("a", 64)
	installed := "ghcr.io/rock3r/punaro@sha256:" + digest
	if !installedReleaseMatchesBuildIdentity("ghcr.io/rock3r/punaro:v0.1.0-alpha.1", installed, "v0.1.0-alpha.1") {
		t.Fatal("release-tagged build identity did not accept the repository's digest-pinned installation")
	}
	if !installedReleaseMatchesBuildIdentity(installed, installed, "v0.1.0-alpha.1") {
		t.Fatal("native exact-digest build identity did not match")
	}
	for _, expected := range []string{
		"",
		"ghcr.io/other/punaro:v0.1.0-alpha.1",
		"ghcr.io/rock3r/punaro:v0.1.0-alpha.2",
		"ghcr.io/rock3r/punaro:latest",
	} {
		if installedReleaseMatchesBuildIdentity(expected, installed, "v0.1.0-alpha.1") {
			t.Fatalf("invalid build identity %q matched", expected)
		}
	}
}

func TestDoctorFileDigestCommandValidatesAndHashesRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "compose.operator.yaml")
	body := []byte("services: {}\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if code := runDoctorFileDigest([]string{"--path", path}, &stdout); code != 0 {
		t.Fatalf("digest command code=%d", code)
	}
	want := sha256.Sum256(body)
	var state serverDoctorFileDigestState
	if json.Unmarshal(stdout.Bytes(), &state) != nil || !state.Known || state.Digest != hex.EncodeToString(want[:]) {
		t.Fatalf("digest state=%#v want=%x", state, want)
	}
}

func TestDoctorFileDigestDelegatesCompleteInspectionToIsolatedHelper(t *testing.T) {
	previous := serverDoctorFileDigest
	called := false
	serverDoctorFileDigest = func(_ context.Context, path string) serverDoctorFileDigestState {
		called = true
		if path != "/stalled/compose.operator.yaml" {
			t.Fatalf("digest path=%q", path)
		}
		return serverDoctorFileDigestState{}
	}
	t.Cleanup(func() { serverDoctorFileDigest = previous })
	state := fileDigestMatches(t.Context(), "/stalled/compose.operator.yaml", strings.Repeat("a", 64))
	if !called || state.Known {
		t.Fatalf("isolated digest called=%t state=%#v", called, state)
	}
}

func TestDoctorDSNReadCommandAndCredentialPreloadStayInsideDeadline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.dsn")
	if err := os.WriteFile(path, []byte("postgres://punaro_app@localhost/punaro?sslmode=disable\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if code := runDoctorDSNRead([]string{"--path", path}, &stdout); code != 0 || stdout.String() != "postgres://punaro_app@localhost/punaro?sslmode=disable" {
		t.Fatalf("DSN helper code=%d output=%q", code, stdout.String())
	}

	previous := serverDoctorDSNRead
	serverDoctorDSNRead = func(ctx context.Context, _ string) (string, bool) {
		<-ctx.Done()
		return "", false
	}
	t.Cleanup(func() { serverDoctorDSNRead = previous })
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	diagnostic := withServerDoctorCredentials(ctx, operator.Installation{AppDSNFile: "/stalled/app.dsn", OwnerDSNFile: "/stalled/owner.dsn"})
	if _, marked, available := serverDoctorCredential(diagnostic, "/stalled/app.dsn"); !marked || available || time.Since(started) > time.Second {
		t.Fatalf("deadline credential marked=%t available=%t elapsed=%s", marked, available, time.Since(started))
	}
}

func TestDoctorPathCheckCommandAndIsolationStayInsideDeadline(t *testing.T) {
	installation, err := operator.Load(testInstallation(t))
	if err != nil {
		t.Fatal(err)
	}
	request, ok := encodeServerDoctorPathRequest(installation)
	if !ok {
		t.Fatal("path-check request encoding failed")
	}
	var stdout bytes.Buffer
	if code := runDoctorPathCheck([]string{"--request", request}, &stdout); code != 0 {
		t.Fatalf("path-check helper code=%d", code)
	}
	var failures []string
	if json.Unmarshal(stdout.Bytes(), &failures) != nil || len(failures) != 0 {
		t.Fatalf("path-check failures=%#v output=%q", failures, stdout.String())
	}

	if runtime.GOOS == "windows" {
		return
	}
	blocker := filepath.Join(t.TempDir(), "blocked-path-check")
	if err := os.WriteFile(blocker, []byte("#!/bin/sh\nexec sleep 10\n"), 0o700); err != nil { // #nosec G306 -- private executable deadline fixture.
		t.Fatal(err)
	}
	previous := serverDoctorPathExecutable
	serverDoctorPathExecutable = func() (string, error) { return blocker, nil }
	t.Cleanup(func() { serverDoctorPathExecutable = previous })
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, known := isolatedServerDoctorPaths(ctx, installation); known || time.Since(started) > time.Second {
		t.Fatalf("isolated path check known=%t elapsed=%s", known, time.Since(started))
	}
}

func TestDoctorStorageCommandAndIsolationStayInsideDeadline(t *testing.T) {
	if runtime.GOOS != "windows" {
		var stdout bytes.Buffer
		if code := runDoctorStorageCheck([]string{"--path", t.TempDir(), "--minimum", "1"}, &stdout); code != 0 {
			t.Fatalf("storage helper code=%d", code)
		}
		var state knownDoctorBool
		if json.Unmarshal(stdout.Bytes(), &state) != nil || !state.Known || !state.OK {
			t.Fatalf("storage helper state=%#v output=%q", state, stdout.String())
		}
	}
	if runtime.GOOS == "windows" {
		return
	}
	blocker := filepath.Join(t.TempDir(), "blocked-storage-check")
	if err := os.WriteFile(blocker, []byte("#!/bin/sh\nexec sleep 10\n"), 0o700); err != nil { // #nosec G306 -- private executable deadline fixture.
		t.Fatal(err)
	}
	previous := serverDoctorStorageExecutable
	serverDoctorStorageExecutable = func() (string, error) { return blocker, nil }
	t.Cleanup(func() { serverDoctorStorageExecutable = previous })
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	if state := isolatedServerDoctorStorage(ctx, t.TempDir(), 1); state.Known || time.Since(started) > time.Second {
		t.Fatalf("isolated storage state=%#v elapsed=%s", state, time.Since(started))
	}
}

func TestDoctorUpdateStageIsolationStaysInsideDeadline(t *testing.T) {
	var stdout bytes.Buffer
	if code := runDoctorUpdateStageCheck([]string{"--directory", t.TempDir()}, &stdout); code != 0 {
		t.Fatalf("update-stage helper exit=%d output=%q", code, stdout.String())
	}
	var clean knownDoctorBool
	if json.NewDecoder(&stdout).Decode(&clean) != nil || !clean.Known || !clean.OK {
		t.Fatalf("update-stage helper state=%#v", clean)
	}
	if runtime.GOOS == "windows" {
		t.Skip("POSIX blocking executable fixture")
	}
	blocker := filepath.Join(t.TempDir(), "blocked-update-stage-check")
	if err := os.WriteFile(blocker, []byte("#!/bin/sh\nexec sleep 10\n"), 0o700); err != nil { // #nosec G306 -- private executable deadline fixture.
		t.Fatal(err)
	}
	previous := serverDoctorUpdateStageExecutable
	serverDoctorUpdateStageExecutable = func() (string, error) { return blocker, nil }
	t.Cleanup(func() { serverDoctorUpdateStageExecutable = previous })
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	if state := isolatedServerDoctorUpdateStage(ctx, t.TempDir()); state.Known || time.Since(started) > time.Second {
		t.Fatalf("isolated update-stage state=%#v elapsed=%s", state, time.Since(started))
	}
}

func TestDoctorCatalogAcceptanceCommandAndIsolationStayInsideDeadline(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil { // #nosec G302 -- private operator-state fixture root.
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if code := runDoctorCatalogAcceptanceCheck([]string{"--directory", directory, "--minimum", "3"}, &stdout); code != 0 {
		t.Fatalf("missing catalog acceptance code=%d output=%q", code, stdout.String())
	}
	var state knownDoctorBool
	if json.Unmarshal(stdout.Bytes(), &state) != nil || !state.Known || state.OK {
		t.Fatalf("missing catalog acceptance=%#v", state)
	}
	if err := operator.AcceptServerCatalogSequence(directory, 4, 3); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if code := runDoctorCatalogAcceptanceCheck([]string{"--directory", directory, "--minimum", "5"}, &stdout); code != 0 {
		t.Fatalf("downgrade catalog acceptance code=%d output=%q", code, stdout.String())
	}
	state = knownDoctorBool{}
	if json.Unmarshal(stdout.Bytes(), &state) != nil || !state.Known || state.OK {
		t.Fatalf("downgrade catalog acceptance=%#v", state)
	}

	blocker := filepath.Join(t.TempDir(), "blocked-catalog-acceptance-doctor")
	previous := serverDoctorCatalogAcceptanceExecutable
	serverDoctorCatalogAcceptanceExecutable = func() (string, error) { return blocker, nil }
	t.Cleanup(func() { serverDoctorCatalogAcceptanceExecutable = previous })
	started := time.Now()
	if state := isolatedServerDoctorCatalogAcceptance(t.Context(), directory, 4); state.Known || time.Since(started) > time.Second {
		t.Fatalf("isolated catalog acceptance=%#v elapsed=%s", state, time.Since(started))
	}
}

func TestDoctorRelayProfileCommandAndIsolationStayInsideDeadline(t *testing.T) {
	root := t.TempDir()
	if runtime.GOOS != "windows" {
		if err := os.Chmod(root, 0o700); err != nil { // #nosec G302 -- private diagnostic fixture root.
			t.Fatal(err)
		}
	}
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	keyPath := filepath.Join(root, "doctor.key")
	accessPath := filepath.Join(root, "access.env")
	profilePath := filepath.Join(root, "doctor.env")
	if err := os.WriteFile(keyPath, []byte(base64.RawURLEncoding.EncodeToString(privateKey)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(accessPath, []byte("PUNARO_CF_ACCESS_CLIENT_ID=doctor-id\nPUNARO_CF_ACCESS_CLIENT_SECRET=doctor-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profilePath, []byte("PUNARO_SERVER_DOCTOR_RELAY_URL=https://punaro.example\nPUNARO_SERVER_DOCTOR_MACHINE_ID=server-doctor\nPUNARO_SERVER_DOCTOR_PRIVATE_KEY_FILE="+keyPath+"\nPUNARO_SERVER_DOCTOR_ACCESS_TOKEN_FILE="+accessPath+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if code := runDoctorRelayProfileCheck([]string{"--path", profilePath}, &stdout); code != 0 {
		t.Fatalf("relay-profile helper code=%d output=%q", code, stdout.String())
	}
	var payload serverDoctorProfilePayload
	if json.Unmarshal(stdout.Bytes(), &payload) != nil || payload.RelayURL != "https://punaro.example" || payload.MachineID != "server-doctor" {
		t.Fatalf("relay-profile helper payload=%#v", payload)
	}
	credential := "22222222-2222-4222-8222-222222222222." + strings.Repeat("A", 43)
	credentialPath := filepath.Join(root, "device.credential")
	deviceProfilePath := filepath.Join(root, "device-doctor.env")
	if err := os.WriteFile(credentialPath, []byte(credential+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(deviceProfilePath, []byte("PUNARO_SERVER_DOCTOR_RELAY_URL=https://punaro.example\nPUNARO_SERVER_DOCTOR_MACHINE_ID=server-doctor\nPUNARO_SERVER_DOCTOR_DEVICE_CREDENTIAL_FILE="+credentialPath+"\nPUNARO_SERVER_DOCTOR_ACCESS_TOKEN_FILE="+accessPath+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if code := runDoctorRelayProfileCheck([]string{"--path", deviceProfilePath}, &stdout); code != 0 {
		t.Fatalf("device relay-profile helper code=%d", code)
	}
	payload = serverDoctorProfilePayload{}
	if json.Unmarshal(stdout.Bytes(), &payload) != nil || payload.DeviceCredential != credential || payload.SigningKey != "" {
		t.Fatalf("device relay-profile helper payload is invalid")
	}
	if runtime.GOOS == "windows" {
		return
	}
	blocker := filepath.Join(t.TempDir(), "blocked-relay-profile-check")
	if err := os.WriteFile(blocker, []byte("#!/bin/sh\nexec sleep 10\n"), 0o700); err != nil { // #nosec G306 -- private executable deadline fixture.
		t.Fatal(err)
	}
	previous := serverDoctorProfileExecutable
	serverDoctorProfileExecutable = func() (string, error) { return blocker, nil }
	t.Cleanup(func() { serverDoctorProfileExecutable = previous })
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := isolatedServerDoctorProfile(ctx, profilePath); err == nil || time.Since(started) > time.Second {
		t.Fatalf("isolated relay profile error=%v elapsed=%s", err, time.Since(started))
	}
}

func TestDoctorRecoveryReceiptCommandAndIsolationStayInsideDeadline(t *testing.T) {
	directory := t.TempDir()
	request := serverDoctorRecoveryReceiptRequest{Directory: directory, ExpectAbsent: true}
	encoded, ok := encodeServerDoctorRecoveryReceiptRequest(request)
	if !ok {
		t.Fatal("recovery-receipt request encoding failed")
	}
	var stdout bytes.Buffer
	if code := runDoctorRecoveryReceiptCheck([]string{"--request", encoded}, &stdout); code != 0 {
		t.Fatalf("recovery-receipt helper code=%d output=%q", code, stdout.String())
	}
	var state knownDoctorBool
	if json.Unmarshal(stdout.Bytes(), &state) != nil || !state.Known || !state.OK {
		t.Fatalf("recovery-receipt helper state=%#v", state)
	}
	if runtime.GOOS == "windows" {
		return
	}
	blocker := filepath.Join(t.TempDir(), "blocked-recovery-receipt-check")
	if err := os.WriteFile(blocker, []byte("#!/bin/sh\nexec sleep 10\n"), 0o700); err != nil { // #nosec G306 -- private executable deadline fixture.
		t.Fatal(err)
	}
	previous := serverDoctorRecoveryReceiptExecutable
	serverDoctorRecoveryReceiptExecutable = func() (string, error) { return blocker, nil }
	t.Cleanup(func() { serverDoctorRecoveryReceiptExecutable = previous })
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	if state := isolatedServerDoctorRecoveryReceipt(ctx, request); state.Known || time.Since(started) > time.Second {
		t.Fatalf("isolated recovery receipt=%#v elapsed=%s", state, time.Since(started))
	}
}

func TestUpRefusesActiveUpdateBeforeStartingWriters(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 6}, nil
	}
	maintenanceActive = func(context.Context, string) (bool, error) { return true, nil }
	started := false
	startServices = func(context.Context, operator.Installation) error { started = true; return nil }
	var stderr bytes.Buffer
	if code := run([]string{"up", "--directory", directory}, io.Discard, &stderr); code != 1 || started || !strings.Contains(stderr.String(), "punaro update") {
		t.Fatalf("code=%d started=%t stderr=%q", code, started, stderr.String())
	}
}

func TestBackupCommandsUsePublishedInstallationAndStrictVerifier(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	installation, err := operator.Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	manifest := punarobackup.Manifest{Version: 1, BackupID: "018f47f4-7b18-7cc2-98d6-31d4fb5ab742", CreatedAt: time.Date(2026, 7, 19, 20, 0, 0, 0, time.UTC), SchemaVersion: 5, State: punarobackup.State{InstallationID: "4e02b0e5-1934-4dda-9c4a-767c120c2fac", TimelineID: "797476ad-8fdc-4c05-b144-3ccbb92b54bf", ChangeSequence: 42}}
	backupPath := filepath.Join(installation.BackupDir, "verified")
	createOperatorBackup = func(_ context.Context, got operator.Installation) (punarobackup.Manifest, string, error) {
		if got.Directory != directory {
			t.Fatalf("unexpected installation: %#v", got)
		}
		return manifest, backupPath, nil
	}
	listOperatorBackups = func(root string) ([]punarobackup.Summary, error) {
		if root != installation.BackupDir {
			t.Fatalf("unexpected backup root: %q", root)
		}
		return []punarobackup.Summary{{Directory: backupPath, BackupID: manifest.BackupID, CreatedAt: manifest.CreatedAt, SchemaVersion: 5, State: manifest.State}}, nil
	}
	verifyOperatorBackup = func(path string) (punarobackup.Manifest, error) {
		if path != backupPath {
			t.Fatalf("unexpected verify path: %q", path)
		}
		return manifest, nil
	}

	for _, command := range [][]string{{"backup", "--directory", directory}, {"backup", "list", "--directory", directory}, {"backup", "verify", "--backup", backupPath}} {
		var stdout, stderr bytes.Buffer
		if code := run(command, &stdout, &stderr); code != 0 {
			t.Fatalf("command=%v code=%d stdout=%s stderr=%s", command, code, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), manifest.BackupID) {
			t.Fatalf("command=%v omitted backup identity: %s", command, stdout.String())
		}
	}
}

func TestRestoreCommandRequiresExplicitNewStackInputs(t *testing.T) {
	preserveDependencies(t)
	root := t.TempDir()
	backupPath := filepath.Join(root, "backup")
	if err := os.Mkdir(backupPath, 0o700); err != nil {
		t.Fatal(err)
	}
	requestSeen := restoreRequest{}
	restoreOperatorBackup = func(_ context.Context, request restoreRequest) (punarobackup.State, error) {
		requestSeen = request
		return punarobackup.State{InstallationID: "4e02b0e5-1934-4dda-9c4a-767c120c2fac", TimelineID: "7c016e76-aadb-48f8-b460-e75f7d90e888", ChangeSequence: 42}, nil
	}
	args := []string{"restore", "--backup", backupPath, "--into-new-stack", filepath.Join(root, "install"), "--data-dir", filepath.Join(root, "data"), "--backup-dir", filepath.Join(root, "new-backups"), "--owner-dsn-file", filepath.Join(root, "owner.dsn"), "--app-dsn-file", filepath.Join(root, "app.dsn")}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("restore code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if requestSeen.BackupDirectory != backupPath || requestSeen.Directory != filepath.Join(root, "install") || requestSeen.DataDir != filepath.Join(root, "data") {
		t.Fatalf("unexpected restore request: %#v", requestSeen)
	}
	if code := run([]string{"restore", "--backup", backupPath}, io.Discard, io.Discard); code != 2 {
		t.Fatalf("incomplete restore code=%d, want 2", code)
	}
}

func TestRunRoutesUpdateCommand(t *testing.T) {
	var stderr bytes.Buffer
	if code := run([]string{"update"}, io.Discard, &stderr); code != 2 {
		t.Fatalf("run(update) = %d, want 2", code)
	}
	if strings.Contains(stderr.String(), "unsupported operator command") {
		t.Fatalf("update command was not routed: %q", stderr.String())
	}
}

func TestServerDoctorCommandOutputIsBounded(t *testing.T) {
	output := boundedServerDoctorOutput{maximum: serverDoctorOutputLimit}
	if written, err := output.Write([]byte("healthy")); err != nil || written != len("healthy") || output.buffer.String() != "healthy" || output.overflow {
		t.Fatalf("bounded output=%q overflow=%v written=%d err=%v", output.buffer.String(), output.overflow, written, err)
	}
	oversized := strings.Repeat("x", serverDoctorOutputLimit+1)
	if written, err := output.Write([]byte(oversized)); err != nil || written != len(oversized) || output.buffer.Len() != serverDoctorOutputLimit || !output.overflow {
		t.Fatalf("oversized length=%d overflow=%v written=%d err=%v", output.buffer.Len(), output.overflow, written, err)
	}
}

func TestPostgresToolNeverPlacesPasswordInArgumentsOrInheritedEnvironment(t *testing.T) {
	root := t.TempDir()
	dsnFile := filepath.Join(root, "owner.dsn")
	password := "visible-secret-password"
	if err := os.WriteFile(dsnFile, []byte("postgresql://punaro_owner:"+password+"@127.0.0.1:5432/punaro?sslmode=disable\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "capture.sh")
	capture := filepath.Join(root, "capture.txt")
	body := "#!/bin/sh\nprintf '%s\\n' \"$@\" \"${PGPASSWORD:-missing}\" > \"$CAPTURE_FILE\"\nexit 9\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil { // #nosec G306 -- executable test fixture.
		t.Fatal(err)
	}
	t.Setenv("PGPASSWORD", "inherited-secret")
	t.Setenv("CAPTURE_FILE", capture)
	err := runPostgresTool(context.Background(), script, dsnFile, func(connection string) []string { return []string{"--dbname", connection} })
	if err == nil {
		t.Fatal("failing capture tool unexpectedly succeeded")
	}
	message := err.Error()
	if strings.Contains(message, password) || strings.Contains(message, "inherited-secret") {
		t.Fatalf("tool leaked a credential in its error: %q", message)
	}
	captured, readErr := os.ReadFile(capture) // #nosec G304 -- fixed private test capture path.
	if readErr != nil || strings.Contains(string(captured), password) || strings.Contains(string(captured), "inherited-secret") || !strings.Contains(string(captured), "missing") {
		t.Fatalf("tool leaked or inherited a credential: capture=%q err=%v", captured, readErr)
	}
	if !strings.Contains(string(captured), "postgresql://punaro_owner@127.0.0.1:5432/punaro?sslmode=disable") {
		t.Fatalf("sanitized connection was not passed: %q", captured)
	}
}

func TestPostgresDumpUsesPrivatePreopenedOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is Unix-only")
	}
	root := t.TempDir()
	dsnFile := filepath.Join(root, "owner.dsn")
	if err := os.WriteFile(dsnFile, []byte("postgresql://punaro_owner@127.0.0.1:5432/punaro?sslmode=disable\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "pg_dump")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf 'private-dump'\n"), 0o700); err != nil { // #nosec G306 -- executable test fixture.
		t.Fatal(err)
	}
	t.Setenv("PATH", root)
	destination := filepath.Join(root, "database.dump")
	if err := pgDumpSnapshot(context.Background(), dsnFile, "00000003-0000001B-999", destination); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("dump mode=%v", info.Mode().Perm())
	}
	body, err := os.ReadFile(destination) // #nosec G304 -- fixed test artifact path.
	if err != nil || string(body) != "private-dump" {
		t.Fatalf("dump=%q err=%v", body, err)
	}
}

func TestPostgresToolRejectsSSLPasswordWithoutLeakingIt(t *testing.T) {
	root := t.TempDir()
	dsnFile := filepath.Join(root, "owner.dsn")
	const secret = "client-key-secret" // #nosec G101 -- non-secret rejection sentinel.
	if err := os.WriteFile(dsnFile, []byte("postgresql://punaro_owner@127.0.0.1:5432/punaro?sslmode=require&sslpassword="+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runPostgresTool(context.Background(), filepath.Join(root, "must-not-run"), dsnFile, func(connection string) []string { return []string{"--dbname", connection} })
	if err == nil || strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), "password query parameters") {
		t.Fatalf("sslpassword rejection=%q", err)
	}
}

func TestComposeUpArgsUseInstallationSpecificProjectName(t *testing.T) {
	first := operator.Installation{Directory: filepath.Join(string(filepath.Separator), "srv", "a", "punaro"), OwnerPrincipalID: "11111111-1111-4111-8111-111111111111"}
	second := operator.Installation{Directory: filepath.Join(string(filepath.Separator), "srv", "b", "punaro"), OwnerPrincipalID: "22222222-2222-4222-8222-222222222222"}
	firstArgs, firstErr := composeUpArgs(first)
	secondArgs, secondErr := composeUpArgs(second)
	firstProject, _ := operator.ComposeProjectName(first)
	if firstErr != nil || secondErr != nil || len(firstArgs) < 3 || firstArgs[1] != "--project-name" || firstArgs[2] != firstProject {
		t.Fatalf("first args=%v", firstArgs)
	}
	if firstArgs[2] == secondArgs[2] {
		t.Fatalf("same-basename installations share project name: %q", firstArgs[2])
	}
	if _, err := composeUpArgs(operator.Installation{OwnerPrincipalID: "invalid"}); err == nil {
		t.Fatal("invalid owner identity reached Docker arguments")
	}
}

func TestComposeEnvironmentMakesGeneratedInputsAuthoritative(t *testing.T) {
	directory := filepath.Join(string(filepath.Separator), "srv", "punaro")
	got := composeEnvironment([]string{
		"PATH=/usr/bin:/bin",
		"HOME=/home/operator",
		"DOCKER_HOST=unix:///run/user/1000/docker.sock",
		"DOCKER_CONTEXT=desktop-linux",
		"DOCKER_CONFIG=/home/operator/.docker",
		"HTTPS_PROXY=http://proxy.example",
		"PWD=/stale",
		"pwd=/also-stale",
		"PUNARO_IMAGE=attacker.example/punaro:latest",
		"PuNaRo_Listen_Addr=attacker",
		"PUNARO_POSTGRES_DSN_FILE=/attacker.dsn",
		"PUNARO_FUTURE=attacker",
		"COMPOSE_FILE=/attacker.yaml",
		"compose_path_separator=attacker",
		"COMPOSE_PROJECT_NAME=attacker",
		"COMPOSE_ENV_FILES=/attacker.env",
		"COMPOSE_PROFILES=attacker",
		"XPUNARO_IMAGE=unrelated",
		"XCOMPOSE_FILE=unrelated",
	}, directory)
	want := []string{
		"PATH=/usr/bin:/bin",
		"HOME=/home/operator",
		"DOCKER_HOST=unix:///run/user/1000/docker.sock",
		"DOCKER_CONTEXT=desktop-linux",
		"DOCKER_CONFIG=/home/operator/.docker",
		"HTTPS_PROXY=http://proxy.example",
		"XPUNARO_IMAGE=unrelated",
		"XCOMPOSE_FILE=unrelated",
		"PWD=" + directory,
	}
	if !slices.Equal(got, want) {
		t.Fatalf("environment=%v want=%v", got, want)
	}
}

func TestComposeUpCommandWiresSanitizedEnvironmentAndDirectory(t *testing.T) {
	t.Setenv("PUNARO_IMAGE", "attacker.example/punaro:latest")
	t.Setenv("COMPOSE_FILE", "/attacker.yaml")
	installation := operator.Installation{
		Directory:        filepath.Join(string(filepath.Separator), "srv", "punaro"),
		OwnerPrincipalID: "11111111-1111-4111-8111-111111111111",
	}
	command, err := composeUpCommand(context.Background(), installation)
	if err != nil {
		t.Fatal(err)
	}
	if command.Dir != installation.Directory {
		t.Fatalf("command directory=%q", command.Dir)
	}
	for _, entry := range command.Env {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "PUNARO_") || strings.HasPrefix(name, "COMPOSE_") {
			t.Fatalf("unsafe inherited variable %q", name)
		}
	}
	if !slices.Contains(command.Env, "PWD="+installation.Directory) {
		t.Fatalf("command environment lacks trusted PWD: %v", command.Env)
	}
}

func TestUpRefusesExistingUpgradeBeforeMigrationOrStart(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	migrated, started, pairChecked := false, false, false
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.UpgradeRequired, Version: 3}, nil
	}
	migratePristinePair = func(context.Context, string, string) (punaropostgres.SchemaState, error) {
		migrated = true
		return punaropostgres.SchemaState{}, nil
	}
	startServices = func(context.Context, operator.Installation) error { started = true; return nil }
	verifyInstallationPair = func(context.Context, string, string) error { pairChecked = true; return errors.New("must not run") }
	var stdout, stderr bytes.Buffer
	if code := run([]string{"up", "--directory", directory}, &stdout, &stderr); code != 1 || migrated || started || pairChecked || !strings.Contains(stderr.String(), "no in-place updater") || !strings.Contains(stderr.String(), "previous compatible release") || strings.Contains(stderr.String(), "punaro update") {
		t.Fatalf("code=%d migrated=%t started=%t pairChecked=%t stdout=%q stderr=%q", code, migrated, started, pairChecked, stdout.String(), stderr.String())
	}
}

func TestDoctorClassifiesOldSchemaBeforeRolePair(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.UpgradeRequired, Version: 3}, nil
	}
	pairChecked := false
	verifyInstallationPair = func(context.Context, string, string) error { pairChecked = true; return errors.New("must not run") }
	probe = func(context.Context, string) error { return nil }
	var stdout, stderr bytes.Buffer
	if code := run([]string{"doctor", "--directory", directory, "--machine-id", "punaro-lxc"}, &stdout, &stderr); code != 1 || pairChecked || !strings.Contains(stdout.String(), `"code": "database_schema"`) || !strings.Contains(stdout.String(), `"code": "database_pair"`) || !strings.Contains(stdout.String(), `"status": "unavailable"`) {
		t.Fatalf("code=%d pairChecked=%t stdout=%q stderr=%q", code, pairChecked, stdout.String(), stderr.String())
	}
}

func TestUpRefusesResetPristineDatabase(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	migrateCalls, startCalls, probeCalls := 0, 0, 0
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.Pristine}, nil
	}
	migratePristinePair = func(context.Context, string, string) (punaropostgres.SchemaState, error) {
		migrateCalls++
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 5}, nil
	}
	startServices = func(context.Context, operator.Installation) error { startCalls++; return nil }
	probe = func(context.Context, string) error { probeCalls++; return nil }
	var stdout, stderr bytes.Buffer
	if code := run([]string{"up", "--directory", directory}, &stdout, &stderr); code != 1 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if migrateCalls != 0 || startCalls != 0 || probeCalls != 0 || !strings.Contains(stderr.String(), "schema is pristine") {
		t.Fatalf("migrate=%d start=%d probe=%d stderr=%q", migrateCalls, startCalls, probeCalls, stderr.String())
	}
}

func TestUpStartsCompatibleThenDoctors(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	inspectCalls, startCalls, probeCalls := 0, 0, 0
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		inspectCalls++
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 5}, nil
	}
	startServices = func(context.Context, operator.Installation) error { startCalls++; return nil }
	probe = func(context.Context, string) error { probeCalls++; return nil }
	var stdout, stderr bytes.Buffer
	if code := run([]string{"up", "--directory", directory}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if startCalls != 1 || inspectCalls != 2 || probeCalls != 3 {
		t.Fatalf("inspect=%d start=%d probe=%d", inspectCalls, startCalls, probeCalls)
	}
}

func TestUpRefusesMismatchedInstallationPairBeforeStart(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 44}, nil
	}
	verifyInstallationPair = func(context.Context, string, string) error {
		return errors.New("different installation")
	}
	started := false
	startServices = func(context.Context, operator.Installation) error { started = true; return nil }
	var stdout, stderr bytes.Buffer
	if code := run([]string{"up", "--directory", directory}, &stdout, &stderr); code != 1 || started || !strings.Contains(stderr.String(), "database roles") {
		t.Fatalf("code=%d started=%t stdout=%q stderr=%q", code, started, stdout.String(), stderr.String())
	}
}

func TestDoctorFailsForConfigurationDriftAndRoleMismatch(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	installation, err := operator.Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(installation.BackupDir); err != nil {
		t.Fatal(err)
	}
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 5}, nil
	}
	verifyInstallationPair = func(context.Context, string, string) error {
		return errors.New("different installation")
	}
	probe = func(context.Context, string) error { return nil }
	var stdout, stderr bytes.Buffer
	if code := run([]string{"doctor", "--directory", directory, "--machine-id", "punaro-lxc"}, &stdout, &stderr); code != 1 || !strings.Contains(stdout.String(), `"healthy": false`) || !strings.Contains(stdout.String(), `"code": "database_pair"`) || !strings.Contains(stdout.String(), `"code": "backup_directory"`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestDoctorEmitsStrictContentFreeServerReport(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	serverDoctorInspect = func(_ context.Context, _ operator.Installation, machineID string, gatewayColocated bool, relayProfile string) serverDoctorState {
		if machineID != "punaro-lxc" || gatewayColocated {
			t.Fatalf("doctor inputs machine=%q gateway_colocated=%t", machineID, gatewayColocated)
		}
		if relayProfile != "/run/punaro/server-doctor.env" {
			t.Fatalf("relay profile=%q", relayProfile)
		}
		state := healthyServerDoctorState()
		state.RelayEnrollment = knownDoctorBool{}
		state.RelayProtocol = knownDoctorBool{}
		return state
	}
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 44}, nil
	}
	probe = func(context.Context, string) error { return nil }
	var stdout, stderr bytes.Buffer
	if code := run([]string{"doctor", "--directory", directory, "--machine-id", "punaro-lxc", "--relay-profile", "/run/punaro/server-doctor.env"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	report, err := punarodiagnostic.Decode(bytes.NewReader(stdout.Bytes()))
	if err != nil || report.Component != punarodiagnostic.ComponentServer || !report.Healthy || report.Identity.MachineID != "punaro-lxc" || report.Identity.StorageSchema != 44 || report.Identity.ArtifactDigest != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("report=%#v err=%v stderr=%q", report, err, stderr.String())
	}
	for _, check := range report.Checks {
		if strings.HasPrefix(check.Code, "gateway_") && (check.Required || check.Status != punarodiagnostic.StatusUnavailable || check.Remediation != "collect_gateway_report") {
			t.Fatalf("split gateway check=%#v", check)
		}
		if (check.Code == "relay_enrollment" || check.Code == "relay_protocol") && (check.Required || check.Status != punarodiagnostic.StatusUnavailable || check.Remediation != "enable_relay_to_require_relay_checks") {
			t.Fatalf("disabled relay check=%#v", check)
		}
	}
	for _, forbidden := range []string{directory, "postgres://", "invalid", "127.0.0.1", "registry.example"} {
		if strings.Contains(stdout.String(), forbidden) {
			t.Fatalf("doctor leaked %q: %s", forbidden, stdout.String())
		}
	}
}

func TestServerDoctorUsesNonRelayPublicEdgeProbeWhenRelayDisabled(t *testing.T) {
	for _, accessProtected := range []bool{true, false} {
		t.Run(map[bool]string{true: "protected", false: "open"}[accessProtected], func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.Method != http.MethodHead || request.URL.Path != "/" {
					t.Fatalf("request=%s %s", request.Method, request.URL.Path)
				}
				if request.Header.Get("CF-Access-Client-Id") == "" && accessProtected {
					response.WriteHeader(http.StatusForbidden)
					return
				}
				response.Header().Set("Cache-Control", "no-store")
				response.Header().Set("X-Content-Type-Options", "nosniff")
				response.Header().Set("X-Frame-Options", "DENY")
				http.NotFound(response, request)
			}))
			defer server.Close()
			profile := serverDoctorProfile{RelayURL: server.URL, AccessToken: adapter.AccessServiceToken{ClientID: "access-id", ClientSecret: "access-secret"}}
			route, origin, access := inspectServerPublicEdge(t.Context(), server.URL, profile, server.Client())
			if !route.Known || !route.OK || !origin.Known || !origin.OK || !access.Known || access.OK != accessProtected {
				t.Fatalf("route=%#v origin=%#v access=%#v", route, origin, access)
			}
		})
	}
}

func TestServerDoctorRequiresPreflightBeforeMailCutoverPublication(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	installation, err := operator.Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	installation.RelayMachinesJSON = "configured"
	if installation.MailCutover != nil {
		t.Fatal("test requires a pre-publication installation")
	}
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 44}, nil
	}
	probe = func(context.Context, string) error { return nil }
	preflightCalls := 0
	inspectMailCutoverPreflight = func(context.Context, string) (punaropostgres.MailCutoverPreflight, error) {
		preflightCalls++
		return punaropostgres.MailCutoverPreflight{LegacyPending: 1, TargetRows: 1}, nil
	}
	report, err := diagnoseServer(t.Context(), installation, "punaro-lxc", false, "")
	if err != nil || preflightCalls != 1 || report.Healthy {
		t.Fatalf("preflight_calls=%d healthy=%t err=%v", preflightCalls, report.Healthy, err)
	}
	want := map[string]punarodiagnostic.Status{
		"mail_cutover_legacy_inventory": punarodiagnostic.StatusFail,
		"mail_cutover_recovery":         punarodiagnostic.StatusPass,
		"mail_cutover_target":           punarodiagnostic.StatusFail,
	}
	for _, check := range report.Checks {
		if status, ok := want[check.Code]; ok {
			if !check.Required || check.Status != status {
				t.Fatalf("check=%#v want_status=%s", check, status)
			}
			delete(want, check.Code)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing preflight checks: %v", want)
	}
}

func TestServerDoctorDoesNotSynthesizeEnabledLANRelayHealth(t *testing.T) {
	installation := operator.Installation{Ingress: ingress.Policy{Mode: ingress.LAN}, RelayEnabled: true}
	route, origin, access, enrollment, protocol := inspectServerRelay(t.Context(), installation, "")
	if !route.Known || !route.OK || !origin.Known || !origin.OK || !access.Known || !access.OK {
		t.Fatalf("route=%#v origin=%#v access=%#v", route, origin, access)
	}
	if enrollment.Known || protocol.Known {
		t.Fatalf("enrollment=%#v protocol=%#v", enrollment, protocol)
	}
}

func TestServerDoctorBindsEnabledRelayProbeToInstalledPublicURL(t *testing.T) {
	root := t.TempDir()
	if runtime.GOOS != "windows" {
		if err := os.Chmod(root, 0o700); err != nil { // #nosec G302 -- private diagnostic fixture root.
			t.Fatal(err)
		}
	}
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	keyPath := filepath.Join(root, "doctor.key")
	accessPath := filepath.Join(root, "access.env")
	profilePath := filepath.Join(root, "doctor.env")
	if err := os.WriteFile(keyPath, []byte(base64.RawURLEncoding.EncodeToString(privateKey)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(accessPath, []byte("PUNARO_CF_ACCESS_CLIENT_ID=doctor-id\nPUNARO_CF_ACCESS_CLIENT_SECRET=doctor-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	profile := "PUNARO_SERVER_DOCTOR_RELAY_URL=https://stale.example\nPUNARO_SERVER_DOCTOR_MACHINE_ID=server-doctor\nPUNARO_SERVER_DOCTOR_PRIVATE_KEY_FILE=" + keyPath + "\nPUNARO_SERVER_DOCTOR_ACCESS_TOKEN_FILE=" + accessPath + "\n"
	if err := os.WriteFile(profilePath, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	installation := operator.Installation{Ingress: ingress.Policy{Mode: ingress.Internet, PublicURL: "https://installed.example"}, RelayEnabled: true}
	route, origin, access, enrollment, protocol := inspectServerRelay(t.Context(), installation, profilePath)
	for name, check := range map[string]knownDoctorBool{"route": route, "origin": origin, "access": access} {
		if !check.Known || check.OK {
			t.Fatalf("%s=%#v", name, check)
		}
	}
	if enrollment.Known || protocol.Known {
		t.Fatalf("enrollment=%#v protocol=%#v", enrollment, protocol)
	}
}

func TestServerDoctorUsesMigratedDeviceCredentialAfterCutover(t *testing.T) {
	credential := "22222222-2222-4222-8222-222222222222." + strings.Repeat("A", 43)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		correlation := request.Header.Get(relay.RequestCorrelationHeader)
		if request.Method != http.MethodHead || request.URL.Path != relay.DoctorPath || request.Header.Get("Authorization") != "Bearer "+credential || !relay.ValidRequestToken(correlation) {
			t.Fatalf("invalid bearer doctor request")
		}
		response.Header().Set(relay.ResponseNonceHeader, correlation)
		response.Header().Set(relay.ProtocolHeader, "1")
		response.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	previous := serverDoctorProfileLoad
	serverDoctorProfileLoad = func(context.Context, string) (serverDoctorProfile, error) {
		return serverDoctorProfile{RelayURL: server.URL, MachineID: "server-doctor", DeviceCredential: credential}, nil
	}
	t.Cleanup(func() { serverDoctorProfileLoad = previous })
	installation := operator.Installation{Ingress: ingress.Policy{Mode: ingress.Internet, PublicURL: server.URL}, RelayEnabled: true}
	route, origin, access, enrollment, protocol := inspectServerRelay(t.Context(), installation, "/protected/server-doctor.env")
	for name, check := range map[string]knownDoctorBool{"route": route, "origin": origin, "access": access, "enrollment": enrollment, "protocol": protocol} {
		if !check.Known || !check.OK {
			t.Fatalf("%s=%#v", name, check)
		}
	}
}

func TestDoctorRequiresExplicitValidServerMachineIdentity(t *testing.T) {
	directory := testInstallation(t)
	for _, args := range [][]string{
		{"doctor", "--directory", directory},
		{"doctor", "--directory", directory, "--machine-id", "bad/id"},
	} {
		if code := run(args, io.Discard, io.Discard); code != 2 {
			t.Fatalf("args=%v code=%d", args, code)
		}
	}
}

func TestDoctorClassifiesEveryExtendedServerDependency(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	relayMachines := filepath.Join(t.TempDir(), "relay-machines.json")
	if err := os.WriteFile(relayMachines, []byte(`[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/a/"],"endpoints":[],"attachment_device_id":""}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := operator.ConfigureRelayMachines(directory, relayMachines); err != nil {
		t.Fatal(err)
	}
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 44}, nil
	}
	probe = func(context.Context, string) error { return nil }
	state := healthyServerDoctorState()
	state.Release = "v0.1.0-alpha.2"
	state.ReleaseSequence = 2
	state.CatalogSequence = 4
	state.InstalledRelease.OK = false
	state.OperatorBinaryRelease.OK = false
	state.RunningImage.OK = false
	state.ComposeBinding.OK = false
	state.MigrationBinding.Known = false
	state.PostgresKnown = false
	state.Storage.OK = false
	state.BackupAvailable.OK = false
	state.BackupFresh.Known = false
	state.UpdateTransaction.OK = false
	state.RecoveryReceipt.Known = false
	state.UpdateRecovery.OK = false
	state.DatabasePrivate.OK = false
	state.HealthPrivate.OK = false
	state.AdminPrivate.OK = false
	state.BlobPrivate.OK = false
	state.TunnelRoute.OK = false
	state.TunnelOrigin.OK = false
	state.AccessAdmission.Known = false
	state.RelayEnrollment.OK = false
	state.RelayProtocol.Known = false
	state.GatewayInstalled.OK = false
	state.GatewayEnabled.OK = false
	state.GatewayRunning.Known = false
	state.GatewayExecutable.OK = false
	state.GatewayExitStatus.Known = false
	state.GatewayRestartState.OK = false
	state.GatewayRelease.OK = false
	serverDoctorInspect = func(context.Context, operator.Installation, string, bool, string) serverDoctorState { return state }

	var stdout, stderr bytes.Buffer
	if code := run([]string{"doctor", "--directory", directory, "--machine-id", "punaro-lxc", "--gateway-co-located"}, &stdout, &stderr); code != 1 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	report, err := punarodiagnostic.Decode(bytes.NewReader(stdout.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if report.Identity.Release != state.Release || report.Identity.ReleaseSequence != state.ReleaseSequence || report.Identity.CatalogSequence != state.CatalogSequence || report.Identity.Platform == "" {
		t.Fatalf("identity=%#v", report.Identity)
	}
	want := map[string]punarodiagnostic.Status{
		"installed_release": "fail", "operator_binary_release": "fail", "running_image": "fail", "compose_manifest_binding": "fail",
		"migration_manifest_binding": "unavailable", "postgres_major": "unavailable", "storage_capacity": "fail",
		"verified_backup": "fail", "backup_freshness": "unavailable", "update_transaction": "fail", "recovery_receipt": "unavailable", "update_recovery": "fail",
		"database_listener_private": "fail", "health_listener_private": "fail", "administration_listener_private": "fail",
		"blob_storage_private": "fail", "tunnel_route": "fail", "access_admission": "unavailable",
		"tunnel_origin": "fail", "relay_enrollment": "fail", "relay_protocol": "unavailable",
		"gateway_service_installed": "fail", "gateway_service_running": "unavailable", "gateway_release": "fail",
		"gateway_service_enabled": "fail", "gateway_service_executable": "fail", "gateway_service_last_exit": "unavailable", "gateway_service_restart_state": "fail",
	}
	for _, check := range report.Checks {
		if status, ok := want[check.Code]; ok {
			if check.Status != status {
				t.Fatalf("check %s=%s want %s", check.Code, check.Status, status)
			}
			delete(want, check.Code)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing checks: %v", want)
	}
}

func TestServerDoctorBackupInspectionHonorsCanceledContext(t *testing.T) {
	root := t.TempDir()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	available, fresh := inspectServerBackups(ctx, root, time.Now().UTC())
	if available.Known || fresh.Known {
		t.Fatalf("canceled backup inspection reported known results: available=%#v fresh=%#v", available, fresh)
	}
}

func TestServerDoctorBackupInspectionBoundsRootEntries(t *testing.T) {
	root := t.TempDir()
	for index := 0; index <= 128; index++ {
		if err := os.Mkdir(filepath.Join(root, fmt.Sprintf("entry-%03d", index)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	available, fresh := inspectServerBackups(t.Context(), root, time.Now().UTC())
	if available.Known || fresh.Known {
		t.Fatalf("oversized backup root reported known results: available=%#v fresh=%#v", available, fresh)
	}
}

func TestDoctorBackupCommandAndIsolationStayInsideDeadline(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil { // #nosec G302 -- private backup diagnostic fixture.
		t.Fatal(err)
	}
	directAvailable, directFresh := inspectServerBackups(t.Context(), root, time.Now().UTC())
	if !directAvailable.Known || directAvailable.OK || !directFresh.Known || directFresh.OK {
		t.Fatalf("direct backup state root=%q available=%#v fresh=%#v", root, directAvailable, directFresh)
	}
	var stdout bytes.Buffer
	if code := runDoctorBackupCheck([]string{"--root", root, "--now", time.Now().UTC().Format(time.RFC3339Nano)}, &stdout); code != 0 {
		t.Fatalf("backup helper code=%d", code)
	}
	var state serverDoctorBackupState
	if json.Unmarshal(stdout.Bytes(), &state) != nil || !state.Available.Known || state.Available.OK || !state.Fresh.Known || state.Fresh.OK {
		t.Fatalf("backup helper state=%#v output=%q", state, stdout.String())
	}
	if runtime.GOOS == "windows" {
		return
	}
	blocker := filepath.Join(t.TempDir(), "blocked-backup-check")
	if err := os.WriteFile(blocker, []byte("#!/bin/sh\nexec sleep 10\n"), 0o700); err != nil { // #nosec G306 -- private executable deadline fixture.
		t.Fatal(err)
	}
	previous := serverDoctorBackupExecutable
	serverDoctorBackupExecutable = func() (string, error) { return blocker, nil }
	t.Cleanup(func() { serverDoctorBackupExecutable = previous })
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	available, fresh := isolatedServerDoctorBackups(ctx, root, time.Now().UTC())
	if available.Known || fresh.Known || time.Since(started) > time.Second {
		t.Fatalf("isolated backup available=%#v fresh=%#v elapsed=%s", available, fresh, time.Since(started))
	}
}

func TestServerGatewayServiceDefinitionReadIsBoundedAndContextAware(t *testing.T) {
	path := filepath.Join(t.TempDir(), "punaro-telegram.service")
	valid := []byte("[Service]\nExecStart=/usr/local/bin/punaro-telegram\n")
	if err := os.WriteFile(path, valid, 0o600); err != nil {
		t.Fatal(err)
	}
	if !serverGatewayServiceFileBound(t.Context(), path) {
		t.Fatal("valid gateway service definition rejected")
	}
	if err := os.WriteFile(path, make([]byte, (64<<10)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if serverGatewayServiceFileBound(t.Context(), path) {
		t.Fatal("oversized gateway service definition accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if serverGatewayServiceFileBound(ctx, path) {
		t.Fatal("canceled gateway service definition read continued")
	}
}

func TestServerGatewayServiceInspectionDelegatesToIsolatedHelper(t *testing.T) {
	previous := serverDoctorGatewayServiceCheck
	called := false
	serverDoctorGatewayServiceCheck = func(_ context.Context, expectedRelease string) serverDoctorGatewayState {
		called = true
		if expectedRelease != "v0.1.0-alpha.1" {
			t.Fatalf("expected release=%q", expectedRelease)
		}
		return serverDoctorGatewayState{Installed: known(true, true)}
	}
	t.Cleanup(func() { serverDoctorGatewayServiceCheck = previous })
	installed, enabled, running, executable, exitStatus, restartState, release := inspectGatewayService(t.Context(), "v0.1.0-alpha.1")
	if !called || !installed.Known || !installed.OK || enabled.Known || running.Known || executable.Known || exitStatus.Known || restartState.Known || release.Known {
		t.Fatalf("delegated=%t states=%#v %#v %#v %#v %#v %#v %#v", called, installed, enabled, running, executable, exitStatus, restartState, release)
	}
}

func TestServerGatewayServiceInspectionHonorsDeadline(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX blocking executable fixture")
	}
	blocker := filepath.Join(t.TempDir(), "blocked-server-gateway-doctor")
	if err := os.WriteFile(blocker, []byte("#!/bin/sh\nexec sleep 10\n"), 0o700); err != nil { // #nosec G306 -- private executable deadline fixture.
		t.Fatal(err)
	}
	previous := serverDoctorGatewayExecutable
	serverDoctorGatewayExecutable = func() (string, error) { return blocker, nil }
	t.Cleanup(func() { serverDoctorGatewayExecutable = previous })
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	state := isolatedServerDoctorGatewayService(ctx, "v0.1.0-alpha.1")
	if state != (serverDoctorGatewayState{}) || time.Since(started) > time.Second {
		t.Fatalf("isolated gateway state=%#v elapsed=%s", state, time.Since(started))
	}
}

func TestServerGatewaySystemdExecStartRequiresExactEffectiveExecutable(t *testing.T) {
	valid := "{ path=/usr/local/bin/punaro-telegram ; argv[]=/usr/local/bin/punaro-telegram ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n"
	if !serverGatewaySystemdExecStartBound(valid) {
		t.Fatal("valid effective gateway ExecStart rejected")
	}
	for _, stale := range []string{
		strings.Replace(valid, "/usr/local/bin/punaro-telegram", "/tmp/punaro-telegram", 1),
		strings.Replace(valid, "argv[]=/usr/local/bin/punaro-telegram", "argv[]=/usr/local/bin/punaro-telegram doctor", 1),
		valid + valid,
		"",
	} {
		if serverGatewaySystemdExecStartBound(stale) {
			t.Fatalf("stale effective gateway ExecStart accepted: %q", stale)
		}
	}
}

func TestServerDoctorRequiresReleasePostgreSQLMajor(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 44}, nil
	}
	probe = func(context.Context, string) error { return nil }
	for _, actual := range []int{17, 19} {
		t.Run(fmt.Sprintf("major-%d", actual), func(t *testing.T) {
			state := healthyServerDoctorState()
			state.PostgresMajor = actual
			serverDoctorInspect = func(context.Context, operator.Installation, string, bool, string) serverDoctorState { return state }
			var stdout, stderr bytes.Buffer
			if code := run([]string{"doctor", "--directory", directory, "--machine-id", "punaro-lxc"}, &stdout, &stderr); code != 1 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			report, err := punarodiagnostic.Decode(bytes.NewReader(stdout.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			for _, check := range report.Checks {
				if check.Code == "postgres_major" {
					if check.Status != punarodiagnostic.StatusFail || check.Remediation != "install_release_postgres_major" {
						t.Fatalf("postgres major check=%#v", check)
					}
					return
				}
			}
			t.Fatal("postgres_major check missing")
		})
	}
}

func TestServerDoctorInspectsRunningImageFromInstallationDirectory(t *testing.T) {
	directory := t.TempDir()
	original := serverDoctorRunningImageCommand
	t.Cleanup(func() { serverDoctorRunningImageCommand = original })
	var calls int
	serverDoctorRunningImageCommand = func(_ context.Context, actualDirectory, executable string, arguments ...string) (string, bool) {
		calls++
		if actualDirectory != directory || executable != "docker" {
			t.Fatalf("directory=%q executable=%q", actualDirectory, executable)
		}
		switch arguments[0] {
		case "compose":
			return "punaro-container\n", true
		case "inspect":
			return cliTestImage + "\n", true
		default:
			t.Fatalf("arguments=%q", arguments)
			return "", false
		}
	}
	state := inspectRunningImage(t.Context(), operator.Installation{
		Directory:        directory,
		Image:            cliTestImage,
		OwnerPrincipalID: "11111111-1111-4111-8111-111111111111",
	})
	if !state.Known || !state.OK || calls != 2 {
		t.Fatalf("running image state=%#v calls=%d", state, calls)
	}
}

func TestServerDoctorRunningImageDistinguishesMismatchAndUnavailable(t *testing.T) {
	original := serverDoctorRunningImageCommand
	t.Cleanup(func() { serverDoctorRunningImageCommand = original })
	installation := operator.Installation{
		Directory:        t.TempDir(),
		Image:            cliTestImage,
		OwnerPrincipalID: "11111111-1111-4111-8111-111111111111",
	}
	serverDoctorRunningImageCommand = func(_ context.Context, _ string, _ string, arguments ...string) (string, bool) {
		if arguments[0] == "compose" {
			return "punaro-container\n", true
		}
		return "ghcr.io/rock3r/punaro@sha256:" + strings.Repeat("b", 64) + "\n", true
	}
	if state := inspectRunningImage(t.Context(), installation); !state.Known || state.OK {
		t.Fatalf("mismatched running image state=%#v", state)
	}
	serverDoctorRunningImageCommand = func(context.Context, string, string, ...string) (string, bool) {
		return "", false
	}
	if state := inspectRunningImage(t.Context(), installation); state.Known || state.OK {
		t.Fatalf("unavailable running image state=%#v", state)
	}
}

func TestOperatorBinaryReleaseFollowsDurableUpdateOutcome(t *testing.T) {
	transaction := punaropostgres.UpdateTransaction{UpdateRequest: punaropostgres.UpdateRequest{SourceRelease: "v0.1.0-alpha.7", TargetRelease: "v0.1.0-alpha.8"}, Phase: punaropostgres.UpdateCommitted}
	if state := operatorBinaryReleaseState("v0.1.0-alpha.7", transaction, true); !state.Known || state.OK {
		t.Fatalf("stale committed operator state=%#v", state)
	}
	if state := operatorBinaryReleaseState("v0.1.0-alpha.8", transaction, true); !state.Known || !state.OK {
		t.Fatalf("updated committed operator state=%#v", state)
	}
	transaction.Phase = punaropostgres.UpdateRecovered
	if state := operatorBinaryReleaseState("v0.1.0-alpha.7", transaction, true); !state.Known || !state.OK {
		t.Fatalf("recovered source operator state=%#v", state)
	}
	if state := operatorBinaryReleaseState("", punaropostgres.UpdateTransaction{}, false); state.Known || state.OK {
		t.Fatalf("unidentified fresh operator state=%#v", state)
	}
	if state := operatorBinaryReleaseState("v0.1.0-alpha.8", punaropostgres.UpdateTransaction{}, false); !state.Known || !state.OK {
		t.Fatalf("fresh identified operator state=%#v", state)
	}
}

func TestServerDoctorCommandUsesRequestedWorkingDirectory(t *testing.T) {
	directory := t.TempDir()
	command := newServerDoctorCommand(t.Context(), directory, "docker", "version")
	if command.Dir != directory {
		t.Fatalf("command directory=%q want=%q", command.Dir, directory)
	}
}

func TestServerDoctorProfileLoadsOnlyProtectedLeastPrivilegeInputs(t *testing.T) {
	root := t.TempDir()
	if runtime.GOOS != "windows" {
		if err := os.Chmod(root, 0o700); err != nil { // #nosec G302 -- directory must be owner-only executable.
			t.Fatal(err)
		}
	}
	write := func(name, body string, mode os.FileMode) string {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	keyPath := write("doctor.key", base64.RawURLEncoding.EncodeToString(privateKey), 0o600)
	accessPath := write("access.env", "PUNARO_CF_ACCESS_CLIENT_ID=doctor-id\nPUNARO_CF_ACCESS_CLIENT_SECRET=doctor-secret\n", 0o600)
	profilePath := write("doctor.env", "PUNARO_SERVER_DOCTOR_RELAY_URL=https://punaro.example\nPUNARO_SERVER_DOCTOR_MACHINE_ID=server-doctor\nPUNARO_SERVER_DOCTOR_PRIVATE_KEY_FILE="+keyPath+"\nPUNARO_SERVER_DOCTOR_ACCESS_TOKEN_FILE="+accessPath+"\n", 0o600)
	profile, err := loadServerDoctorProfile(t.Context(), profilePath)
	if err != nil || profile.RelayURL != "https://punaro.example" || profile.MachineID != "server-doctor" || len(profile.PrivateKey) != ed25519.PrivateKeySize || profile.AccessToken.ClientID != "doctor-id" || profile.AccessToken.ClientSecret != "doctor-secret" {
		t.Fatalf("protected server doctor profile did not load: %v", err)
	}
	credential := "22222222-2222-4222-8222-222222222222." + strings.Repeat("A", 43)
	credentialPath := write("device.credential", credential+"\n", 0o600)
	deviceProfilePath := write("device-doctor.env", "PUNARO_SERVER_DOCTOR_RELAY_URL=https://punaro.example\nPUNARO_SERVER_DOCTOR_MACHINE_ID=server-doctor\nPUNARO_SERVER_DOCTOR_DEVICE_CREDENTIAL_FILE="+credentialPath+"\nPUNARO_SERVER_DOCTOR_ACCESS_TOKEN_FILE="+accessPath+"\n", 0o600)
	deviceProfile, err := loadServerDoctorProfile(t.Context(), deviceProfilePath)
	if err != nil || len(deviceProfile.PrivateKey) != 0 || deviceProfile.DeviceCredential != credential || deviceProfile.AccessToken.ClientID != "doctor-id" {
		t.Fatalf("protected device server doctor profile did not load: %v", err)
	}
	bothProfilePath := write("ambiguous-doctor.env", "PUNARO_SERVER_DOCTOR_RELAY_URL=https://punaro.example\nPUNARO_SERVER_DOCTOR_MACHINE_ID=server-doctor\nPUNARO_SERVER_DOCTOR_PRIVATE_KEY_FILE="+keyPath+"\nPUNARO_SERVER_DOCTOR_DEVICE_CREDENTIAL_FILE="+credentialPath+"\nPUNARO_SERVER_DOCTOR_ACCESS_TOKEN_FILE="+accessPath+"\n", 0o600)
	if _, err := loadServerDoctorProfile(t.Context(), bothProfilePath); err == nil || strings.Contains(err.Error(), credential) {
		t.Fatalf("ambiguous profile error=%q", err)
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(accessPath, 0o644); err != nil { // #nosec G302 -- deliberate insecure-permission diagnostic fixture.
			t.Fatal(err)
		}
		if _, err := loadServerDoctorProfile(t.Context(), profilePath); err == nil || strings.Contains(err.Error(), "doctor-secret") || strings.Contains(err.Error(), accessPath) {
			t.Fatalf("unsafe profile error=%q", err)
		}
	}
}

func TestServerDoctorProfileWriterCreatesProtectedReusableProfile(t *testing.T) {
	root := t.TempDir()
	if runtime.GOOS != "windows" {
		if err := os.Chmod(root, 0o700); err != nil { // #nosec G302 -- directory must be owner-only executable.
			t.Fatal(err)
		}
	}
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	keyPath := filepath.Join(root, "doctor.key")
	accessPath := filepath.Join(root, "access.env")
	profilePath := filepath.Join(root, "doctor.env")
	if err := os.WriteFile(keyPath, []byte(base64.RawURLEncoding.EncodeToString(privateKey)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(accessPath, []byte("PUNARO_CF_ACCESS_CLIENT_ID=doctor-id\nPUNARO_CF_ACCESS_CLIENT_SECRET=doctor-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"doctor-profile", "write", "--out", profilePath, "--relay-url", "https://punaro.example", "--machine-id", "server-doctor", "--private-key-file", keyPath, "--access-token-file", accessPath}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), "doctor-secret") || strings.Contains(stdout.String()+stderr.String(), "doctor-id") {
		t.Fatalf("profile writer leaked credentials: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	info, err := os.Stat(profilePath)
	if err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("profile mode=%v err=%v", info.Mode(), err)
	}
	profile, err := loadServerDoctorProfile(t.Context(), profilePath)
	if err != nil || profile.RelayURL != "https://punaro.example" || profile.MachineID != "server-doctor" {
		t.Fatalf("written profile=%#v err=%v", profile, err)
	}
	if code := run(args, io.Discard, io.Discard); code != 1 {
		t.Fatalf("existing profile overwrite code=%d", code)
	}
	credential := "22222222-2222-4222-8222-222222222222." + strings.Repeat("A", 43)
	credentialPath := filepath.Join(root, "device.credential")
	if err := os.WriteFile(credentialPath, []byte(credential+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deviceProfilePath := filepath.Join(root, "device-doctor.env")
	deviceArgs := []string{"doctor-profile", "write", "--out", deviceProfilePath, "--relay-url", "https://punaro.example", "--machine-id", "server-doctor", "--device-credential-file", credentialPath, "--access-token-file", accessPath}
	stdout.Reset()
	stderr.Reset()
	if code := run(deviceArgs, &stdout, &stderr); code != 0 || strings.Contains(stdout.String()+stderr.String(), credential) {
		t.Fatalf("device profile code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	deviceProfile, err := loadServerDoctorProfile(t.Context(), deviceProfilePath)
	if err != nil || deviceProfile.DeviceCredential != credential || len(deviceProfile.PrivateKey) != 0 {
		t.Fatalf("written device profile=%#v err=%v", deviceProfile, err)
	}
	ambiguousPath := filepath.Join(root, "ambiguous-doctor.env")
	ambiguousArgs := []string{"doctor-profile", "write", "--out", ambiguousPath, "--relay-url", "https://punaro.example", "--machine-id", "server-doctor", "--private-key-file", keyPath, "--device-credential-file", credentialPath, "--access-token-file", accessPath}
	if code := run(ambiguousArgs, io.Discard, io.Discard); code != 1 {
		t.Fatalf("ambiguous profile code=%d", code)
	}
	if _, err := os.Lstat(ambiguousPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ambiguous profile exists: %v", err)
	}
}

func TestServerDoctorProfileReadHonorsCanceledContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "doctor.env")
	if err := os.WriteFile(path, []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := loadServerDoctorProfile(ctx, path); err == nil {
		t.Fatal("canceled server doctor profile read continued")
	}
}

func TestServerDoctorRequiresRecoveryReceiptAtIrreversibleUpdateBoundary(t *testing.T) {
	for _, phase := range []punaropostgres.UpdatePhase{
		punaropostgres.UpdateBackupVerified, punaropostgres.UpdateMigrationStarted, punaropostgres.UpdateMigrated,
		punaropostgres.UpdateCandidateReady, punaropostgres.UpdateDoctorPassed, punaropostgres.UpdateConfigPublished,
		punaropostgres.UpdateRecoveryRequired, punaropostgres.UpdateRecoveryReady, punaropostgres.UpdateRecoveryDoctor, punaropostgres.UpdateRecoveryConfig,
	} {
		if !updatePhaseRequiresRecoveryReceipt(phase) {
			t.Fatalf("phase %s did not require recovery receipt", phase)
		}
	}
	for _, phase := range []punaropostgres.UpdatePhase{punaropostgres.UpdateFenced, punaropostgres.UpdateWritersStopped, punaropostgres.UpdateCommitted, punaropostgres.UpdateRecovered, punaropostgres.UpdateAborted} {
		if updatePhaseRequiresRecoveryReceipt(phase) {
			t.Fatalf("phase %s unexpectedly required recovery receipt", phase)
		}
	}
}

func TestInitMigratesPristineBeforeCreatingOwner(t *testing.T) {
	preserveDependencies(t)
	originalRelease, originalCatalogSequence := serverBuildRelease, serverBuildCatalogSequence
	serverBuildRelease, serverBuildCatalogSequence = "v0.0.0-test", "9"
	t.Cleanup(func() {
		serverBuildRelease, serverBuildCatalogSequence = originalRelease, originalCatalogSequence
	})
	root := t.TempDir()
	for _, name := range []string{"data", "backup", "data/attachments"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"owner.dsn", "app.dsn"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("postgres://invalid\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	relayMachines := filepath.Join(root, "relay-machines.json")
	if err := os.WriteFile(relayMachines, []byte(`[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/a/"],"endpoints":[],"attachment_device_id":""}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	sequence := []string{}
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		sequence = append(sequence, "inspect")
		if len(sequence) == 1 {
			return punaropostgres.SchemaState{Classification: punaropostgres.Pristine}, nil
		}
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 5}, nil
	}
	migratePristinePair = func(context.Context, string, string) (punaropostgres.SchemaState, error) {
		sequence = append(sequence, "migrate")
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 5}, nil
	}
	createOwner = func(context.Context, string, string) (punaropostgres.Principal, error) {
		sequence = append(sequence, "owner")
		return punaropostgres.Principal{ID: "11111111-1111-4111-8111-111111111111"}, nil
	}
	args := []string{"init", "--directory", filepath.Join(root, "install"), "--data-dir", filepath.Join(root, "data"), "--backup-dir", filepath.Join(root, "backup"), "--image", cliTestImage, "--owner-dsn-file", filepath.Join(root, "owner.dsn"), "--app-dsn-file", filepath.Join(root, "app.dsn"), "--owner-name", "operator", "--mode", "internet", "--public-url", "https://punaro.example", "--memory-api", "--memory-mutations", "--relay-machines-file", relayMachines, "--trusted-attachments", "--trusted-attachment-blob-dir", filepath.Join(root, "data", "attachments")}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 0 || strings.Join(sequence, ",") != "inspect,migrate,inspect,owner" {
		t.Fatalf("code=%d sequence=%v stdout=%q stderr=%q", code, sequence, stdout.String(), stderr.String())
	}
	installation, err := operator.Load(filepath.Join(root, "install"))
	wantBlobDir, canonicalErr := filepath.EvalSymlinks(filepath.Join(root, "data", "attachments"))
	if err != nil || canonicalErr != nil || !installation.MemoryAPIEnabled || !installation.MemoryMutationsEnabled || !installation.RelayEnabled || !installation.TrustedAttachmentsEnabled || installation.TrustedAttachmentBlobDir != wantBlobDir {
		t.Fatalf("installation=%#v err=%v", installation, err)
	}
	if err := operator.InspectServerCatalogAcceptance(installation.Directory, 9); err != nil {
		t.Fatalf("release-bound init did not publish catalog acceptance: %v", err)
	}
}

func TestServerInstallationCatalogSequencePreservesRestoreHighWater(t *testing.T) {
	originalRelease, originalCatalogSequence := serverBuildRelease, serverBuildCatalogSequence
	t.Cleanup(func() {
		serverBuildRelease, serverBuildCatalogSequence = originalRelease, originalCatalogSequence
	})
	serverBuildRelease, serverBuildCatalogSequence = "v0.0.0-test", "9"

	if got, err := serverInstallationCatalogSequence(12); err != nil || got != 12 {
		t.Fatalf("preserved sequence=%d err=%v", got, err)
	}
	if got, err := serverInstallationCatalogSequence(4); err != nil || got != 9 {
		t.Fatalf("embedded floor sequence=%d err=%v", got, err)
	}
	serverBuildCatalogSequence = "invalid"
	if _, err := serverInstallationCatalogSequence(12); err == nil {
		t.Fatal("release-bound installation accepted an invalid embedded catalog sequence")
	}
}

func TestReleaseBoundBackupRequiresCatalogAcceptance(t *testing.T) {
	originalRelease := serverBuildRelease
	t.Cleanup(func() { serverBuildRelease = originalRelease })
	serverBuildRelease = "v0.0.0-test"
	if err := requireBackupCatalogAcceptance(0); err == nil {
		t.Fatal("release-bound backup accepted missing catalog state")
	}
	if err := requireBackupCatalogAcceptance(9); err != nil {
		t.Fatalf("release-bound backup rejected catalog high-water: %v", err)
	}
	serverBuildRelease = ""
	if err := requireBackupCatalogAcceptance(0); err != nil {
		t.Fatalf("unbound legacy backup rejected pristine state: %v", err)
	}
}

func TestBootstrapCommandIsUnsupported(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"bootstrap"}, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "unsupported operator command") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestInitProvesPristineDSNPairBeforeMigration(t *testing.T) {
	preserveDependencies(t)
	root := t.TempDir()
	for _, name := range []string{"data", "backup"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"owner.dsn", "app.dsn"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("postgres://invalid\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.Pristine}, nil
	}
	migratePristinePair = func(context.Context, string, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{}, fmt.Errorf("%w: different pristine databases", punaropostgres.ErrMigrationNotAttempted)
	}
	args := []string{"init", "--directory", filepath.Join(root, "install"), "--data-dir", filepath.Join(root, "data"), "--backup-dir", filepath.Join(root, "backup"), "--image", cliTestImage, "--owner-dsn-file", filepath.Join(root, "owner.dsn"), "--app-dsn-file", filepath.Join(root, "app.dsn"), "--owner-name", "operator", "--mode", "internet", "--public-url", "https://punaro.example"}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "requires a pristine") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(root, "install")); !os.IsNotExist(err) {
		t.Fatalf("pre-migration refusal left a resumable stage: %v", err)
	}
}

func TestInitRefusesAlreadyCompatibleDatabase(t *testing.T) {
	preserveDependencies(t)
	root := t.TempDir()
	for _, name := range []string{"data", "backup"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"owner.dsn", "app.dsn"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("postgres://invalid\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 5}, nil
	}
	created := false
	createOwner = func(context.Context, string, string) (punaropostgres.Principal, error) {
		created = true
		return punaropostgres.Principal{}, nil
	}
	args := []string{"init", "--directory", filepath.Join(root, "install"), "--data-dir", filepath.Join(root, "data"), "--backup-dir", filepath.Join(root, "backup"), "--image", cliTestImage, "--owner-dsn-file", filepath.Join(root, "owner.dsn"), "--app-dsn-file", filepath.Join(root, "app.dsn"), "--owner-name", "operator", "--mode", "internet", "--public-url", "https://punaro.example"}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 1 || created || !strings.Contains(stderr.String(), "requires a pristine") {
		t.Fatalf("code=%d created=%t stdout=%q stderr=%q", code, created, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(root, "install")); !os.IsNotExist(err) {
		t.Fatalf("refused fresh init left a resumable stage: %v", err)
	}
}

func TestUpRefusesCompatibleDatabaseWithDifferentOwner(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 5}, nil
	}
	inspectOwner = func(context.Context, string) (punaropostgres.Principal, error) {
		return punaropostgres.Principal{ID: "22222222-2222-4222-8222-222222222222"}, nil
	}
	started := false
	startServices = func(context.Context, operator.Installation) error { started = true; return nil }
	var stdout, stderr bytes.Buffer
	if code := run([]string{"up", "--directory", directory}, &stdout, &stderr); code != 1 || started || !strings.Contains(stderr.String(), "owner does not match") {
		t.Fatalf("code=%d started=%t stdout=%q stderr=%q", code, started, stdout.String(), stderr.String())
	}
}

func TestInitResumeRecoversUncertainOwnerOutcome(t *testing.T) {
	preserveDependencies(t)
	originalRelease, originalCatalogSequence := serverBuildRelease, serverBuildCatalogSequence
	serverBuildRelease, serverBuildCatalogSequence = "v0.0.0-test", "9"
	t.Cleanup(func() {
		serverBuildRelease, serverBuildCatalogSequence = originalRelease, originalCatalogSequence
	})
	root := t.TempDir()
	for _, name := range []string{"data", "backup"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"owner.dsn", "app.dsn"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("postgres://invalid\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	inspectCalls := 0
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		inspectCalls++
		if inspectCalls == 1 {
			return punaropostgres.SchemaState{Classification: punaropostgres.Pristine}, nil
		}
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 5}, nil
	}
	createOwner = func(context.Context, string, string) (punaropostgres.Principal, error) {
		return punaropostgres.Principal{}, context.DeadlineExceeded
	}
	directory := filepath.Join(root, "install")
	args := []string{"init", "--directory", directory, "--data-dir", filepath.Join(root, "data"), "--backup-dir", filepath.Join(root, "backup"), "--image", cliTestImage, "--owner-dsn-file", filepath.Join(root, "owner.dsn"), "--app-dsn-file", filepath.Join(root, "app.dsn"), "--owner-name", "operator", "--mode", "internet", "--public-url", "https://punaro.example"}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "--resume") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	recoverInstallationOwner = func(_ context.Context, installation operator.Installation) (punaropostgres.Principal, error) {
		return punaropostgres.Principal{ID: "11111111-1111-4111-8111-111111111111", DisplayName: installation.OwnerName}, nil
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"init", "--resume", "--directory", directory}, &stdout, &stderr); code != 0 {
		t.Fatalf("resume code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if err := operator.InspectServerCatalogAcceptance(directory, 9); err != nil {
		t.Fatalf("release-bound init recovery did not publish catalog acceptance: %v", err)
	}
}

func TestClientAddPrintsPreviewWithoutDatabaseMutation(t *testing.T) {
	directory := testInstallation(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"client", "add", "--directory", directory, "--name", "laptop", "--machine-id", "laptop", "--all-projects"}, &stdout, &stderr); code != 3 || !strings.Contains(stdout.String(), "trusted-agent") || !strings.Contains(stderr.String(), "rerun with --yes") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestClientInviteAliasPrintsPreviewWithoutDatabaseMutation(t *testing.T) {
	directory := testInstallation(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"client", "invite", "--directory", directory, "--name", "laptop", "--machine-id", "laptop", "--all-projects"}, &stdout, &stderr); code != 3 || !strings.Contains(stdout.String(), "trusted-agent") || !strings.Contains(stderr.String(), "rerun with --yes") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestClientInventoryAndRevocationUseHostLocalInstallationAuthority(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 44}, nil
	}
	clientID := "22222222-2222-4222-8222-222222222222"
	listClients = func(_ context.Context, installation operator.Installation, limit int) ([]punaropostgres.ClientMetadata, error) {
		if installation.Directory != directory || limit != 7 {
			t.Fatalf("list installation=%#v limit=%d", installation, limit)
		}
		return []punaropostgres.ClientMetadata{{ClientID: clientID, MachineID: "laptop", EndpointPrefix: "agent/laptop/", LifecycleState: "active"}}, nil
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"client", "list", "--directory", directory, "--limit", "7"}, &stdout, &stderr); code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), clientID) || strings.Contains(stdout.String(), "credential\"") {
		t.Fatalf("list code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	revoked := false
	revokeClient = func(_ context.Context, installation operator.Installation, gotClientID, reason string) error {
		if installation.Directory != directory || gotClientID != clientID || reason != "retired" {
			t.Fatalf("revoke installation=%#v client=%q reason=%q", installation, gotClientID, reason)
		}
		revoked = true
		return nil
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"client", "revoke", "--directory", directory, "--client", clientID, "--reason", "retired"}, &stdout, &stderr); code != 0 || stdout.Len() != 0 || stderr.Len() != 0 || !revoked {
		t.Fatalf("revoke code=%d revoked=%t stdout=%q stderr=%q", code, revoked, stdout.String(), stderr.String())
	}
}

func TestClientAddRefusesYesWithoutPriorExactPreviewHash(t *testing.T) {
	directory := testInstallation(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"client", "add", "--directory", directory, "--name", "laptop", "--machine-id", "laptop", "--all-projects", "--yes", "--confirm-preview-hash", "stale"}, &stdout, &stderr); code != 3 || !strings.Contains(stderr.String(), "does not match") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestClientAddRefusesMutationWhenDatabaseRolesDiffer(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	verifyInstallationPair = func(context.Context, string, string) error {
		return errors.New("different installation")
	}
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 44}, nil
	}
	var stdout, stderr bytes.Buffer
	_, previewHash, err := punaropostgres.PreviewTrustedAgentEnrollment(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"client", "add", "--directory", directory, "--name", "laptop", "--machine-id", "laptop", "--all-projects", "--yes", "--confirm-preview-hash", previewHash}
	if code := run(args, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "database roles") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestClientLifecycleCommandsRefuseCompatibleHistoricalSchema(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 43}, nil
	}
	listed := false
	listClients = func(context.Context, operator.Installation, int) ([]punaropostgres.ClientMetadata, error) {
		listed = true
		return nil, nil
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"client", "list", "--directory", directory}, &stdout, &stderr); code != 1 || listed || !strings.Contains(stderr.String(), "refused") {
		t.Fatalf("code=%d listed=%t stdout=%q stderr=%q", code, listed, stdout.String(), stderr.String())
	}
}

func TestClientAddRevalidatesPathsAndOwnerBeforeMutation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{name: "path drift", mutate: func(t *testing.T, directory string) {
			installation, err := operator.Load(directory)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(installation.BackupDir); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "owner mismatch", mutate: func(_ *testing.T, _ string) {
			inspectOwner = func(context.Context, string) (punaropostgres.Principal, error) {
				return punaropostgres.Principal{ID: "22222222-2222-4222-8222-222222222222"}, nil
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			preserveDependencies(t)
			directory := testInstallation(t)
			inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
				return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 44}, nil
			}
			test.mutate(t, directory)
			issued := false
			issueEnrollment = func(context.Context, operator.Installation, punaropostgres.EnrollmentRequest, string) (punaropostgres.PendingEnrollment, error) {
				issued = true
				return punaropostgres.PendingEnrollment{}, nil
			}
			_, previewHash, err := punaropostgres.PreviewTrustedAgentEnrollment(nil, true)
			if err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			args := []string{"client", "add", "--directory", directory, "--name", "laptop", "--machine-id", "laptop", "--all-projects", "--yes", "--confirm-preview-hash", previewHash}
			if code := run(args, &stdout, &stderr); code != 1 || issued {
				t.Fatalf("code=%d issued=%t stdout=%q stderr=%q", code, issued, stdout.String(), stderr.String())
			}
		})
	}
}

func TestConfirmedClientAddEmitsOnlyEnrollmentJSON(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 44}, nil
	}
	issueEnrollment = func(_ context.Context, _ operator.Installation, request punaropostgres.EnrollmentRequest, previewHash string) (punaropostgres.PendingEnrollment, error) {
		return punaropostgres.PendingEnrollment{ID: "22222222-2222-4222-8222-222222222222", ClientBinding: request.ClientBinding, Code: "one-time-code", PreviewHash: previewHash}, nil
	}
	_, previewHash, err := punaropostgres.PreviewTrustedAgentEnrollment(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"client", "add", "--directory", directory, "--name", "laptop", "--machine-id", "laptop", "--all-projects", "--yes", "--confirm-preview-hash", previewHash}
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	decoder := json.NewDecoder(&stdout)
	var pending punaropostgres.PendingEnrollment
	if err := decoder.Decode(&pending); err != nil || pending.Code != "one-time-code" {
		t.Fatalf("pending=%#v err=%v", pending, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		t.Fatalf("confirmed add emitted multiple JSON documents: extra=%#v err=%v", extra, err)
	}
}
