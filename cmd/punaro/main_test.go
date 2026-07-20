package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	punarobackup "github.com/rock3r/punaro/internal/backup"
	"github.com/rock3r/punaro/internal/ingress"
	"github.com/rock3r/punaro/internal/operator"
	punaropostgres "github.com/rock3r/punaro/internal/postgres"
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
	if _, err := targetDB.ExecContext(ctx, `DROP SCHEMA auth, relay, attachment, brain, jobs, audit CASCADE`); err != nil {
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

func preserveDependencies(t *testing.T) {
	t.Helper()
	originalInspect, originalOwner, originalMigrate, originalMaintenance := inspectSchema, inspectOwner, migratePristinePair, maintenanceActive
	originalCreate, originalRecover := createOwner, recoverInstallationOwner
	originalVerify := verifyInstallationPair
	originalStart, originalProbe, originalIssue := startServices, probe, issueEnrollment
	originalBackup, originalListBackups, originalVerifyBackup, originalRestore := createOperatorBackup, listOperatorBackups, verifyOperatorBackup, restoreOperatorBackup
	t.Cleanup(func() {
		inspectSchema, inspectOwner, migratePristinePair, maintenanceActive = originalInspect, originalOwner, originalMigrate, originalMaintenance
		createOwner, recoverInstallationOwner = originalCreate, originalRecover
		verifyInstallationPair = originalVerify
		startServices, probe = originalStart, originalProbe
		issueEnrollment = originalIssue
		createOperatorBackup, listOperatorBackups, verifyOperatorBackup, restoreOperatorBackup = originalBackup, originalListBackups, originalVerifyBackup, originalRestore
	})
	inspectOwner = func(context.Context, string) (punaropostgres.Principal, error) {
		return punaropostgres.Principal{ID: "11111111-1111-4111-8111-111111111111", DisplayName: "owner"}, nil
	}
	verifyInstallationPair = func(context.Context, string, string) error { return nil }
	migratePristinePair = func(context.Context, string, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 5}, nil
	}
	maintenanceActive = func(context.Context, string) (bool, error) { return false, nil }
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
	if code := run([]string{"doctor", "--directory", directory}, &stdout, &stderr); code != 1 || pairChecked || !strings.Contains(stdout.String(), "schema not compatible") || strings.Contains(stdout.String(), "database roles target different") {
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
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 5}, nil
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
	if code := run([]string{"doctor", "--directory", directory}, &stdout, &stderr); code != 1 || !strings.Contains(stdout.String(), `"healthy": false`) || !strings.Contains(stdout.String(), "database roles target different installations") || !strings.Contains(stdout.String(), "backup directory") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestInitMigratesPristineBeforeCreatingOwner(t *testing.T) {
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
	args := []string{"init", "--directory", filepath.Join(root, "install"), "--data-dir", filepath.Join(root, "data"), "--backup-dir", filepath.Join(root, "backup"), "--image", cliTestImage, "--owner-dsn-file", filepath.Join(root, "owner.dsn"), "--app-dsn-file", filepath.Join(root, "app.dsn"), "--owner-name", "operator", "--mode", "internet", "--public-url", "https://punaro.example"}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 0 || strings.Join(sequence, ",") != "inspect,migrate,inspect,owner" {
		t.Fatalf("code=%d sequence=%v stdout=%q stderr=%q", code, sequence, stdout.String(), stderr.String())
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
}

func TestClientAddPrintsPreviewWithoutDatabaseMutation(t *testing.T) {
	directory := testInstallation(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"client", "add", "--directory", directory, "--name", "laptop", "--all-projects"}, &stdout, &stderr); code != 3 || !strings.Contains(stdout.String(), "trusted-agent") || !strings.Contains(stderr.String(), "rerun with --yes") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestClientAddRefusesYesWithoutPriorExactPreviewHash(t *testing.T) {
	directory := testInstallation(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"client", "add", "--directory", directory, "--name", "laptop", "--all-projects", "--yes", "--confirm-preview-hash", "stale"}, &stdout, &stderr); code != 3 || !strings.Contains(stderr.String(), "does not match") {
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
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 5}, nil
	}
	var stdout, stderr bytes.Buffer
	_, previewHash, err := punaropostgres.PreviewTrustedAgentEnrollment(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"client", "add", "--directory", directory, "--name", "laptop", "--all-projects", "--yes", "--confirm-preview-hash", previewHash}
	if code := run(args, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "database roles") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
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
				return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 5}, nil
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
			args := []string{"client", "add", "--directory", directory, "--name", "laptop", "--all-projects", "--yes", "--confirm-preview-hash", previewHash}
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
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 5}, nil
	}
	issueEnrollment = func(_ context.Context, _ operator.Installation, request punaropostgres.EnrollmentRequest, previewHash string) (punaropostgres.PendingEnrollment, error) {
		return punaropostgres.PendingEnrollment{ID: "22222222-2222-4222-8222-222222222222", ClientBinding: request.ClientBinding, Code: "one-time-code", PreviewHash: previewHash}, nil
	}
	_, previewHash, err := punaropostgres.PreviewTrustedAgentEnrollment(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"client", "add", "--directory", directory, "--name", "laptop", "--all-projects", "--yes", "--confirm-preview-hash", previewHash}
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
