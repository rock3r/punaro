// punaro-migrate is the explicit, one-shot PostgreSQL schema owner command.
// punarod never invokes migrations during ordinary startup or readiness.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	punaropostgres "github.com/rock3r/punaro/internal/postgres"
)

var migratePostgresUpdate = punaropostgres.MigrateUpdate

func main() { os.Exit(run(os.Args[1:], os.Stderr)) }

func run(args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("punaro-migrate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var ownerDSNFile, updateID, backupID, targetRelease, targetImage, exportedSnapshotID, manifestSHA256 string
	var targetSchema int64
	flags.StringVar(&ownerDSNFile, "owner-dsn-file", "", "absolute path to the protected PostgreSQL schema-owner DSN file")
	flags.StringVar(&updateID, "update-id", "", "exact update transaction ID")
	flags.StringVar(&backupID, "backup-id", "", "exact verified pre-update backup ID")
	flags.StringVar(&targetRelease, "target-release", "", "exact target release")
	flags.StringVar(&targetImage, "target-image", "", "exact full digest-pinned target image")
	flags.Int64Var(&targetSchema, "target-schema", 0, "exact target schema version")
	flags.StringVar(&exportedSnapshotID, "exported-snapshot-id", "", "exact exported snapshot ID")
	flags.StringVar(&manifestSHA256, "manifest-sha256", "", "exact verified backup manifest SHA-256")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || ownerDSNFile == "" || updateID == "" || backupID == "" || targetRelease == "" || targetImage == "" || targetSchema < 1 || exportedSnapshotID == "" || manifestSHA256 == "" {
		_, _ = fmt.Fprintln(stderr, "punaro-migrate requires complete update authorization")
		return 2
	}
	authorization := punaropostgres.UpdateMigrationAuthorization{
		UpdateID: updateID, BackupID: backupID, TargetRelease: targetRelease,
		TargetImage: targetImage, TargetSchema: targetSchema,
		ExportedSnapshotID: exportedSnapshotID, ManifestSHA256: manifestSHA256,
	}
	if authorization.Validate() != nil {
		_, _ = fmt.Fprintln(stderr, "punaro-migrate update authorization is invalid")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	state, err := migratePostgresUpdate(ctx, punaropostgres.Config{DSNFile: ownerDSNFile}, authorization)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "punaro-migrate failed")
		return 1
	}
	_, _ = fmt.Fprintf(stderr, "punaro-migrate completed schema=%s version=%d\n", state.Classification, state.Version)
	return 0
}
