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

var migratePostgres = punaropostgres.Migrate

func main() { os.Exit(run(os.Args[1:], os.Stderr)) }

func run(args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("punaro-migrate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var ownerDSNFile string
	flags.StringVar(&ownerDSNFile, "owner-dsn-file", "", "absolute path to the protected PostgreSQL schema-owner DSN file")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if ownerDSNFile == "" {
		_, _ = fmt.Fprintln(stderr, "punaro-migrate requires -owner-dsn-file")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	state, err := migratePostgres(ctx, punaropostgres.Config{DSNFile: ownerDSNFile})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "punaro-migrate failed: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stderr, "punaro-migrate completed schema=%s version=%d\n", state.Classification, state.Version)
	return 0
}
