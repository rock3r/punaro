// punarod is the central Punaro relay daemon.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/rock3r/punaro/internal/access"
	attachmentv2 "github.com/rock3r/punaro/internal/attachment/v2"
	"github.com/rock3r/punaro/internal/config"
	"github.com/rock3r/punaro/internal/relay"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("punarod", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var envFile string
	flags.StringVar(&envFile, "env-file", "", "optional path to a dotenv file")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(envFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "punarod configuration error: %v\n", err)
		return 2
	}
	if cfg.AttachmentsEnabled {
		_, _ = fmt.Fprintln(stderr, "punarod attachment v2 runtime is withheld: the required recipient-envelope, fresh-directory, revocation, and permit state machine is not implemented")
		return 2
	}
	relayHandler, relayStore, err := buildRelayHandler(cfg)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "punarod relay configuration error: %v\n", err)
		return 2
	}
	if relayStore != nil {
		defer func() { _ = relayStore.Close() }()
	}
	directoryHandler, err := buildDirectoryHandler(cfg, relayStore)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "punarod directory configuration error: %v\n", err)
		return 2
	}
	logger := log.New(os.Stderr, "punarod ", log.LstdFlags|log.LUTC)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"status":"ok"}\n`)) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"status":"ready"}\n`)) })
	if relayHandler != nil {
		mux.Handle("/v1/", relayHandler)
	}
	if directoryHandler != nil {
		mux.Handle("/v2/directory", directoryHandler)
	}
	server := &http.Server{Addr: cfg.ListenAddr, Handler: securityHeaders(mux), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- server.ListenAndServe() }()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	logger.Printf("listening address=%s data_dir=%s log_level=%s", cfg.ListenAddr, cfg.DataDir, cfg.LogLevel)
	select {
	case err := <-serverErrors:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Printf("server stopped error=%v", err)
			return 1
		}
		return 0
	case <-signals:
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			logger.Printf("graceful shutdown failed error=%v", err)
			return 1
		}
		return 0
	}
}

func buildDirectoryHandler(cfg config.Config, store *relay.Store) (http.Handler, error) {
	if !cfg.DirectoryEnabled {
		return nil, nil
	}
	if store == nil {
		return nil, errors.New("directory service requires relay store")
	}
	machines, err := relay.ParseMachineEnrollments(cfg.RelayMachinesJSON)
	if err != nil {
		return nil, err
	}
	authenticator, err := relay.NewAuthenticator(store, machines)
	if err != nil {
		return nil, err
	}
	source, err := attachmentv2.OpenDirectorySnapshotFileSource(cfg.DirectorySnapshotFile)
	if err != nil {
		return nil, err
	}
	handler, err := relay.NewDirectoryHandler(authenticator, source, nil)
	if err != nil {
		return nil, err
	}
	if cfg.AccessIssuer != "" {
		verifier, err := access.NewVerifier(access.Config{Issuer: cfg.AccessIssuer, Audience: cfg.AccessAudience, JWKSURL: cfg.AccessJWKSURL}, nil)
		if err != nil {
			return nil, err
		}
		handler = verifier.Middleware(handler)
	}
	return handler, nil
}

func buildRelayHandler(cfg config.Config) (http.Handler, *relay.Store, error) {
	if !cfg.RelayEnabled {
		return nil, nil, nil
	}
	machines, err := relay.ParseMachineEnrollments(cfg.RelayMachinesJSON)
	if err != nil {
		return nil, nil, err
	}
	store, err := relay.Open(filepath.Join(cfg.DataDir, "relay.db"))
	if err != nil {
		return nil, nil, err
	}
	authenticator, err := relay.NewAuthenticator(store, machines)
	if err != nil {
		_ = store.Close()
		return nil, nil, err
	}
	handler := relay.NewHandler(store, authenticator, relay.HandlerOptions{})
	if cfg.AccessIssuer != "" {
		verifier, err := access.NewVerifier(access.Config{Issuer: cfg.AccessIssuer, Audience: cfg.AccessAudience, JWKSURL: cfg.AccessJWKSURL}, nil)
		if err != nil {
			_ = store.Close()
			return nil, nil, err
		}
		handler = verifier.Middleware(handler)
	}
	return handler, store, nil
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}
