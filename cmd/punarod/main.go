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
	permitHandler, closePermit, err := buildPermitHandler(cfg, relayStore)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "punarod permit configuration error: %v\n", err)
		return 2
	}
	if closePermit != nil {
		defer closePermit()
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
	if permitHandler != nil {
		mux.Handle("/v2/permits", permitHandler)
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

type permitRouteAuthorizer struct{ authenticator *relay.Authenticator }

func (a permitRouteAuthorizer) AuthorizePermitRequest(ctx context.Context, request attachmentv2.PermitRequest) error {
	machineID, authenticated := relay.AuthenticatedMachineID(ctx)
	if !authenticated || a.authenticator == nil {
		return errors.New("permit route is not machine-authenticated")
	}
	deviceID, bound := a.authenticator.AttachmentDeviceID(machineID)
	if !bound || deviceID != request.HolderDeviceID {
		return errors.New("machine is not bound to permit holder")
	}
	return nil
}

// buildPermitHandler exposes only permit issuance, never attachment upload or
// download. It binds an enrolled transport identity to the directory holder
// before issuing a capability and fetches a newly verified directory snapshot
// for every request. The returned closer owns the private checkpoint and
// issuance ledgers.
func buildPermitHandler(cfg config.Config, store *relay.Store) (http.Handler, func(), error) {
	if !cfg.PermitIssuanceEnabled {
		return nil, nil, nil
	}
	if store == nil {
		return nil, nil, errors.New("permit issuance requires relay store")
	}
	machines, err := relay.ParseMachineEnrollments(cfg.RelayMachinesJSON)
	if err != nil {
		return nil, nil, err
	}
	boundMachines := 0
	for _, machine := range machines {
		if machine.AttachmentDeviceID != [16]byte{} {
			boundMachines++
		}
	}
	if boundMachines == 0 {
		return nil, nil, errors.New("permit issuance requires an enrolled attachment device binding")
	}
	authenticator, err := relay.NewAuthenticator(store, machines)
	if err != nil {
		return nil, nil, err
	}
	source, err := attachmentv2.OpenDirectorySnapshotFileSource(cfg.DirectorySnapshotFile)
	if err != nil {
		return nil, nil, err
	}
	privateDir := filepath.Join(cfg.DataDir, "attachment-v2")
	checkpoints, err := attachmentv2.OpenSQLiteCheckpointStore(filepath.Join(privateDir, "directory-checkpoints.db"))
	if err != nil {
		return nil, nil, err
	}
	ledger, err := attachmentv2.OpenSQLitePermitLedger(filepath.Join(privateDir, "permit-ledger.db"))
	if err != nil {
		_ = checkpoints.Close()
		return nil, nil, err
	}
	closeStores := func() {
		_ = ledger.Close()
		_ = checkpoints.Close()
	}
	privateKey, err := attachmentv2.LoadPrivateEd25519KeyFile(cfg.PermitIssuerPrivateKeyFile)
	if err != nil {
		closeStores()
		return nil, nil, err
	}
	authority, err := attachmentv2.NewFreshDirectoryAuthorityProvider(source, attachmentv2.DirectoryTrust{Audience: cfg.DirectoryAudience, RootKeyID: cfg.DirectoryRootKeyID, RootPublicKey: cfg.DirectoryRootPublicKey, Checkpoints: checkpoints})
	if err != nil {
		closeStores()
		return nil, nil, err
	}
	lifetime, err := permitIssuerLifetime(cfg.PermitMaxLifetimeSeconds)
	if err != nil {
		closeStores()
		return nil, nil, err
	}
	issuer, err := attachmentv2.NewPermitIssuer(attachmentv2.PermitIssuerOptions{Ledger: ledger, IssuerKeyID: cfg.PermitIssuerKeyID, PrivateKey: privateKey, MaxLifetime: lifetime, MaxBytes: cfg.PermitMaxBytes, MaxChunks: cfg.PermitMaxChunks, MaxOperations: cfg.PermitMaxOperations})
	if err != nil {
		closeStores()
		return nil, nil, err
	}
	handler, err := attachmentv2.NewPermitHTTPHandler(issuer, authority, permitRouteAuthorizer{authenticator: authenticator}, nil)
	if err != nil {
		closeStores()
		return nil, nil, err
	}
	middleware, err := relay.NewMachineAuthenticationMiddleware(authenticator, 4<<10, nil)
	if err != nil {
		closeStores()
		return nil, nil, err
	}
	handler = middleware(handler)
	if cfg.AccessIssuer != "" {
		verifier, err := access.NewVerifier(access.Config{Issuer: cfg.AccessIssuer, Audience: cfg.AccessAudience, JWKSURL: cfg.AccessJWKSURL}, nil)
		if err != nil {
			closeStores()
			return nil, nil, err
		}
		handler = verifier.Middleware(handler)
	}
	return handler, closeStores, nil
}

func permitIssuerLifetime(seconds uint64) (time.Duration, error) {
	if seconds == 0 || seconds > 60 {
		return 0, errors.New("permit issuer lifetime must be between one and sixty seconds")
	}
	return time.Duration(seconds) * time.Second, nil // #nosec G115 -- bound above is safely representable in time.Duration.
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
