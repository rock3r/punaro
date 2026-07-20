// punarod is the central Punaro relay daemon.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/rock3r/punaro/internal/access"
	attachmentv2 "github.com/rock3r/punaro/internal/attachment/v2"
	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
	"github.com/rock3r/punaro/internal/config"
	"github.com/rock3r/punaro/internal/devicehttp"
	"github.com/rock3r/punaro/internal/ingress"
	punaropostgres "github.com/rock3r/punaro/internal/postgres"
	"github.com/rock3r/punaro/internal/relay"
)

const (
	attachmentV3ReapInterval = time.Minute
	attachmentV3ReapBatch    = 64
)

type platformDatabase interface {
	Ready(context.Context) error
	Close() error
}

type deviceDatabase interface {
	RedeemEnrollment(context.Context, punaropostgres.RedeemEnrollment) (punaropostgres.DeviceCredential, error)
	AuthenticateDevice(context.Context, string) (punaropostgres.AuthenticatedDevice, error)
}

var openPlatformDatabase = func(ctx context.Context, cfg punaropostgres.Config) (platformDatabase, error) {
	return punaropostgres.OpenApplication(ctx, cfg)
}

var listenTCP = net.Listen

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
	postgresReadiness := func() error { return nil }
	var platformDB platformDatabase
	if cfg.PostgresEnabled {
		platformDB, err = openPlatformDatabase(context.Background(), punaropostgres.Config{DSNFile: cfg.PostgresDSNFile})
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "punarod PostgreSQL configuration error: %v\n", err)
			return 2
		}
		defer func() { _ = platformDB.Close() }()
		postgresReadiness = func() error { return platformDB.Ready(context.Background()) }
		if err := postgresReadiness(); err != nil {
			_, _ = fmt.Fprintf(stderr, "punarod PostgreSQL readiness error: %v\n", err)
			return 2
		}
	}
	accessReadiness := func() error { return nil }
	if cfg.AccessIssuer != "" {
		verifier, err := newAccessVerifier(cfg)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "punarod Access configuration error: %v\n", err)
			return 2
		}
		accessReadiness = func() error { return verifier.Warm(context.Background(), time.Now().UTC()) }
		if err := accessReadiness(); err != nil {
			_, _ = fmt.Fprintf(stderr, "punarod Access readiness error: %v\n", err)
			return 2
		}
	}
	var postgresRelay relay.Backend
	if cfg.RelayStore == "postgres" {
		var ok bool
		postgresRelay, ok = platformDB.(relay.Backend)
		if !ok {
			_, _ = fmt.Fprintln(stderr, "punarod relay configuration error: PostgreSQL relay store is unavailable")
			return 2
		}
	}
	relayHandler, relayStore, err := buildRelayHandler(cfg, postgresRelay)
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
	permitHandler, closePermit, permitReadiness, err := buildPermitHandler(cfg, relayStore)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "punarod permit configuration error: %v\n", err)
		return 2
	}
	if closePermit != nil {
		defer closePermit()
	}
	v3PermitHandler, v3AttachmentHandler, closeV3, v3Readiness, err := buildV3AttachmentHandlers(cfg, relayStore)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "punarod v3 attachment configuration error: %v\n", err)
		return 2
	}
	if closeV3 != nil {
		defer closeV3()
	}
	logger := log.New(os.Stderr, "punarod ", log.LstdFlags|log.LUTC)
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"status":"ok"}\n`)) })
	healthMux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if postgresReadiness() != nil || accessReadiness() != nil || (permitReadiness != nil && permitReadiness() != nil) || (v3Readiness != nil && v3Readiness() != nil) {
			http.Error(w, `{"status":"not_ready"}`, http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"status":"ready"}\n`))
	})
	mux := http.NewServeMux()
	if cfg.DeviceAuthEnabled {
		database, ok := platformDB.(deviceDatabase)
		if !ok {
			_, _ = fmt.Fprintln(stderr, "punarod device ingress error: PostgreSQL device store is unavailable")
			return 2
		}
		policy := &ingress.Policy{Mode: ingress.Mode(cfg.IngressMode), ListenAddr: cfg.ListenAddr, PublicURL: cfg.PublicURL, TrustedLAN: cfg.TrustedLANCIDR, AllowPlaintext: cfg.TrustedLANHTTP}
		if err := policy.Validate(); err != nil {
			_, _ = fmt.Fprintln(stderr, "punarod device ingress error: invalid transport policy")
			return 2
		}
		deviceHandler := devicehttp.New(database, policy)
		mux.Handle("/v1/enrollments/redeem", deviceHandler)
		mux.Handle("/v1/device/session", deviceHandler)
	}
	if relayHandler != nil {
		mux.Handle("/v1/", relayHandler)
	}
	if directoryHandler != nil {
		mux.Handle("/v2/directory", directoryHandler)
	}
	if permitHandler != nil {
		mux.Handle("/v2/permits", permitHandler)
	}
	if v3PermitHandler != nil {
		mux.Handle("/v3/permits", v3PermitHandler)
	}
	if v3AttachmentHandler != nil {
		mux.Handle("/v3/attachments/", v3AttachmentHandler)
	}
	server := configuredServer(cfg.ListenAddr, securityHeaders(mux))
	healthServer := configuredServer(cfg.HealthListenAddr, securityHeaders(healthMux))
	publicListener, err := listenTCP("tcp", cfg.ListenAddr)
	if err != nil {
		logger.Printf("public listener bind failed error=%v", err)
		return 1
	}
	healthListener, err := listenTCP("tcp", cfg.HealthListenAddr)
	if err != nil {
		_ = publicListener.Close()
		logger.Printf("health listener bind failed error=%v", err)
		return 1
	}
	type serverResult struct {
		name string
		err  error
	}
	serverErrors := make(chan serverResult, 2)
	go func() { serverErrors <- serverResult{name: "public", err: server.Serve(publicListener)} }()
	go func() { serverErrors <- serverResult{name: "health", err: healthServer.Serve(healthListener)} }()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	logger.Printf("listening address=%s health_address=%s data_dir=%s log_level=%s", cfg.ListenAddr, cfg.HealthListenAddr, cfg.DataDir, cfg.LogLevel)
	select {
	case result := <-serverErrors:
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = shutdownHTTPServers(shutdown, server, healthServer)
		if result.err != nil && !errors.Is(result.err, http.ErrServerClosed) {
			logger.Printf("%s server stopped error=%v", result.name, result.err)
			return 1
		}
		return 0
	case <-signals:
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := shutdownHTTPServers(shutdown, server, healthServer); err != nil {
			logger.Printf("graceful shutdown failed error=%v", err)
			return 1
		}
		return 0
	}
}

func configuredServer(address string, handler http.Handler) *http.Server {
	return &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
}

type httpShutdowner interface {
	Shutdown(context.Context) error
}

func shutdownHTTPServers(ctx context.Context, servers ...httpShutdowner) error {
	failures := make(chan error, len(servers))
	var wait sync.WaitGroup
	for _, server := range servers {
		if server != nil {
			wait.Add(1)
			go func() {
				defer wait.Done()
				if err := server.Shutdown(ctx); err != nil {
					failures <- err
				}
			}()
		}
	}
	wait.Wait()
	close(failures)
	var joined []error
	for err := range failures {
		joined = append(joined, err)
	}
	return errors.Join(joined...)
}

type permitRouteAuthorizer struct{ authenticator *relay.Authenticator }

// attachmentV3RouteAuthorizer binds an independently authenticated enrolled
// machine to the exact directory device named by a v3 permit. Possession of a
// copied permit/operation is never sufficient for route admission.
type attachmentV3RouteAuthorizer struct{ authenticator *relay.Authenticator }

func (a attachmentV3RouteAuthorizer) AuthorizeAttachmentRequest(ctx context.Context, permit attachmentv3.Permit) error {
	machineID, authenticated := relay.AuthenticatedMachineID(ctx)
	if !authenticated || a.authenticator == nil {
		return errors.New("v3 attachment route is not machine-authenticated")
	}
	deviceID, bound := a.authenticator.AttachmentDeviceID(machineID)
	if !bound || deviceID != permit.HolderDeviceID {
		return errors.New("machine is not bound to v3 attachment permit holder")
	}
	return nil
}

// attachmentV3PermitRouteAuthorizer applies the same independent
// machine-to-directory-device binding before the issuer even looks up a
// holder key. This prevents one enrolled machine from submitting a copied
// holder-signed v3 permit request for another machine's device.
type attachmentV3PermitRouteAuthorizer struct{ authenticator *relay.Authenticator }

func (a attachmentV3PermitRouteAuthorizer) AuthorizePermitRequest(ctx context.Context, request attachmentv3.PermitRequest) error {
	machineID, authenticated := relay.AuthenticatedMachineID(ctx)
	if !authenticated || a.authenticator == nil {
		return errors.New("v3 permit route is not machine-authenticated")
	}
	deviceID, bound := a.authenticator.AttachmentDeviceID(machineID)
	if !bound || deviceID != request.HolderDeviceID {
		return errors.New("machine is not bound to v3 permit holder")
	}
	return nil
}

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

func (a permitRouteAuthorizer) AuthorizeAttachmentRequest(ctx context.Context, permit attachmentv2.Permit) error {
	machineID, authenticated := relay.AuthenticatedMachineID(ctx)
	if !authenticated || a.authenticator == nil {
		return errors.New("attachment route is not machine-authenticated")
	}
	deviceID, bound := a.authenticator.AttachmentDeviceID(machineID)
	if !bound || deviceID != permit.HolderDeviceID {
		return errors.New("machine is not bound to attachment permit holder")
	}
	return nil
}

// buildPermitHandler exposes only permit issuance, never attachment upload or
// download. It binds an enrolled transport identity to the directory holder
// before issuing a capability and fetches a newly verified directory snapshot
// for every request. The returned closer owns the private checkpoint and
// issuance ledgers.
func buildPermitHandler(cfg config.Config, store *relay.Store) (http.Handler, func(), func() error, error) {
	if !cfg.PermitIssuanceEnabled {
		return nil, nil, nil, nil
	}
	if store == nil {
		return nil, nil, nil, errors.New("permit issuance requires relay store")
	}
	machines, err := relay.ParseMachineEnrollments(cfg.RelayMachinesJSON)
	if err != nil {
		return nil, nil, nil, err
	}
	boundMachines := 0
	for _, machine := range machines {
		if machine.AttachmentDeviceID != [16]byte{} {
			boundMachines++
		}
	}
	if boundMachines == 0 {
		return nil, nil, nil, errors.New("permit issuance requires an enrolled attachment device binding")
	}
	authenticator, err := relay.NewAuthenticator(store, machines)
	if err != nil {
		return nil, nil, nil, err
	}
	source, err := attachmentv2.OpenDirectorySnapshotFileSource(cfg.DirectorySnapshotFile)
	if err != nil {
		return nil, nil, nil, err
	}
	privateDir := filepath.Join(cfg.DataDir, "attachment-v2")
	checkpoints, err := attachmentv2.OpenSQLiteCheckpointStore(filepath.Join(privateDir, "directory-checkpoints.db"))
	if err != nil {
		return nil, nil, nil, err
	}
	ledger, err := attachmentv2.OpenSQLitePermitLedger(filepath.Join(privateDir, "permit-ledger.db"))
	if err != nil {
		_ = checkpoints.Close()
		return nil, nil, nil, err
	}
	closeStores := func() {
		_ = ledger.Close()
		_ = checkpoints.Close()
	}
	privateKey, err := attachmentv2.LoadPrivateEd25519KeyFile(cfg.PermitIssuerPrivateKeyFile)
	if err != nil {
		closeStores()
		return nil, nil, nil, err
	}
	authority, err := attachmentv2.NewFreshDirectoryAuthorityProvider(source, attachmentv2.DirectoryTrust{Audience: cfg.DirectoryAudience, RootKeyID: cfg.DirectoryRootKeyID, RootPublicKey: cfg.DirectoryRootPublicKey, Checkpoints: checkpoints})
	if err != nil {
		closeStores()
		return nil, nil, nil, err
	}
	lifetime, err := permitIssuerLifetime(cfg.PermitMaxLifetimeSeconds)
	if err != nil {
		closeStores()
		return nil, nil, nil, err
	}
	issuer, err := attachmentv2.NewPermitIssuer(attachmentv2.PermitIssuerOptions{Ledger: ledger, IssuerKeyID: cfg.PermitIssuerKeyID, PrivateKey: privateKey, MaxLifetime: lifetime, MaxBytes: cfg.PermitMaxBytes, MaxChunks: cfg.PermitMaxChunks, MaxOperations: cfg.PermitMaxOperations, MaxActive: cfg.PermitMaxActive})
	if err != nil {
		closeStores()
		return nil, nil, nil, err
	}
	handler, err := attachmentv2.NewPermitHTTPHandler(issuer, authority, permitRouteAuthorizer{authenticator: authenticator}, nil)
	if err != nil {
		closeStores()
		return nil, nil, nil, err
	}
	middleware, err := relay.NewMachineAuthenticationMiddleware(authenticator, 4<<10, nil)
	if err != nil {
		closeStores()
		return nil, nil, nil, err
	}
	handler = middleware(handler)
	if cfg.AccessIssuer != "" {
		verifier, err := newAccessVerifier(cfg)
		if err != nil {
			closeStores()
			return nil, nil, nil, err
		}
		handler = verifier.Middleware(handler)
	}
	issuerPublic := privateKey.Public().(ed25519.PublicKey)
	readiness := func() error {
		current, err := authority.ResolvePermitIssuanceAuthority(context.Background(), time.Now().UTC())
		if err != nil {
			return errors.New("fresh permit directory authority is unavailable")
		}
		authorized, err := current.CurrentPermitIssuerKey(cfg.PermitIssuerKeyID)
		if err != nil || !bytes.Equal(authorized, issuerPublic) {
			return errors.New("permit issuer is not directory-authorized")
		}
		return nil
	}
	if err := readiness(); err != nil {
		closeStores()
		return nil, nil, nil, err
	}
	return handler, closeStores, readiness, nil
}

// buildV3AttachmentHandlers constructs the complete v3 permit and transfer
// surface together. It deliberately does not share the v2 ledger or handler:
// only root-verified directory facts are adapted across versions.
func buildV3AttachmentHandlers(cfg config.Config, store *relay.Store) (http.Handler, http.Handler, func(), func() error, error) {
	if !cfg.AttachmentV3Enabled {
		return nil, nil, nil, nil, nil
	}
	if store == nil {
		return nil, nil, nil, nil, errors.New("v3 attachment runtime requires relay store")
	}
	machines, err := relay.ParseMachineEnrollments(cfg.RelayMachinesJSON)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	boundMachines := 0
	for _, machine := range machines {
		if machine.AttachmentDeviceID != [16]byte{} {
			boundMachines++
		}
	}
	if boundMachines == 0 {
		return nil, nil, nil, nil, errors.New("v3 attachment runtime requires an enrolled attachment device binding")
	}
	authenticator, err := relay.NewAuthenticator(store, machines)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	source, err := attachmentv2.OpenDirectorySnapshotFileSource(cfg.DirectorySnapshotFile)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	privateDir := filepath.Join(cfg.DataDir, "attachment-v3")
	checkpoints, err := attachmentv2.OpenSQLiteCheckpointStore(filepath.Join(privateDir, "directory-checkpoints.db"))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	closeStores := func() { _ = checkpoints.Close() }
	privateKey, err := attachmentv2.LoadPrivateEd25519KeyFile(cfg.PermitIssuerPrivateKeyFile)
	if err != nil {
		closeStores()
		return nil, nil, nil, nil, err
	}
	directoryProvider, err := attachmentv2.NewFreshDirectoryAuthorityProvider(source, attachmentv2.DirectoryTrust{Audience: cfg.DirectoryAudience, RootKeyID: cfg.DirectoryRootKeyID, RootPublicKey: cfg.DirectoryRootPublicKey, Checkpoints: checkpoints})
	if err != nil {
		closeStores()
		return nil, nil, nil, nil, err
	}
	authority, err := attachmentv3.NewDirectoryAuthorityAdapter(directoryProvider)
	if err != nil {
		closeStores()
		return nil, nil, nil, nil, err
	}
	lifetime, err := v3PermitIssuerLifetime(cfg.PermitMaxLifetimeSeconds)
	if err != nil {
		closeStores()
		return nil, nil, nil, nil, err
	}
	runtime, err := attachmentv3.NewAttachmentRuntime(attachmentv3.AttachmentRuntimeOptions{SourceStorePath: cfg.AttachmentV3SourceStoreFile, AttachmentAuthority: authority, PermitAuthority: authority, AttachmentAuthorize: attachmentV3RouteAuthorizer{authenticator: authenticator}, PermitAuthorize: attachmentV3PermitRouteAuthorizer{authenticator: authenticator}, IssuerKeyID: cfg.PermitIssuerKeyID, IssuerPrivateKey: privateKey, MaxLifetime: lifetime, MaxBytes: cfg.PermitMaxBytes, MaxChunks: cfg.PermitMaxChunks, MaxOperations: cfg.PermitMaxOperations, MaxActive: cfg.PermitMaxActive})
	if err != nil {
		closeStores()
		return nil, nil, nil, nil, err
	}
	// Recover quota before exposing handlers. Waiting for the first periodic
	// tick after a restart could leave every finite source slot occupied by
	// already-expired state and deny otherwise valid source-init operations.
	if _, err := runtime.ReapExpired(context.Background(), time.Now().UTC(), attachmentV3ReapBatch); err != nil {
		_ = runtime.Close()
		closeStores()
		return nil, nil, nil, nil, fmt.Errorf("recover expired v3 attachment state: %w", err)
	}
	var closeRuntimeOnce sync.Once
	closeRuntime := func() {
		closeRuntimeOnce.Do(func() {
			_ = runtime.Close()
			closeStores()
		})
	}
	permitMiddleware, err := relay.NewMachineAuthenticationMiddleware(authenticator, 4<<10, nil)
	if err != nil {
		closeRuntime()
		return nil, nil, nil, nil, err
	}
	attachmentMiddleware, err := relay.NewMachineAuthenticationMiddleware(authenticator, 256<<10+16, nil)
	if err != nil {
		closeRuntime()
		return nil, nil, nil, nil, err
	}
	permitHandler := permitMiddleware(runtime.PermitHandler())
	attachmentHandler := attachmentMiddleware(runtime.AttachmentHandler())
	if cfg.AccessIssuer != "" {
		verifier, err := newAccessVerifier(cfg)
		if err != nil {
			closeRuntime()
			return nil, nil, nil, nil, err
		}
		permitHandler = verifier.Middleware(permitHandler)
		attachmentHandler = verifier.Middleware(attachmentHandler)
	}
	issuerPublic := privateKey.Public().(ed25519.PublicKey)
	readiness := func() error {
		current, err := authority.ResolvePermitIssuanceAuthority(context.Background(), time.Now().UTC())
		if err != nil {
			return errors.New("fresh v3 permit directory authority is unavailable")
		}
		authorized, err := current.CurrentPermitIssuerKey(cfg.PermitIssuerKeyID)
		if err != nil || !bytes.Equal(authorized, issuerPublic) {
			return errors.New("v3 permit issuer is not directory-authorized")
		}
		if _, err := authority.ResolveAttachmentAuthority(context.Background(), time.Now().UTC()); err != nil {
			return errors.New("fresh v3 attachment directory authority is unavailable")
		}
		return nil
	}
	if err := readiness(); err != nil {
		closeRuntime()
		return nil, nil, nil, nil, err
	}
	// Reaping does not decide authorization; every live operation fresh-checks
	// the directory first. It only durably releases expired state in bounded
	// batches so a restart or a long-lived quiet relay cannot accumulate source
	// staging forever. The close function waits for it before closing SQLite.
	// #nosec G118 -- closeRuntime below owns and invokes cancelReaper before
	// closing the dependent SQLite runtime.
	reaperContext, cancelReaper := context.WithCancel(context.Background())
	reaperDone := make(chan struct{})
	previousClose := closeRuntime
	closeRuntime = func() {
		cancelReaper()
		<-reaperDone
		previousClose()
	}
	go func() {
		defer close(reaperDone)
		ticker := time.NewTicker(attachmentV3ReapInterval)
		defer ticker.Stop()
		for {
			select {
			case <-reaperContext.Done():
				return
			case now := <-ticker.C:
				_, _ = runtime.ReapExpired(reaperContext, now, attachmentV3ReapBatch)
			}
		}
	}()
	return permitHandler, attachmentHandler, closeRuntime, readiness, nil
}

func v3PermitIssuerLifetime(seconds uint64) (time.Duration, error) {
	if seconds == 0 || seconds > 30 {
		return 0, errors.New("v3 permit issuer lifetime must be between one and thirty seconds")
	}
	return time.Duration(seconds) * time.Second, nil // #nosec G115 -- bound above is safely representable in time.Duration.
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
		verifier, err := newAccessVerifier(cfg)
		if err != nil {
			return nil, err
		}
		handler = verifier.Middleware(handler)
	}
	return handler, nil
}

func buildRelayHandler(cfg config.Config, postgresBackends ...relay.Backend) (http.Handler, *relay.Store, error) {
	if !cfg.RelayEnabled {
		return nil, nil, nil
	}
	machines, err := relay.ParseMachineEnrollments(cfg.RelayMachinesJSON)
	if err != nil {
		return nil, nil, err
	}
	var backend relay.Backend
	var store *relay.Store
	if cfg.RelayStore == "postgres" {
		if len(postgresBackends) != 1 || postgresBackends[0] == nil {
			return nil, nil, errors.New("PostgreSQL relay store is unavailable")
		}
		backend = postgresBackends[0]
	} else {
		store, err = relay.Open(filepath.Join(cfg.DataDir, "relay.db"))
		if err != nil {
			return nil, nil, err
		}
		backend = store
	}
	authenticator, err := relay.NewAuthenticator(backend, machines)
	if err != nil {
		if store != nil {
			_ = store.Close()
		}
		return nil, nil, err
	}
	handler := relay.NewHandler(backend, authenticator, relay.HandlerOptions{})
	if cfg.AccessIssuer != "" {
		verifier, err := newAccessVerifier(cfg)
		if err != nil {
			if store != nil {
				_ = store.Close()
			}
			return nil, nil, err
		}
		handler = verifier.Middleware(handler)
	}
	return handler, store, nil
}

func newAccessVerifier(cfg config.Config) (*access.Verifier, error) {
	return access.NewVerifier(access.Config{Issuer: cfg.AccessIssuer, Audience: cfg.AccessAudience, JWKSURL: cfg.AccessJWKSURL, JWKSFile: cfg.AccessJWKSFile}, nil)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}
