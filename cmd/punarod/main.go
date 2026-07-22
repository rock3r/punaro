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
	"github.com/rock3r/punaro/internal/config"
	"github.com/rock3r/punaro/internal/devicehttp"
	"github.com/rock3r/punaro/internal/ingress"
	"github.com/rock3r/punaro/internal/memoryhttp"
	punaropostgres "github.com/rock3r/punaro/internal/postgres"
	"github.com/rock3r/punaro/internal/relay"
	"github.com/rock3r/punaro/internal/trustedattachment"
	"github.com/rock3r/punaro/internal/trustedattachmenthttp"
)

const (
	trustedReconcileBatch    = 100
	trustedReconcileMaxPages = 1000
	trustedOrphanGrace       = 24 * time.Hour
	trustedGCClaimLifetime   = time.Minute
	trustedReconcileInterval = 5 * time.Minute
)

type platformDatabase interface {
	Ready(context.Context) error
	Close() error
}

type deviceDatabase interface {
	RedeemEnrollment(context.Context, punaropostgres.RedeemEnrollment) (punaropostgres.DeviceCredential, error)
	AuthenticateDevice(context.Context, string) (punaropostgres.AuthenticatedDevice, error)
}

type trustedAttachmentDatabase interface {
	deviceDatabase
	trustedattachment.Repository
	TrustedAttachmentRuntimeReady(context.Context) error
	ReserveAttachment(context.Context, punaropostgres.AttachmentReservationRequest) (punaropostgres.AttachmentReservation, error)
}

type memoryDatabase interface {
	deviceDatabase
	CanonicalBrainRuntimeReady(context.Context) error
	ResolveProjectIdentity(context.Context, string, punaropostgres.ProjectIdentityKind, string) (punaropostgres.ProjectIdentityResolution, error)
	GetMemory(context.Context, string, string, string) (punaropostgres.MemoryItem, error)
	GetMemoryProposal(context.Context, string, string, string) (punaropostgres.MemoryProposal, error)
	SearchMemory(context.Context, punaropostgres.MemorySearchRequest) (punaropostgres.MemorySearchPage, error)
	BuildMemoryPromptBrief(context.Context, punaropostgres.MemoryPromptBriefRequest) (punaropostgres.MemoryPromptBrief, error)
	FetchMemoryChanges(context.Context, punaropostgres.MemoryChangeRequest) (punaropostgres.MemoryChangePage, error)
}

type credentialTransitionDatabase interface {
	deviceDatabase
	DeviceSessionCurrent(context.Context, punaropostgres.AuthenticatedDevice) (bool, error)
	ResolveLegacyMachine(context.Context, ed25519.PublicKey) (string, error)
	ResolveMigratedLegacyPublicKey(context.Context, punaropostgres.AuthenticatedDevice) (ed25519.PublicKey, error)
}

type postgresTransitionAuthority struct {
	database credentialTransitionDatabase
}

func (a postgresTransitionAuthority) AuthorizeTransition(ctx context.Context, credential string, legacyKey ed25519.PublicKey) (relay.TransitionAuthorization, error) {
	if a.database == nil || (credential == "") == (len(legacyKey) == 0) {
		return relay.TransitionAuthorization{}, relay.ErrForbidden
	}
	if credential == "" {
		principalID, err := a.database.ResolveLegacyMachine(ctx, legacyKey)
		if err != nil {
			return relay.TransitionAuthorization{}, relay.ErrForbidden
		}
		key := append(ed25519.PublicKey(nil), legacyKey...)
		return relay.TransitionAuthorization{PrincipalID: principalID, LegacyPublicKey: key, Current: func(currentCtx context.Context) error {
			if _, err := a.database.ResolveLegacyMachine(currentCtx, key); err != nil {
				return relay.ErrForbidden
			}
			return nil
		}}, nil
	}
	authenticated, err := a.database.AuthenticateDevice(ctx, credential)
	if err != nil {
		return relay.TransitionAuthorization{}, relay.ErrForbidden
	}
	publicKey, err := a.database.ResolveMigratedLegacyPublicKey(ctx, authenticated)
	if err != nil {
		return relay.TransitionAuthorization{}, relay.ErrForbidden
	}
	key := append(ed25519.PublicKey(nil), publicKey...)
	return relay.TransitionAuthorization{PrincipalID: authenticated.PrincipalID, CredentialLookupID: authenticated.LookupID, CredentialGeneration: authenticated.Generation, LegacyPublicKey: key, Current: func(currentCtx context.Context) error {
		current, err := a.database.DeviceSessionCurrent(currentCtx, authenticated)
		if err != nil || !current {
			return relay.ErrForbidden
		}
		resolved, err := a.database.ResolveMigratedLegacyPublicKey(currentCtx, authenticated)
		if err != nil || !bytes.Equal(resolved, key) {
			return relay.ErrForbidden
		}
		return nil
	}}, nil
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
	trustedAttachmentHandler, err := buildTrustedAttachmentHandler(cfg, platformDB)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "punarod trusted attachment configuration error: %v\n", err)
		return 2
	}
	if trustedAttachmentHandler != nil {
		defer trustedAttachmentHandler.Close()
	}
	memoryHandler, err := buildMemoryHandler(cfg, platformDB)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "punarod memory API configuration error: %v\n", err)
		return 2
	}
	logger := log.New(os.Stderr, "punarod ", log.LstdFlags|log.LUTC)
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"status":"ok"}\n`)) })
	healthMux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if postgresReadiness() != nil || accessReadiness() != nil || (trustedAttachmentHandler != nil && trustedAttachmentHandler.Ready() != nil) {
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
	registerProductionRoutes(mux, memoryHandler, trustedAttachmentHandler, relayHandler)
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

func registerProductionRoutes(mux *http.ServeMux, memoryHandler http.Handler, trustedAttachmentHandler *trustedAttachmentRuntime, relayHandler http.Handler) {
	if memoryHandler != nil {
		mux.Handle("/v1/projects/resolve", memoryHandler)
		mux.Handle("/v1/projects/", memoryHandler)
	}
	if trustedAttachmentHandler != nil {
		mux.Handle("/v1/trusted-attachments", trustedAttachmentHandler)
		mux.Handle("/v1/trusted-attachments/", trustedAttachmentHandler)
	}
	if relayHandler != nil {
		mux.Handle("/v1/", relayHandler)
	}
}

func buildMemoryHandler(cfg config.Config, platformDB platformDatabase) (http.Handler, error) {
	if !cfg.MemoryAPIEnabled {
		return nil, nil
	}
	database, ok := platformDB.(memoryDatabase)
	if !ok {
		return nil, errors.New("PostgreSQL memory database authority is unavailable")
	}
	readinessCtx, readinessCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer readinessCancel()
	if err := database.CanonicalBrainRuntimeReady(readinessCtx); err != nil {
		return nil, errors.New("PostgreSQL canonical brain schema is unavailable")
	}
	policy := &ingress.Policy{Mode: ingress.Mode(cfg.IngressMode), ListenAddr: cfg.ListenAddr, PublicURL: cfg.PublicURL, TrustedLAN: cfg.TrustedLANCIDR, AllowPlaintext: cfg.TrustedLANHTTP}
	if err := policy.Validate(); err != nil {
		return nil, errors.New("memory credential transport policy is invalid")
	}
	return memoryhttp.New(database, policy), nil
}

func buildTrustedAttachmentHandler(cfg config.Config, platformDB platformDatabase) (*trustedAttachmentRuntime, error) {
	if !cfg.TrustedAttachmentsEnabled {
		return nil, nil
	}
	database, ok := platformDB.(trustedAttachmentDatabase)
	if !ok {
		return nil, errors.New("PostgreSQL attachment database authority is unavailable")
	}
	readinessCtx, readinessCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer readinessCancel()
	if err := database.TrustedAttachmentRuntimeReady(readinessCtx); err != nil {
		return nil, errors.New("PostgreSQL trusted attachment schema is unavailable")
	}
	store, err := trustedattachment.OpenBlobStore(cfg.TrustedAttachmentBlobDir)
	if err != nil {
		return nil, err
	}
	service, err := trustedattachment.NewService(database, store)
	if err != nil {
		return nil, err
	}
	reconcileCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := reconcileTrustedAttachments(reconcileCtx, service); err != nil {
		return nil, errors.New("trusted attachment startup reconciliation failed")
	}
	policy := &ingress.Policy{Mode: ingress.Mode(cfg.IngressMode), ListenAddr: cfg.ListenAddr, PublicURL: cfg.PublicURL, TrustedLAN: cfg.TrustedLANCIDR, AllowPlaintext: cfg.TrustedLANHTTP}
	if err := policy.Validate(); err != nil {
		return nil, errors.New("trusted attachment ingress policy is invalid")
	}
	return newTrustedAttachmentRuntime(trustedattachmenthttp.New(database, service, policy), service), nil
}

type trustedAttachmentRuntime struct {
	handler http.Handler
	cancel  context.CancelFunc
	done    chan struct{}
	mu      sync.RWMutex
	err     error
}

func newTrustedAttachmentRuntime(handler http.Handler, reconciler attachmentReconciler) *trustedAttachmentRuntime {
	ctx, cancel := context.WithCancel(context.Background())
	runtime := &trustedAttachmentRuntime{handler: handler, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(runtime.done)
		ticker := time.NewTicker(trustedReconcileInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				operationCtx, operationCancel := context.WithTimeout(ctx, trustedReconcileInterval)
				err := reconcileTrustedAttachments(operationCtx, reconciler)
				operationCancel()
				runtime.mu.Lock()
				runtime.err = err
				runtime.mu.Unlock()
			}
		}
	}()
	return runtime
}

func (runtime *trustedAttachmentRuntime) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if runtime == nil || runtime.handler == nil || runtime.Ready() != nil {
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Cache-Control", "no-store")
		response.WriteHeader(http.StatusServiceUnavailable)
		_, _ = response.Write([]byte("{\"error\":\"attachment service is unavailable\"}\n"))
		return
	}
	runtime.handler.ServeHTTP(response, request)
}

func (runtime *trustedAttachmentRuntime) Ready() error {
	if runtime == nil {
		return errors.New("trusted attachment runtime is unavailable")
	}
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	return runtime.err
}

func (runtime *trustedAttachmentRuntime) Close() {
	if runtime == nil || runtime.cancel == nil {
		return
	}
	runtime.cancel()
	<-runtime.done
}

type attachmentReconciler interface {
	ReconcileBatch(context.Context, punaropostgres.AttachmentReconcileCursor, int) (trustedattachment.ReconcileResult, error)
	GarbageCollectBatch(context.Context, string, int, time.Duration) (trustedattachment.GarbageCollectResult, error)
	ReconcileOrphanBatch(context.Context, string, int, time.Duration) (trustedattachment.OrphanReconcileResult, error)
}

func reconcileTrustedAttachments(ctx context.Context, reconciler attachmentReconciler) error {
	if reconciler == nil {
		return errors.New("trusted attachment reconciler is unavailable")
	}
	cursor := punaropostgres.AttachmentReconcileCursor{}
	databaseComplete := false
	for page := 0; page < trustedReconcileMaxPages; page++ {
		result, err := reconciler.ReconcileBatch(ctx, cursor, trustedReconcileBatch)
		if err != nil {
			return err
		}
		if result.Changed != 0 {
			cursor = punaropostgres.AttachmentReconcileCursor{}
			continue
		}
		if result.Scanned < trustedReconcileBatch {
			databaseComplete = true
			break
		}
		cursor = result.Next
	}
	if !databaseComplete {
		return errors.New("trusted attachment database reconciliation exceeds startup bound")
	}
	gcAfter := ""
	gcComplete := false
	for page := 0; page < trustedReconcileMaxPages; page++ {
		result, err := reconciler.GarbageCollectBatch(ctx, gcAfter, trustedReconcileBatch, trustedGCClaimLifetime)
		if err != nil {
			return err
		}
		if result.Changed != 0 {
			gcAfter = ""
			continue
		}
		if result.Scanned < trustedReconcileBatch {
			gcComplete = true
			break
		}
		gcAfter = result.Next
	}
	if !gcComplete {
		return errors.New("trusted attachment deletion garbage collection exceeds startup bound")
	}
	after := ""
	filesystemComplete := false
	for page := 0; page < trustedReconcileMaxPages; page++ {
		result, err := reconciler.ReconcileOrphanBatch(ctx, after, trustedReconcileBatch, trustedOrphanGrace)
		if err != nil {
			return err
		}
		if result.Changed != 0 {
			after = ""
			continue
		}
		if result.Scanned < trustedReconcileBatch {
			filesystemComplete = true
			break
		}
		after = result.Next
	}
	if !filesystemComplete {
		return errors.New("trusted attachment filesystem reconciliation exceeds startup bound")
	}
	return nil
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
	var authenticator *relay.Authenticator
	if cfg.CredentialTransitionEnabled {
		transitionDatabase, ok := backend.(credentialTransitionDatabase)
		if !ok {
			if store != nil {
				_ = store.Close()
			}
			return nil, nil, errors.New("credential transition store is unavailable")
		}
		authenticator, err = relay.NewTransitionAuthenticator(backend, machines, postgresTransitionAuthority{database: transitionDatabase})
	} else {
		authenticator, err = relay.NewAuthenticator(backend, machines)
	}
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
