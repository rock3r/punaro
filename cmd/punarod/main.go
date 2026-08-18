// punarod is the central Punaro relay daemon.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/rock3r/punaro/internal/access"
	"github.com/rock3r/punaro/internal/config"
	"github.com/rock3r/punaro/internal/devicehttp"
	"github.com/rock3r/punaro/internal/embeddingprovider"
	"github.com/rock3r/punaro/internal/ingress"
	"github.com/rock3r/punaro/internal/mcphttp"
	"github.com/rock3r/punaro/internal/mcpoauth"
	"github.com/rock3r/punaro/internal/memoryhttp"
	punaropostgres "github.com/rock3r/punaro/internal/postgres"
	"github.com/rock3r/punaro/internal/relay"
	"github.com/rock3r/punaro/internal/trustedattachment"
	"github.com/rock3r/punaro/internal/trustedattachmenthttp"
)

const (
	trustedReconcileBatch       = 100
	trustedReconcileMaxPages    = 1000
	trustedOrphanGrace          = 24 * time.Hour
	trustedGCClaimLifetime      = time.Minute
	trustedReconcileInterval    = 5 * time.Minute
	deliveryMaintenanceInterval = time.Minute
)

type platformDatabase interface {
	Ready(context.Context) error
	Close() error
}

type deviceDatabase interface {
	ClientLifecycleRuntimeReady(context.Context) error
	RedeemEnrollment(context.Context, punaropostgres.RedeemEnrollment) (punaropostgres.DeviceCredential, error)
	AuthenticateDevice(context.Context, string) (punaropostgres.AuthenticatedDevice, error)
	SelfRevokeDevice(context.Context, string, string) (punaropostgres.DeviceRevocation, error)
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
	CreateMemory(context.Context, punaropostgres.MemoryCreateRequest) (punaropostgres.MemoryMutationResult, error)
	UpdateMemory(context.Context, punaropostgres.MemoryUpdateRequest) (punaropostgres.MemoryMutationResult, error)
	ArchiveMemory(context.Context, punaropostgres.MemoryArchiveRequest) (punaropostgres.MemoryMutationResult, error)
	DeleteMemory(context.Context, punaropostgres.MemoryDeleteRequest) (punaropostgres.MemoryMutationResult, error)
	ProposeMemory(context.Context, punaropostgres.MemoryProposalCreateRequest) (punaropostgres.MemoryProposalResult, error)
	ApproveMemoryProposal(context.Context, punaropostgres.MemoryProposalDecisionRequest) (punaropostgres.MemoryProposalResult, error)
	RejectMemoryProposal(context.Context, punaropostgres.MemoryProposalDecisionRequest) (punaropostgres.MemoryProposalResult, error)
	PrepareMemoryHybridSearch(context.Context, punaropostgres.MemorySearchRequest) (punaropostgres.MemoryEmbeddingGeneration, error)
	SearchMemoryHybridLexical(context.Context, punaropostgres.MemorySearchRequest) (punaropostgres.MemoryHybridSearchSurfacePage, error)
	SearchMemoryHybrid(context.Context, punaropostgres.MemoryHybridSearchRequest) (punaropostgres.MemoryHybridSearchSurfacePage, error)
}

type embeddingRuntimeDatabase interface {
	CanonicalBrainRuntimeReady(context.Context) error
	ClaimMemoryEmbeddingWork(context.Context, punaropostgres.MemoryEmbeddingClaimRequest) ([]punaropostgres.MemoryEmbeddingLease, error)
	PublishMemoryEmbeddingWork(context.Context, punaropostgres.MemoryEmbeddingPublication) error
	RetryMemoryEmbeddingWork(context.Context, punaropostgres.MemoryEmbeddingRetry) error
	OpenMemoryEmbeddingSource(context.Context, punaropostgres.MemoryEmbeddingLease) (punaropostgres.MemoryEmbeddingGeneration, []punaropostgres.MemoryEmbeddingSourceChunk, func(), error)
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

var readEmbeddingAPIKey = embeddingprovider.ReadAPIKeyFile

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
	lifecycleReadiness := func() error { return nil }
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
	if relayHandler != nil {
		if stopMaintain := startDeliveryMaintenance(relayStore, postgresRelay); stopMaintain != nil {
			defer stopMaintain()
		}
	}
	relayMetricsSnapshot := func() relay.MetricsSnapshot { return relay.MetricsSnapshot{} }
	if provider, ok := relayHandler.(interface{ MetricsSnapshot() relay.MetricsSnapshot }); ok {
		relayMetricsSnapshot = provider.MetricsSnapshot
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
	remoteMCPMetadataHandler, err := buildRemoteMCPMetadataHandler(cfg, platformDB)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "punarod remote MCP configuration error: metadata is unavailable")
		return 2
	}
	logger := log.New(os.Stderr, "punarod ", log.LstdFlags|log.LUTC)
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"status":"ok"}\n`)) })
	healthMux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !runtimeReady(postgresReadiness, lifecycleReadiness, accessReadiness, trustedAttachmentHandler) {
			http.Error(w, `{"status":"not_ready"}`, http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"status":"ready"}\n`))
	})
	healthMux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(relayMetricsSnapshot())
	})
	mux := http.NewServeMux()
	var transportPolicy *ingress.Policy
	if cfg.DeviceAuthEnabled {
		database, ok := platformDB.(deviceDatabase)
		if !ok {
			_, _ = fmt.Fprintln(stderr, "punarod device ingress error: PostgreSQL device store is unavailable")
			return 2
		}
		lifecycleReadiness = clientLifecycleReadiness(database)
		if err := lifecycleReadiness(); err != nil {
			_, _ = fmt.Fprintln(stderr, "punarod device ingress error: PostgreSQL client lifecycle schema is unavailable")
			return 2
		}
		transportPolicy = &ingress.Policy{Mode: ingress.Mode(cfg.IngressMode), ListenAddr: cfg.ListenAddr, PublicURL: cfg.PublicURL, TrustedLAN: cfg.TrustedLANCIDR, AllowPlaintext: cfg.TrustedLANHTTP}
		if err := transportPolicy.Validate(); err != nil {
			_, _ = fmt.Fprintln(stderr, "punarod device ingress error: invalid transport policy")
			return 2
		}
		deviceHandler := devicehttp.New(database, transportPolicy)
		registerDeviceRoutes(mux, deviceHandler)
	}
	if relayHandler != nil && transportPolicy != nil {
		relayHandler = admitRelayTransport(transportPolicy, relayHandler)
	}
	registerProductionRoutes(mux, memoryHandler, trustedAttachmentHandler, relayHandler, remoteMCPMetadataHandler)
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
	embeddingRuntime, err := buildEmbeddingRuntime(cfg, platformDB)
	if err != nil {
		_ = healthListener.Close()
		_ = publicListener.Close()
		_, _ = fmt.Fprintf(stderr, "punarod embedding worker configuration error: %v\n", err)
		return 2
	}
	if embeddingRuntime != nil {
		defer embeddingRuntime.Close()
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

func admitRelayTransport(policy *ingress.Policy, next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if policy == nil || next == nil || !policy.AllowsCredential(request) {
			http.Error(response, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(response, request)
	})
}

func clientLifecycleReadiness(database deviceDatabase) func() error {
	return func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return database.ClientLifecycleRuntimeReady(ctx)
	}
}

func runtimeReady(postgresReadiness, lifecycleReadiness, accessReadiness func() error, trustedAttachmentHandler *trustedAttachmentRuntime) bool {
	return postgresReadiness() == nil && lifecycleReadiness() == nil && accessReadiness() == nil &&
		(trustedAttachmentHandler == nil || trustedAttachmentHandler.Ready() == nil)
}

func registerDeviceRoutes(mux *http.ServeMux, deviceHandler http.Handler) {
	if deviceHandler == nil {
		return
	}
	mux.Handle("/v1/enrollments/redeem", deviceHandler)
	mux.Handle("/v1/device/session", deviceHandler)
	mux.Handle("/v1/device/session/revoke", deviceHandler)
}

func registerProductionRoutes(mux *http.ServeMux, memoryHandler http.Handler, trustedAttachmentHandler *trustedAttachmentRuntime, relayHandler http.Handler, remoteMCPMetadataHandler http.Handler) {
	if remoteMCPMetadataHandler != nil {
		mux.Handle("/.well-known/oauth-protected-resource", remoteMCPMetadataHandler)
		mux.Handle("/.well-known/oauth-protected-resource/", remoteMCPMetadataHandler)
		mux.Handle("/mcp", remoteMCPMetadataHandler)
	}
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

type remoteMCPPrincipalDatabase interface {
	RemoteMCPPrincipalActive(context.Context, string) (bool, error)
}

func buildRemoteMCPMetadataHandler(cfg config.Config, database platformDatabase) (http.Handler, error) {
	if !cfg.RemoteMCPMetadataEnabled {
		return nil, nil
	}
	var validator mcphttp.TokenValidator
	subjectBindings := map[string]string(nil)
	var principalDatabase remoteMCPPrincipalDatabase
	var err error
	if cfg.RemoteMCPTokenValidationEnabled {
		validator, err = mcpoauth.NewVerifier(mcpoauth.Config{Issuer: cfg.RemoteMCPIssuer, Audience: cfg.RemoteMCPResourceURL, JWKSURL: cfg.RemoteMCPJWKSURL}, nil)
		if err != nil {
			return nil, err
		}
		var ok bool
		principalDatabase, ok = database.(remoteMCPPrincipalDatabase)
		if !ok {
			return nil, errors.New("remote MCP principal database is unavailable")
		}
		subjectBindings, err = remoteMCPSubjectBindings(context.Background(), cfg.RemoteMCPSubjectBindingsJSON, principalDatabase)
		if err != nil {
			return nil, err
		}
	}
	var principalActive mcphttp.PrincipalActive
	if cfg.RemoteMCPTokenValidationEnabled {
		principalActive = principalDatabase.RemoteMCPPrincipalActive
	}
	return mcphttp.New(cfg.RemoteMCPResourceURL, strings.Split(cfg.RemoteMCPAuthorizationServers, ","), validator, subjectBindings, principalActive)
}

func remoteMCPSubjectBindings(ctx context.Context, raw string, database remoteMCPPrincipalDatabase) (map[string]string, error) {
	var bindings []struct {
		Subject     string `json:"subject"`
		PrincipalID string `json:"principal_id"`
	}
	if json.Unmarshal([]byte(raw), &bindings) != nil || len(bindings) == 0 {
		return nil, errors.New("remote MCP subject bindings are invalid")
	}
	result := make(map[string]string, len(bindings))
	for _, binding := range bindings {
		if binding.Subject == "" || binding.PrincipalID == "" || result[binding.Subject] != "" {
			return nil, errors.New("remote MCP subject bindings are invalid")
		}
		active, err := database.RemoteMCPPrincipalActive(ctx, binding.PrincipalID)
		if err != nil || !active {
			return nil, errors.New("remote MCP subject binding principal is unavailable")
		}
		result[binding.Subject] = binding.PrincipalID
	}
	return result, nil
}

func buildMemoryHandler(cfg config.Config, platformDB platformDatabase) (http.Handler, error) {
	if err := validateEmbeddingProvider(cfg); err != nil {
		return nil, err
	}
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
	if cfg.MemoryOpenAIEmbeddingsURL == "" {
		return memoryhttp.New(database, policy, cfg.MemoryMutationsEnabled), nil
	}
	key, err := readEmbeddingAPIKey(cfg.MemoryOpenAIAPIKeyFile)
	if err != nil {
		return nil, errors.New("memory embedding provider credential is unavailable")
	}
	provider, err := embeddingprovider.NewOpenAICompatible(cfg.MemoryOpenAIEmbeddingsURL, key, &http.Client{})
	if err != nil {
		return nil, errors.New("memory embedding provider is unavailable")
	}
	hybrid, err := punaropostgres.NewMemoryHybridRetrievalExecutor(database, provider)
	if err != nil {
		return nil, errors.New("memory hybrid retrieval is unavailable")
	}
	return memoryhttp.NewWithHybrid(database, policy, cfg.MemoryMutationsEnabled, hybrid), nil
}

func buildEmbeddingRuntime(cfg config.Config, platformDB platformDatabase) (*embeddingRuntime, error) {
	if cfg.MemoryOpenAIEmbeddingsURL == "" {
		return nil, nil
	}
	database, ok := platformDB.(embeddingRuntimeDatabase)
	if !ok {
		return nil, errors.New("PostgreSQL embedding database authority is unavailable")
	}
	readinessCtx, readinessCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer readinessCancel()
	if err := database.CanonicalBrainRuntimeReady(readinessCtx); err != nil {
		return nil, errors.New("PostgreSQL canonical brain schema is unavailable")
	}
	key, err := readEmbeddingAPIKey(cfg.MemoryOpenAIAPIKeyFile)
	if err != nil {
		return nil, errors.New("memory embedding provider credential is unavailable")
	}
	provider, err := embeddingprovider.NewOpenAICompatible(cfg.MemoryOpenAIEmbeddingsURL, key, &http.Client{})
	if err != nil {
		return nil, errors.New("memory embedding provider is unavailable")
	}
	executor, err := punaropostgres.NewMemoryEmbeddingExecutor(database, database, provider)
	if err != nil {
		return nil, errors.New("memory embedding executor is unavailable")
	}
	return newEmbeddingRuntime(executor, uuid.NewString(), time.Minute), nil
}

func validateEmbeddingProvider(cfg config.Config) error {
	if cfg.MemoryOpenAIEmbeddingsURL == "" {
		return nil
	}
	key, err := readEmbeddingAPIKey(cfg.MemoryOpenAIAPIKeyFile)
	if err != nil {
		return errors.New("memory embedding provider credential is unavailable")
	}
	if _, err := embeddingprovider.NewOpenAICompatible(cfg.MemoryOpenAIEmbeddingsURL, key, &http.Client{}); err != nil {
		return errors.New("memory embedding provider is unavailable")
	}
	return nil
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
	if setter, ok := backend.(interface {
		SetRateLimits(relay.RateLimitConfig) error
	}); ok {
		limits := cfg.RelayRateLimits()
		if limits == (relay.RateLimitConfig{}) {
			limits = relay.DefaultRateLimitConfig()
		}
		if err := setter.SetRateLimits(limits); err != nil {
			if store != nil {
				_ = store.Close()
			}
			return nil, nil, err
		}
	}
	if setter, ok := backend.(interface {
		SetQuotaLimits(relay.QuotaConfig) error
	}); ok {
		limits := cfg.RelayQuotaLimits()
		if limits == (relay.QuotaConfig{}) {
			limits = relay.DefaultQuotaConfig()
		}
		if err := setter.SetQuotaLimits(limits); err != nil {
			if store != nil {
				_ = store.Close()
			}
			return nil, nil, err
		}
	}
	if setter, ok := backend.(interface {
		SetRetentionPolicy(relay.RetentionConfig) error
	}); ok {
		policy := cfg.RelayRetentionPolicy()
		if policy == (relay.RetentionConfig{}) {
			policy = relay.DefaultRetentionConfig()
		}
		if err := setter.SetRetentionPolicy(policy); err != nil {
			if store != nil {
				_ = store.Close()
			}
			return nil, nil, err
		}
	}
	metrics := &relay.Metrics{}
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
	handler := relay.NewHandler(backend, authenticator, relay.HandlerOptions{Metrics: metrics})
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
	return relayMetricsHandler{Handler: handler, metrics: metrics}, store, nil
}

type relayMetricsHandler struct {
	http.Handler
	metrics *relay.Metrics
}

func (h relayMetricsHandler) MetricsSnapshot() relay.MetricsSnapshot {
	return h.metrics.Snapshot()
}

type deliveryMaintainer interface {
	MaintainDeliveries(time.Time) (relay.MaintenanceResult, error)
}

func startDeliveryMaintenance(store *relay.Store, postgresRelay relay.Backend) func() {
	var maintainer deliveryMaintainer
	if store != nil {
		maintainer = store
	} else if postgres, ok := postgresRelay.(deliveryMaintainer); ok {
		maintainer = postgres
	}
	if maintainer == nil {
		return nil
	}
	// #nosec G118 -- the returned stop function owns and invokes cancel.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(deliveryMaintenanceInterval)
		defer ticker.Stop()
		_, _ = maintainer.MaintainDeliveries(time.Now().UTC())
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, _ = maintainer.MaintainDeliveries(time.Now().UTC())
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
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
