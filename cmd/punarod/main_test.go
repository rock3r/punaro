package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rock3r/punaro/internal/config"
	punaropostgres "github.com/rock3r/punaro/internal/postgres"
	"github.com/rock3r/punaro/internal/trustedattachment"
)

func TestRunFailsClosedBeforeStartingAttachmentRuntime(t *testing.T) {
	t.Setenv("PUNARO_ATTACHMENTS_ENABLED", "true")
	var stderr bytes.Buffer
	if code := run(nil, &stderr); code != 2 {
		t.Fatalf("run exit code = %d, want 2; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "retired") {
		t.Fatalf("stderr = %q, want fail-closed explanation", stderr.String())
	}
}

func TestProductionRoutesOmitRetiredAttachments(t *testing.T) {
	mux := http.NewServeMux()
	memory := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusAccepted)
	})
	trusted := &trustedAttachmentRuntime{handler: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	})}
	registerProductionRoutes(mux, memory, trusted, nil)
	for _, path := range []string{"/v2/directory", "/v2/permits", "/v3/permits", "/v3/attachments/example"} {
		request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("retired route %s status=%d", path, response.Code)
		}
	}
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/trusted-attachments", nil)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("trusted attachment route status=%d", response.Code)
	}
	request = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/projects/resolve", nil)
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("memory route status=%d", response.Code)
	}
}

func TestBuildMemoryHandlerIsDarkByDefaultAndRequiresCompleteAuthority(t *testing.T) {
	handler, err := buildMemoryHandler(config.Config{}, &refusingPlatformDatabase{})
	if err != nil || handler != nil {
		t.Fatalf("disabled handler=%v err=%v", handler, err)
	}
	_, err = buildMemoryHandler(config.Config{MemoryAPIEnabled: true, IngressMode: "internet", ListenAddr: "127.0.0.1:8080", PublicURL: "https://punaro.example"}, &refusingPlatformDatabase{})
	if err == nil || !strings.Contains(err.Error(), "memory database authority") {
		t.Fatalf("enabled incomplete authority error=%v", err)
	}
}

type unavailableMemoryDatabase struct {
	deviceDatabase
	readyCalled bool
}

func (*unavailableMemoryDatabase) Ready(context.Context) error { return nil }
func (*unavailableMemoryDatabase) Close() error                { return nil }
func (database *unavailableMemoryDatabase) CanonicalBrainRuntimeReady(context.Context) error {
	database.readyCalled = true
	return errors.New("schema 14 is unavailable")
}
func (*unavailableMemoryDatabase) ResolveProjectIdentity(context.Context, string, punaropostgres.ProjectIdentityKind, string) (punaropostgres.ProjectIdentityResolution, error) {
	return punaropostgres.ProjectIdentityResolution{}, errors.New("unused")
}
func (*unavailableMemoryDatabase) GetMemory(context.Context, string, string, string) (punaropostgres.MemoryItem, error) {
	return punaropostgres.MemoryItem{}, errors.New("unused")
}
func (*unavailableMemoryDatabase) GetMemoryProposal(context.Context, string, string, string) (punaropostgres.MemoryProposal, error) {
	return punaropostgres.MemoryProposal{}, errors.New("unused")
}
func (*unavailableMemoryDatabase) SearchMemory(context.Context, punaropostgres.MemorySearchRequest) (punaropostgres.MemorySearchPage, error) {
	return punaropostgres.MemorySearchPage{}, errors.New("unused")
}
func (*unavailableMemoryDatabase) BuildMemoryPromptBrief(context.Context, punaropostgres.MemoryPromptBriefRequest) (punaropostgres.MemoryPromptBrief, error) {
	return punaropostgres.MemoryPromptBrief{}, errors.New("unused")
}
func (*unavailableMemoryDatabase) FetchMemoryChanges(context.Context, punaropostgres.MemoryChangeRequest) (punaropostgres.MemoryChangePage, error) {
	return punaropostgres.MemoryChangePage{}, errors.New("unused")
}

func TestBuildMemoryHandlerRejectsCompatibleHistoricalSchema(t *testing.T) {
	database := &unavailableMemoryDatabase{}
	_, err := buildMemoryHandler(config.Config{MemoryAPIEnabled: true, IngressMode: "internet", ListenAddr: "127.0.0.1:8080", PublicURL: "https://punaro.example"}, database)
	if err == nil || !database.readyCalled || !strings.Contains(err.Error(), "schema is unavailable") {
		t.Fatalf("ready=%t error=%v", database.readyCalled, err)
	}
}

func TestProductionRoutesKeepMemoryAPIDarkWhenHandlerIsAbsent(t *testing.T) {
	mux := http.NewServeMux()
	registerProductionRoutes(mux, nil, nil, nil)
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/projects/resolve", nil)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("dark memory route status=%d", response.Code)
	}
}

type refusingPlatformDatabase struct {
	readyCalled bool
	closed      bool
}

func (d *refusingPlatformDatabase) Ready(context.Context) error {
	d.readyCalled = true
	return errors.New("PostgreSQL schema is incompatible")
}

func (d *refusingPlatformDatabase) Close() error {
	d.closed = true
	return nil
}

func TestRunRejectsIncompatiblePostgresWithoutStartingServer(t *testing.T) {
	original := openPlatformDatabase
	t.Cleanup(func() { openPlatformDatabase = original })
	database := &refusingPlatformDatabase{}
	openPlatformDatabase = func(_ context.Context, cfg punaropostgres.Config) (platformDatabase, error) {
		if cfg.DSNFile != "/run/secrets/punaro-app-dsn" {
			t.Fatalf("DSN file=%q", cfg.DSNFile)
		}
		return database, nil
	}
	t.Setenv("PUNARO_POSTGRES_ENABLED", "true")
	t.Setenv("PUNARO_POSTGRES_DSN_FILE", "/run/secrets/punaro-app-dsn")
	var stderr bytes.Buffer
	if code := run(nil, &stderr); code != 2 {
		t.Fatalf("run()=%d stderr=%q", code, stderr.String())
	}
	if !database.readyCalled || !database.closed || !strings.Contains(stderr.String(), "readiness error") {
		t.Fatalf("ready=%t closed=%t stderr=%q", database.readyCalled, database.closed, stderr.String())
	}
}

func TestBuildTrustedAttachmentHandlerRequiresCompleteDatabaseAuthority(t *testing.T) {
	root := filepath.Join(t.TempDir(), "blobs")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := buildTrustedAttachmentHandler(config.Config{TrustedAttachmentsEnabled: true, TrustedAttachmentBlobDir: root, IngressMode: "internet", ListenAddr: "127.0.0.1:8080", PublicURL: "https://punaro.example"}, &refusingPlatformDatabase{})
	if err == nil || !strings.Contains(err.Error(), "database authority") {
		t.Fatalf("error=%v", err)
	}
}

type unavailableTrustedAttachmentDatabase struct {
	deviceDatabase
	trustedattachment.Repository
	readyCalled bool
}

func (database *unavailableTrustedAttachmentDatabase) Ready(context.Context) error { return nil }
func (database *unavailableTrustedAttachmentDatabase) Close() error                { return nil }
func (database *unavailableTrustedAttachmentDatabase) TrustedAttachmentRuntimeReady(context.Context) error {
	database.readyCalled = true
	return errors.New("schema 13 is unavailable")
}
func (*unavailableTrustedAttachmentDatabase) ReserveAttachment(context.Context, punaropostgres.AttachmentReservationRequest) (punaropostgres.AttachmentReservation, error) {
	return punaropostgres.AttachmentReservation{}, errors.New("unused")
}

func TestBuildTrustedAttachmentHandlerRejectsCompatibleHistoricalSchema(t *testing.T) {
	root := filepath.Join(t.TempDir(), "blobs")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	database := &unavailableTrustedAttachmentDatabase{}
	_, err := buildTrustedAttachmentHandler(config.Config{TrustedAttachmentsEnabled: true, TrustedAttachmentBlobDir: root, IngressMode: "internet", ListenAddr: "127.0.0.1:8080", PublicURL: "https://punaro.example"}, database)
	if err == nil || !database.readyCalled || !strings.Contains(err.Error(), "schema is unavailable") {
		t.Fatalf("ready=%t error=%v", database.readyCalled, err)
	}
}

func TestConfiguredServerKeepsShortGlobalTimeoutsForMailAndDeviceRoutes(t *testing.T) {
	server := configuredServer("127.0.0.1:8080", http.NotFoundHandler())
	if server.ReadHeaderTimeout != 5*time.Second || server.ReadTimeout != 15*time.Second || server.WriteTimeout != 15*time.Second || server.IdleTimeout != time.Minute || server.MaxHeaderBytes != 16<<10 {
		t.Fatalf("server=%#v", server)
	}
}

type scriptedAttachmentReconciler struct {
	mu          sync.Mutex
	reconcile   []trustedattachment.ReconcileResult
	gc          []trustedattachment.GarbageCollectResult
	orphans     []trustedattachment.OrphanReconcileResult
	reconcileAt int
	gcAt        int
	orphanAt    int
}

func (reconciler *scriptedAttachmentReconciler) ReconcileBatch(context.Context, punaropostgres.AttachmentReconcileCursor, int) (trustedattachment.ReconcileResult, error) {
	reconciler.mu.Lock()
	defer reconciler.mu.Unlock()
	result := reconciler.reconcile[reconciler.reconcileAt]
	reconciler.reconcileAt++
	return result, nil
}

func (reconciler *scriptedAttachmentReconciler) ReconcileOrphanBatch(context.Context, string, int, time.Duration) (trustedattachment.OrphanReconcileResult, error) {
	reconciler.mu.Lock()
	defer reconciler.mu.Unlock()
	result := reconciler.orphans[reconciler.orphanAt]
	reconciler.orphanAt++
	return result, nil
}

func (reconciler *scriptedAttachmentReconciler) GarbageCollectBatch(context.Context, string, int, time.Duration) (trustedattachment.GarbageCollectResult, error) {
	reconciler.mu.Lock()
	defer reconciler.mu.Unlock()
	result := reconciler.gc[reconciler.gcAt]
	reconciler.gcAt++
	return result, nil
}

func TestTrustedAttachmentReconciliationRestartsChangedPagesAndFinishesBothNamespaces(t *testing.T) {
	reconciler := &scriptedAttachmentReconciler{
		reconcile: []trustedattachment.ReconcileResult{{Scanned: 100, Changed: 1}, {Scanned: 100, Next: punaropostgres.AttachmentReconcileCursor{ArtifactID: "11111111-1111-4111-8111-111111111111"}}, {Scanned: 2}},
		gc:        []trustedattachment.GarbageCollectResult{{Scanned: 100, Changed: 1}, {Scanned: 1}},
		orphans:   []trustedattachment.OrphanReconcileResult{{Scanned: 100, Changed: 1}, {Scanned: 1}},
	}
	if err := reconcileTrustedAttachments(context.Background(), reconciler); err != nil {
		t.Fatal(err)
	}
	if reconciler.reconcileAt != 3 || reconciler.gcAt != 2 || reconciler.orphanAt != 2 {
		t.Fatalf("reconcile calls=%d GC calls=%d orphan calls=%d", reconciler.reconcileAt, reconciler.gcAt, reconciler.orphanAt)
	}
}

type changeBoundAttachmentReconciler struct{ stage string }

func (reconciler changeBoundAttachmentReconciler) ReconcileBatch(context.Context, punaropostgres.AttachmentReconcileCursor, int) (trustedattachment.ReconcileResult, error) {
	if reconciler.stage == "database" {
		return trustedattachment.ReconcileResult{Scanned: trustedReconcileBatch, Changed: 1}, nil
	}
	return trustedattachment.ReconcileResult{}, nil
}

func (reconciler changeBoundAttachmentReconciler) GarbageCollectBatch(context.Context, string, int, time.Duration) (trustedattachment.GarbageCollectResult, error) {
	if reconciler.stage == "deletion" {
		return trustedattachment.GarbageCollectResult{Scanned: trustedReconcileBatch, Changed: 1}, nil
	}
	return trustedattachment.GarbageCollectResult{}, nil
}

func (reconciler changeBoundAttachmentReconciler) ReconcileOrphanBatch(context.Context, string, int, time.Duration) (trustedattachment.OrphanReconcileResult, error) {
	if reconciler.stage == "filesystem" {
		return trustedattachment.OrphanReconcileResult{Scanned: trustedReconcileBatch, Changed: 1}, nil
	}
	return trustedattachment.OrphanReconcileResult{}, nil
}

func TestTrustedAttachmentReconciliationFailsClosedAfterChangeRestartBound(t *testing.T) {
	for _, stage := range []string{"database", "deletion", "filesystem"} {
		t.Run(stage, func(t *testing.T) {
			err := reconcileTrustedAttachments(context.Background(), changeBoundAttachmentReconciler{stage: stage})
			if err == nil || !strings.Contains(err.Error(), stage) {
				t.Fatalf("error=%v, want %s bound", err, stage)
			}
		})
	}
}

func TestRunDoesNotServePublicSocketWhenHealthBindFails(t *testing.T) {
	originalListen := listenTCP
	t.Cleanup(func() { listenTCP = originalListen })
	tracked := &trackingListener{}
	calls := 0
	listenTCP = func(string, string) (net.Listener, error) {
		calls++
		if calls == 1 {
			return tracked, nil
		}
		return nil, errors.New("health address occupied")
	}
	t.Setenv("PUNARO_LISTEN_ADDR", "127.0.0.1:18080")
	t.Setenv("PUNARO_HEALTH_LISTEN_ADDR", "127.0.0.1:18081")
	var stderr bytes.Buffer
	if code := run(nil, &stderr); code != 1 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if tracked.acceptCalled {
		t.Fatal("public server began accepting before the health bind succeeded")
	}
	if !tracked.closed {
		t.Fatal("public listener remained open after the health bind failed")
	}
}

type trackingListener struct {
	acceptCalled bool
	closed       bool
}

func (l *trackingListener) Accept() (net.Conn, error) {
	l.acceptCalled = true
	return nil, errors.New("unexpected Accept call")
}

func (l *trackingListener) Close() error { l.closed = true; return nil }
func (*trackingListener) Addr() net.Addr { return testAddr("127.0.0.1:18080") }

type testAddr string

func (testAddr) Network() string  { return "tcp" }
func (a testAddr) String() string { return string(a) }

func TestShutdownHTTPServersStartsAllDrainsConcurrently(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	servers := []httpShutdowner{
		blockingShutdowner{started: started, release: release},
		blockingShutdowner{started: started, release: release},
	}
	result := make(chan error, 1)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	go func() { result <- shutdownHTTPServers(ctx, servers...) }()
	for range 2 {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("both server drains did not start under the shared deadline")
		}
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

type blockingShutdowner struct {
	started chan<- struct{}
	release <-chan struct{}
}

func (s blockingShutdowner) Shutdown(ctx context.Context) error {
	s.started <- struct{}{}
	select {
	case <-s.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
