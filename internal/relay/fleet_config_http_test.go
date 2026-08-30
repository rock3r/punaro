package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type memoryFleetStore struct {
	mu       sync.Mutex
	desired  FleetDesiredMetadata
	archives map[string][]byte
	status   map[string]FleetStatusReport
	keys     map[string]string
}

func (store *memoryFleetStore) FleetDesired(context.Context) (FleetDesiredMetadata, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.desired, nil
}

func (store *memoryFleetStore) FleetRelease(_ context.Context, digest string) ([]byte, error) {
	archive, ok := store.archives[digest]
	if !ok {
		return nil, errors.New("missing")
	}
	return archive, nil
}

func (store *memoryFleetStore) PutFleetStatus(_ context.Context, machineID string, report FleetStatusReport) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.status == nil {
		store.status = map[string]FleetStatusReport{}
		store.keys = map[string]string{}
	}
	key := machineID + "\x00" + report.IdempotencyKey
	if previous, ok := store.keys[key]; ok {
		if previous != report.RequestHash {
			return errors.New("idempotency conflict")
		}
		return nil
	}
	if current, ok := store.status[machineID]; ok && current.ReportGeneration >= report.ReportGeneration {
		return errors.New("stale generation")
	}
	store.status[machineID] = report
	store.keys[key] = report.RequestHash
	return nil
}

func TestHTTPFleetConfigRequiresEnrolledIdentityAndOmitsContents(t *testing.T) {
	t.Parallel()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	auth, err := NewAuthenticator(store, []Machine{{ID: "machine-a", PublicKey: public, EndpointPrefixes: []string{"agent/a/"}}})
	if err != nil {
		t.Fatal(err)
	}
	digest := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	fleet := &memoryFleetStore{
		desired:  FleetDesiredMetadata{Generation: 3, Digest: digest, SourceCommit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SkillCount: 1, TotalBytes: 12},
		archives: map[string][]byte{digest: []byte("archive-bytes")},
	}
	clock := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	handler := NewHandler(store, auth, HandlerOptions{Now: func() time.Time { return clock }, FleetConfig: fleet})
	unsigned := serveUnsigned(t, handler, http.MethodGet, "/v1/fleet-config/desired", "")
	if unsigned.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned status=%d body=%s", unsigned.Code, unsigned.Body.String())
	}
	desired := serveSigned(t, handler, private, "machine-a", http.MethodGet, "/v1/fleet-config/desired", "", "desired", "")
	if desired.Code != http.StatusOK {
		t.Fatalf("desired status=%d body=%s", desired.Code, desired.Body.String())
	}
	body := desired.Body.String()
	if !strings.Contains(body, digest) || !strings.Contains(body, `"generation":3`) || strings.Contains(body, "archive-bytes") || strings.Contains(body, "# fleet") {
		t.Fatalf("desired leaked or missing metadata: %s", body)
	}
	fetched := serveSigned(t, handler, private, "machine-a", http.MethodGet, "/v1/fleet-config/releases/"+digest, "", "fetch", "")
	if fetched.Code != http.StatusOK || fetched.Body.String() != "archive-bytes" {
		t.Fatalf("fetch status=%d body=%s", fetched.Code, fetched.Body.String())
	}
	publish := serveSigned(t, handler, private, "machine-a", http.MethodPost, "/v1/fleet-config/publish", `{}`, "publish", "pub-1")
	if publish.Code != http.StatusNotFound {
		t.Fatalf("client publish status=%d body=%s", publish.Code, publish.Body.String())
	}
}

func TestHTTPFleetConfigStatusIsBoundedIdempotentAndRejectsStaleGeneration(t *testing.T) {
	t.Parallel()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPublic, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	auth, err := NewAuthenticator(store, []Machine{
		{ID: "machine-a", PublicKey: public, EndpointPrefixes: []string{"agent/a/"}},
		{ID: "machine-b", PublicKey: otherPublic, EndpointPrefixes: []string{"agent/b/"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	fleet := &memoryFleetStore{desired: FleetDesiredMetadata{Generation: 1, Digest: strings.Repeat("ab", 32)}}
	clock := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	handler := NewHandler(store, auth, HandlerOptions{Now: func() time.Time { return clock }, FleetConfig: fleet})
	payload := `{"generation":1,"applied_digest":"` + strings.Repeat("ab", 32) + `","state":"current","activation":"next_turn","trailer_state":"present","alias_state":"disabled","project_match_state":"matched","report_generation":2}`
	first := serveSigned(t, handler, private, "machine-a", http.MethodPut, "/v1/fleet-config/status", payload, "status-1", "key-1")
	if first.Code != http.StatusOK {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	retry := serveSigned(t, handler, private, "machine-a", http.MethodPut, "/v1/fleet-config/status", payload, "status-2", "key-1")
	if retry.Code != http.StatusOK {
		t.Fatalf("retry status=%d body=%s", retry.Code, retry.Body.String())
	}
	conflict := serveSigned(t, handler, private, "machine-a", http.MethodPut, "/v1/fleet-config/status", `{"generation":1,"state":"failed","report_generation":2}`, "status-3", "key-1")
	if conflict.Code != http.StatusConflict {
		t.Fatalf("conflict status=%d body=%s", conflict.Code, conflict.Body.String())
	}
	stale := serveSigned(t, handler, private, "machine-a", http.MethodPut, "/v1/fleet-config/status", `{"generation":1,"state":"pending","report_generation":1}`, "status-4", "key-2")
	if stale.Code != http.StatusConflict {
		t.Fatalf("stale status=%d body=%s", stale.Code, stale.Body.String())
	}
	other := serveSigned(t, handler, otherPrivate, "machine-b", http.MethodPut, "/v1/fleet-config/status", `{"generation":1,"state":"pending","report_generation":1}`, "status-b", "key-b")
	if other.Code != http.StatusOK {
		t.Fatalf("other machine status=%d body=%s", other.Code, other.Body.String())
	}
	if len(fleet.status) != 2 || fleet.status["machine-a"].State != "current" || fleet.status["machine-b"].State != "pending" {
		t.Fatalf("rows=%#v", fleet.status)
	}
	activation := serveSigned(t, handler, private, "machine-a", http.MethodPut, "/v1/fleet-config/status", `{"generation":1,"applied_digest":"`+strings.Repeat("ab", 32)+`","state":"current","activation":"next_session","trailer_state":"present","alias_state":"disabled","project_match_state":"matched","report_generation":2}`, "status-activation", "key-1")
	if activation.Code != http.StatusConflict {
		t.Fatalf("activation reuse status=%d body=%s", activation.Code, activation.Body.String())
	}
}

func TestFleetStatusRequestHashIncludesOptionalFields(t *testing.T) {
	t.Parallel()
	base := FleetStatusReport{Generation: 1, AppliedDigest: strings.Repeat("ab", 32), State: "current", ReportGeneration: 2}
	changed := base
	changed.Activation = "next_turn"
	changed.TrailerState = "present"
	changed.AliasState = "linked"
	changed.ProjectMatchState = "matched"
	if fleetStatusRequestHash("machine-a", base) == fleetStatusRequestHash("machine-a", changed) {
		t.Fatal("optional status fields omitted from idempotency hash")
	}
}

func TestHTTPFleetConfigRejectsUnknownMachineAndClientPublish(t *testing.T) {
	t.Parallel()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	auth, err := NewAuthenticator(store, []Machine{{ID: "machine-a", PublicKey: public, EndpointPrefixes: []string{"agent/a/"}}})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(store, auth, HandlerOptions{Now: func() time.Time {
		return time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	}, FleetConfig: &memoryFleetStore{}})
	revoked := serveSigned(t, handler, private, "machine-revoked", http.MethodGet, "/v1/fleet-config/desired", "", "revoked", "")
	if revoked.Code != http.StatusUnauthorized {
		t.Fatalf("revoked status=%d body=%s", revoked.Code, revoked.Body.String())
	}
}

func TestWatchFleetDesiredBroadcastsGenerationAdvance(t *testing.T) {
	t.Parallel()
	store := &memoryFleetStore{desired: FleetDesiredMetadata{Generation: 2, Digest: strings.Repeat("ab", 32)}}
	notifier := NewNotifier()
	client := notifier.Register("machine-a")
	t.Cleanup(client.Close)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go WatchFleetDesired(ctx, store, notifier, 20*time.Millisecond)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		select {
		case event := <-client.Events():
			if event.TopicID == FleetConfigTopic && event.Sequence == 2 {
				store.mu.Lock()
				store.desired.Generation = 5
				store.mu.Unlock()
				goto advanced
			}
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
	t.Fatal("initial generation was not broadcast")
advanced:
	select {
	case event := <-client.Events():
		if event.TopicID != FleetConfigTopic || event.Sequence != 5 {
			t.Fatalf("event=%#v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("advanced generation was not broadcast")
	}
}

func TestBroadcastFleetWakeUsesReservedTopic(t *testing.T) {
	t.Parallel()
	notifier := NewNotifier()
	client := notifier.Register("machine-a")
	t.Cleanup(client.Close)
	if next := BroadcastFleetWake(notifier, 2, 2); next != 2 {
		t.Fatalf("unchanged generation=%d", next)
	}
	select {
	case event := <-client.Events():
		t.Fatalf("unexpected wake %#v", event)
	default:
	}
	if next := BroadcastFleetWake(notifier, 2, 4); next != 4 {
		t.Fatalf("broadcast generation=%d", next)
	}
	event := <-client.Events()
	if event.TopicID != FleetConfigTopic || event.Sequence != 4 || event.Type != "wake" {
		t.Fatalf("event=%#v", event)
	}
}

func serveUnsigned(t *testing.T, handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequestWithContext(context.Background(), method, path, bytes.NewBufferString(body))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
