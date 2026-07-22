package memoryhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rock3r/punaro/internal/ingress"
	"github.com/rock3r/punaro/internal/postgres"
)

const (
	testPrincipalID = "11111111-1111-4111-8111-111111111111"
	testLookupID    = "22222222-2222-4222-8222-222222222222"
	testProjectID   = "33333333-3333-4333-8333-333333333333"
	testItemID      = "44444444-4444-4444-8444-444444444444"
	testProposalID  = "55555555-5555-4555-8555-555555555555"
	testIdentityID  = "66666666-6666-4666-8666-666666666666"
	testInstallID   = "77777777-7777-4777-8777-777777777777"
	testTimelineID  = "88888888-8888-4888-8888-888888888888"
)

type fakeStore struct {
	mu sync.Mutex

	device  postgres.AuthenticatedDevice
	authErr error
	err     error

	credential string
	principal  string
	project    string
	item       string
	proposal   string
	query      string
	limit      int
	cursor     postgres.InstallationState
	kind       postgres.ProjectIdentityKind
	locator    string

	block   chan struct{}
	entered chan struct{}
}

func newFakeStore() *fakeStore {
	return &fakeStore{device: postgres.AuthenticatedDevice{PrincipalID: testPrincipalID, LookupID: testLookupID, Generation: 3}}
}

func (s *fakeStore) AuthenticateDevice(_ context.Context, credential string) (postgres.AuthenticatedDevice, error) {
	s.mu.Lock()
	s.credential = credential
	s.mu.Unlock()
	return s.device, s.authErr
}

func (s *fakeStore) wait(ctx context.Context) error {
	if s.entered != nil {
		s.entered <- struct{}{}
	}
	if s.block == nil {
		return s.err
	}
	select {
	case <-s.block:
		return s.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *fakeStore) ResolveProjectIdentity(ctx context.Context, principal string, kind postgres.ProjectIdentityKind, locator string) (postgres.ProjectIdentityResolution, error) {
	s.mu.Lock()
	s.principal, s.kind, s.locator = principal, kind, locator
	s.mu.Unlock()
	if err := s.wait(ctx); err != nil {
		return postgres.ProjectIdentityResolution{}, err
	}
	return postgres.ProjectIdentityResolution{IdentityID: testIdentityID, ProjectID: testProjectID, Kind: kind}, nil
}

func (s *fakeStore) GetMemory(ctx context.Context, principal, project, item string) (postgres.MemoryItem, error) {
	s.mu.Lock()
	s.principal, s.project, s.item = principal, project, item
	s.mu.Unlock()
	if err := s.wait(ctx); err != nil {
		return postgres.MemoryItem{}, err
	}
	return postgres.MemoryItem{ItemID: item, ProjectID: project, ScopeID: testIdentityID, Kind: "decision", State: postgres.MemoryActive, Trust: "curated", Layer: postgres.MemoryLayerCurated, Revision: 2, ETag: `"memory:2"`, Document: json.RawMessage(`{"title":"Decision"}`), ContentSHA256: strings.Repeat("a", 64), AuthorID: principal, ChangeSequence: 9}, nil
}

func (s *fakeStore) GetMemoryProposal(ctx context.Context, principal, project, proposal string) (postgres.MemoryProposal, error) {
	s.mu.Lock()
	s.principal, s.project, s.proposal = principal, project, proposal
	s.mu.Unlock()
	if err := s.wait(ctx); err != nil {
		return postgres.MemoryProposal{}, err
	}
	return postgres.MemoryProposal{ProposalID: proposal, ProjectID: project, ScopeID: testIdentityID, Action: postgres.MemoryProposalCreate, State: postgres.MemoryProposalPending, ETag: `"proposal:1"`, ProposedBy: principal, Steps: []postgres.MemoryProposalStep{}, Evidence: []postgres.MemoryProposalEvidence{}}, nil
}

func (s *fakeStore) SearchMemory(ctx context.Context, request postgres.MemorySearchRequest) (postgres.MemorySearchPage, error) {
	s.mu.Lock()
	s.principal, s.project, s.query, s.limit = request.PrincipalID, request.ProjectID, request.Query, request.Limit
	s.mu.Unlock()
	if err := s.wait(ctx); err != nil {
		return postgres.MemorySearchPage{}, err
	}
	return postgres.MemorySearchPage{Results: []postgres.MemorySearchResult{{ItemID: testItemID, Revision: 2, ETag: `"memory:2"`, Kind: "decision", Trust: "curated", Layer: postgres.MemoryLayerCurated, Title: "Decision", Summary: "Bounded summary", Match: postgres.MemorySearchMatchLexical}}}, nil
}

func (s *fakeStore) BuildMemoryPromptBrief(ctx context.Context, request postgres.MemoryPromptBriefRequest) (postgres.MemoryPromptBrief, error) {
	s.mu.Lock()
	s.principal, s.project, s.query = request.PrincipalID, request.ProjectID, request.Query
	s.mu.Unlock()
	if err := s.wait(ctx); err != nil {
		return postgres.MemoryPromptBrief{}, err
	}
	return postgres.MemoryPromptBrief{Cursor: postgres.MemoryPromptBriefCursor{InstallationID: testInstallID, TimelineID: testTimelineID, ChangeSequence: 9}, ProjectID: testProjectID, RetrievalMode: postgres.MemoryPromptBriefRetrievalLexical, SemanticStatus: postgres.MemoryPromptBriefSemanticNotConfigured, BudgetVersion: "prompt-brief-v1", Entries: []postgres.MemoryPromptBriefEntry{}, Context: `{"entries":[]}`}, nil
}

func (s *fakeStore) FetchMemoryChanges(ctx context.Context, request postgres.MemoryChangeRequest) (postgres.MemoryChangePage, error) {
	s.mu.Lock()
	s.principal, s.project, s.limit, s.cursor = request.PrincipalID, request.ProjectID, request.Limit, request.Cursor
	s.mu.Unlock()
	if err := s.wait(ctx); err != nil {
		return postgres.MemoryChangePage{}, err
	}
	return postgres.MemoryChangePage{Changes: []postgres.MemoryChange{{TimelineID: testTimelineID, ChangeSequence: 9, ScopeID: testIdentityID, ItemID: testItemID, Type: postgres.MemoryChangeUpdate, Revision: 2}}, Cursor: postgres.InstallationState{InstallationID: testInstallID, TimelineID: testTimelineID, ChangeSequence: 9}}, nil
}

func newTestHandler(store *fakeStore) http.Handler {
	policy := &ingress.Policy{Mode: ingress.LAN, ListenAddr: "127.0.0.1:8443", PublicURL: "https://punaro.test"}
	return New(store, policy)
}

func request(method, path, body string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), method, "https://punaro.test"+path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer device-credential")
	r.Header.Set("X-Forwarded-Proto", "https")
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	return r
}

func serve(t *testing.T, handler http.Handler, r *http.Request, wantStatus int) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != wantStatus {
		t.Fatalf("status=%d want=%d body=%s", w.Code, wantStatus, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control=%q", w.Header().Get("Cache-Control"))
	}
	return w
}

func TestHandlerBindsAuthenticatedPrincipalAcrossBoundedReadRoutes(t *testing.T) {
	store := newFakeStore()
	handler := newTestHandler(store)

	w := serve(t, handler, request(http.MethodPost, "/v1/projects/resolve", `{"kind":"git_remote","locator":"git@github.com:Owner/Repo.git"}`), http.StatusOK)
	if store.principal != testPrincipalID || store.kind != postgres.ProjectIdentityGitRemote || store.locator != "git@github.com:Owner/Repo.git" {
		t.Fatalf("resolve principal=%q kind=%q locator=%q", store.principal, store.kind, store.locator)
	}
	if !strings.Contains(w.Body.String(), `"project_id":"`+testProjectID+`"`) || strings.Contains(w.Body.String(), "ProjectID") || strings.Contains(w.Body.String(), "locator") {
		t.Fatalf("resolve response=%s", w.Body.String())
	}

	w = serve(t, handler, request(http.MethodGet, "/v1/projects/"+testProjectID+"/memories/"+testItemID, ""), http.StatusOK)
	if store.principal != testPrincipalID || store.project != testProjectID || store.item != testItemID || w.Header().Get("ETag") != `"memory:2"` || !strings.Contains(w.Body.String(), `"document":{"title":"Decision"}`) {
		t.Fatalf("get binding=%q/%q/%q headers=%v body=%s", store.principal, store.project, store.item, w.Header(), w.Body.String())
	}

	w = serve(t, handler, request(http.MethodPost, "/v1/projects/"+testProjectID+"/memories/search", `{"query":"needle","limit":3}`), http.StatusOK)
	if store.principal != testPrincipalID || store.query != "needle" || store.limit != 3 {
		t.Fatalf("search binding principal=%q query=%q limit=%d", store.principal, store.query, store.limit)
	}
	var search postgres.MemorySearchPage
	if err := json.Unmarshal(w.Body.Bytes(), &search); err != nil || len(search.Results) != 1 || search.Results[0].ItemID != testItemID || search.Results[0].Title != "Decision" || search.Results[0].Summary != "Bounded summary" || strings.Contains(w.Body.String(), "document") || search.More {
		t.Fatalf("search projection=%#v err=%v body=%s", search, err, w.Body.String())
	}

	w = serve(t, handler, request(http.MethodPost, "/v1/projects/"+testProjectID+"/memories/brief", `{"query":"needle"}`), http.StatusOK)
	if store.principal != testPrincipalID || store.query != "needle" {
		t.Fatalf("brief binding principal=%q query=%q", store.principal, store.query)
	}
	var brief postgres.MemoryPromptBrief
	if err := json.Unmarshal(w.Body.Bytes(), &brief); err != nil || brief.ProjectID != testProjectID || brief.Cursor.InstallationID != testInstallID || brief.Context != `{"entries":[]}` || len(brief.Entries) != 0 {
		t.Fatalf("brief projection=%#v err=%v body=%s", brief, err, w.Body.String())
	}

	changes := `{"cursor":{"installation_id":"` + testInstallID + `","timeline_id":"` + testTimelineID + `","change_sequence":8},"limit":10}`
	w = serve(t, handler, request(http.MethodPost, "/v1/projects/"+testProjectID+"/memories/changes", changes), http.StatusOK)
	if store.principal != testPrincipalID || store.cursor.InstallationID != testInstallID || store.cursor.TimelineID != testTimelineID || store.cursor.ChangeSequence != 8 || store.limit != 10 || strings.Contains(w.Body.String(), "InstallationID") || !strings.Contains(w.Body.String(), `"installation_id"`) {
		t.Fatalf("changes binding=%#v limit=%d body=%s", store.cursor, store.limit, w.Body.String())
	}
	serve(t, handler, request(http.MethodPost, "/v1/projects/"+testProjectID+"/memories/changes", `{"cursor":null,"limit":10}`), http.StatusOK)
	if store.cursor != (postgres.InstallationState{}) {
		t.Fatalf("initial changes cursor=%#v", store.cursor)
	}

	w = serve(t, handler, request(http.MethodGet, "/v1/projects/"+testProjectID+"/memory-proposals/"+testProposalID, ""), http.StatusOK)
	if store.principal != testPrincipalID || store.proposal != testProposalID || w.Header().Get("ETag") != `"proposal:1"` {
		t.Fatalf("proposal binding=%q/%q etag=%q", store.principal, store.proposal, w.Header().Get("ETag"))
	}
	var proposal map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &proposal); err != nil {
		t.Fatalf("proposal response err=%v body=%s", err, w.Body.String())
	}
	wantProposalFields := []string{"proposal_id", "scope_id", "project_id", "action", "state", "etag", "proposed_by", "created_at", "expires_at", "steps", "evidence"}
	if len(proposal) != len(wantProposalFields) {
		t.Fatalf("proposal fields=%v body=%s", proposal, w.Body.String())
	}
	for _, field := range wantProposalFields {
		if _, ok := proposal[field]; !ok {
			t.Fatalf("proposal missing %s: %s", field, w.Body.String())
		}
	}
}

func TestHandlerRejectsAuthenticationTransportAndStrictInputBeforeStore(t *testing.T) {
	store := newFakeStore()
	handler := newTestHandler(store)
	validPath := "/v1/projects/" + testProjectID + "/memories/search"

	missing := request(http.MethodPost, validPath, `{"query":"needle","limit":3}`)
	missing.Header.Del("Authorization")
	serve(t, handler, missing, http.StatusUnauthorized)
	duplicate := request(http.MethodPost, validPath, `{"query":"needle","limit":3}`)
	duplicate.Header["Authorization"] = []string{"Bearer one", "Bearer two"}
	serve(t, handler, duplicate, http.StatusUnauthorized)
	for _, authorization := range []string{"Basic token", "Bearer", "Bearer ", "Bearer two words", "Bearer\ttoken", "Bearertoken"} {
		malformed := request(http.MethodPost, validPath, `{"query":"needle","limit":3}`)
		malformed.Header.Set("Authorization", authorization)
		serve(t, handler, malformed, http.StatusUnauthorized)
	}
	plaintext := request(http.MethodPost, validPath, `{"query":"needle","limit":3}`)
	plaintext.URL.Scheme = "http"
	plaintext.TLS = nil
	plaintext.RemoteAddr = "203.0.113.1:12345"
	plaintext.Header.Del("X-Forwarded-Proto")
	serve(t, handler, plaintext, http.StatusForbidden)

	for _, body := range []string{
		`{"query":"needle","query":"other","limit":3}`,
		`{"query":"needle","limit":3,"unknown":true}`,
		`{"query":"needle","limit":3} trailing`,
		`{"query":"","limit":3}`,
	} {
		serve(t, handler, request(http.MethodPost, validPath, body), http.StatusBadRequest)
	}
	wrongType := request(http.MethodPost, validPath, `{"query":"needle","limit":3}`)
	wrongType.Header.Set("Content-Type", "text/plain")
	serve(t, handler, wrongType, http.StatusUnsupportedMediaType)
	withQuery := request(http.MethodGet, "/v1/projects/"+testProjectID+"/memories/"+testItemID+"?unexpected=1", "")
	serve(t, handler, withQuery, http.StatusBadRequest)
	serve(t, handler, request(http.MethodPut, "/v1/projects/resolve", ""), http.StatusMethodNotAllowed)
	serve(t, handler, request(http.MethodGet, "/v1/projects/not-a-project/memories/"+testItemID, ""), http.StatusBadRequest)
	oversized := request(http.MethodPost, validPath, `{"query":"`+strings.Repeat("a", maxRequestBytes)+`","limit":3}`)
	serve(t, handler, oversized, http.StatusRequestEntityTooLarge)
	badCursor := `{"cursor":{"installation_id":"` + testInstallID + `","timeline_id":"` + testTimelineID + `","timeline_id":"` + testTimelineID + `","change_sequence":0},"limit":10}`
	serve(t, handler, request(http.MethodPost, "/v1/projects/"+testProjectID+"/memories/changes", badCursor), http.StatusBadRequest)
	if store.principal != "" || store.query != "" || store.item != "" {
		t.Fatalf("rejected request reached store: %#v", store)
	}

	store.authErr = postgres.ErrUnauthenticated
	w := serve(t, handler, request(http.MethodGet, "/v1/projects/"+testProjectID+"/memories/"+testItemID, ""), http.StatusUnauthorized)
	if w.Header().Get("WWW-Authenticate") != "Bearer" || store.principal != "" {
		t.Fatalf("revoked credential reached store or lacked challenge: principal=%q headers=%v", store.principal, w.Header())
	}
}

func TestHandlerAcceptsCaseInsensitiveBearerAndUTF8JSONButRejectsControlQueries(t *testing.T) {
	store := newFakeStore()
	handler := newTestHandler(store)
	path := "/v1/projects/" + testProjectID + "/memories/search"
	interoperable := request(http.MethodPost, path, `{"query":"needle","limit":3}`)
	interoperable.Header.Set("Authorization", "bEaReR device-credential")
	interoperable.Header.Set("Content-Type", "application/json; charset=UTF-8")
	serve(t, handler, interoperable, http.StatusOK)

	for _, route := range []string{"search", "brief"} {
		store.query = ""
		body := `{"query":"line\nbreak"`
		if route == "search" {
			body += `,"limit":3`
		}
		body += `}`
		serve(t, handler, request(http.MethodPost, "/v1/projects/"+testProjectID+"/memories/"+route, body), http.StatusBadRequest)
		if store.query != "" {
			t.Fatalf("control query reached %s store: %q", route, store.query)
		}
	}
}

func TestHandlerMasksAuthorityAndMapsCursorConflictsWithoutLeakingStoreErrors(t *testing.T) {
	store := newFakeStore()
	handler := newTestHandler(store)
	path := "/v1/projects/" + testProjectID + "/memories/" + testItemID
	for _, test := range []struct {
		err  error
		want int
	}{
		{postgres.ErrNotFound, http.StatusNotFound},
		{postgres.ErrForbidden, http.StatusNotFound},
		{postgres.ErrCursorTimelineChanged, http.StatusConflict},
		{postgres.ErrCursorFromFuture, http.StatusConflict},
		{errors.New("sql failed with secret document"), http.StatusServiceUnavailable},
	} {
		store.err = test.err
		w := serve(t, handler, request(http.MethodGet, path, ""), test.want)
		if strings.Contains(w.Body.String(), test.err.Error()) || strings.Contains(w.Body.String(), "secret document") {
			t.Fatalf("error leaked for %v: %s", test.err, w.Body.String())
		}
	}
}

func TestHandlerBoundsConcurrencyAndCancelsBlockedStoreWork(t *testing.T) {
	store := newFakeStore()
	store.block = make(chan struct{})
	store.entered = make(chan struct{}, 1)
	policy := &ingress.Policy{Mode: ingress.LAN, ListenAddr: "127.0.0.1:8443", PublicURL: "https://punaro.test"}
	handler := newHandler(store, policy, 1, 20*time.Millisecond)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, request(http.MethodGet, "/v1/projects/"+testProjectID+"/memories/"+testItemID, ""))
		done <- w
	}()
	<-store.entered
	w := serve(t, handler, request(http.MethodGet, "/v1/projects/"+testProjectID+"/memories/"+testItemID, ""), http.StatusTooManyRequests)
	if w.Header().Get("Retry-After") != "1" {
		t.Fatalf("Retry-After=%q", w.Header().Get("Retry-After"))
	}
	first := <-done
	if first.Code != http.StatusServiceUnavailable {
		t.Fatalf("blocked request status=%d body=%s", first.Code, first.Body.String())
	}
}
