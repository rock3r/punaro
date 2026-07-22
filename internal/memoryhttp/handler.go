// Package memoryhttp exposes Punaro's bounded, device-authenticated native
// memory read surface. Canonical authorization remains in the PostgreSQL store.
package memoryhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/rock3r/punaro/internal/ingress"
	"github.com/rock3r/punaro/internal/postgres"
)

const (
	maxRequestBytes      = 4096
	maxConcurrentReads   = 32
	readOperationTimeout = 5 * time.Second
)

type store interface {
	AuthenticateDevice(context.Context, string) (postgres.AuthenticatedDevice, error)
	ResolveProjectIdentity(context.Context, string, postgres.ProjectIdentityKind, string) (postgres.ProjectIdentityResolution, error)
	GetMemory(context.Context, string, string, string) (postgres.MemoryItem, error)
	GetMemoryProposal(context.Context, string, string, string) (postgres.MemoryProposal, error)
	SearchMemory(context.Context, postgres.MemorySearchRequest) (postgres.MemorySearchPage, error)
	BuildMemoryPromptBrief(context.Context, postgres.MemoryPromptBriefRequest) (postgres.MemoryPromptBrief, error)
	FetchMemoryChanges(context.Context, postgres.MemoryChangeRequest) (postgres.MemoryChangePage, error)
}

type handler struct {
	store   store
	policy  *ingress.Policy
	mux     *http.ServeMux
	slots   chan struct{}
	timeout time.Duration
}

// New constructs the native memory read handler. The caller decides whether
// the dark surface is mounted in the production mux.
func New(database store, policy *ingress.Policy) http.Handler {
	return newHandler(database, policy, maxConcurrentReads, readOperationTimeout)
}

func newHandler(database store, policy *ingress.Policy, concurrency int, timeout time.Duration) http.Handler {
	if concurrency < 1 {
		concurrency = 1
	}
	h := &handler{store: database, policy: policy, mux: http.NewServeMux(), slots: make(chan struct{}, concurrency), timeout: timeout}
	h.mux.HandleFunc("POST /v1/projects/resolve", h.resolveProject)
	h.mux.HandleFunc("GET /v1/projects/{project}/memories/{item}", h.getMemory)
	h.mux.HandleFunc("POST /v1/projects/{project}/memories/search", h.searchMemory)
	h.mux.HandleFunc("POST /v1/projects/{project}/memories/brief", h.promptBrief)
	h.mux.HandleFunc("POST /v1/projects/{project}/memories/changes", h.memoryChanges)
	h.mux.HandleFunc("GET /v1/projects/{project}/memory-proposals/{proposal}", h.getProposal)
	return h
}

func (h *handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	if h.store == nil || h.policy == nil || !h.policy.AllowsCredential(request) {
		writeError(response, http.StatusForbidden, "credential transport is forbidden")
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		response.Header().Set("Retry-After", "1")
		writeError(response, http.StatusTooManyRequests, "memory service is busy")
		return
	}
	credential, ok := bearerCredential(request)
	if !ok {
		unauthenticated(response)
		return
	}
	operationCtx, cancel := context.WithTimeout(request.Context(), h.timeout)
	defer cancel()
	device, err := h.store.AuthenticateDevice(operationCtx, credential)
	if err != nil || !validID(device.PrincipalID) || !validID(device.LookupID) || device.Generation < 1 {
		unauthenticated(response)
		return
	}
	h.mux.ServeHTTP(response, request.WithContext(context.WithValue(operationCtx, authenticatedDeviceKey{}, device)))
}

type authenticatedDeviceKey struct{}

func authenticatedDevice(ctx context.Context) (postgres.AuthenticatedDevice, bool) {
	device, ok := ctx.Value(authenticatedDeviceKey{}).(postgres.AuthenticatedDevice)
	return device, ok
}

func bearerCredential(request *http.Request) (string, bool) {
	if len(request.Header.Values("Authorization")) != 1 {
		return "", false
	}
	value := request.Header.Get("Authorization")
	scheme, credential, ok := strings.Cut(value, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	return credential, credential != "" && !strings.ContainsAny(credential, " \t\r\n")
}

func (h *handler) resolveProject(response http.ResponseWriter, request *http.Request) {
	device, ok := authenticatedDevice(request.Context())
	if !ok {
		unauthenticated(response)
		return
	}
	fields, ok := readObject(response, request, "kind", "locator")
	if !ok {
		return
	}
	var kind postgres.ProjectIdentityKind
	var locator string
	if !decodeString(fields["kind"], (*string)(&kind)) || !decodeString(fields["locator"], &locator) ||
		len(locator) > maxRequestBytes || strings.TrimSpace(locator) == "" {
		writeError(response, http.StatusBadRequest, "request is malformed")
		return
	}
	if _, err := postgres.NormalizeProjectIdentityLocator(kind, locator); err != nil {
		writeError(response, http.StatusBadRequest, "request is invalid")
		return
	}
	result, err := h.store.ResolveProjectIdentity(request.Context(), device.PrincipalID, kind, locator)
	if err != nil {
		writeStoreError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (h *handler) getMemory(response http.ResponseWriter, request *http.Request) {
	device, projectID, ok := deviceProject(response, request)
	itemID := request.PathValue("item")
	if !ok || !validID(itemID) || !emptyRequest(request) {
		if ok {
			writeError(response, http.StatusBadRequest, "request is invalid")
		}
		return
	}
	item, err := h.store.GetMemory(request.Context(), device.PrincipalID, projectID, itemID)
	if err != nil {
		writeStoreError(response, err)
		return
	}
	response.Header().Set("ETag", item.ETag)
	writeJSON(response, http.StatusOK, item)
}

func (h *handler) getProposal(response http.ResponseWriter, request *http.Request) {
	device, projectID, ok := deviceProject(response, request)
	proposalID := request.PathValue("proposal")
	if !ok || !validID(proposalID) || !emptyRequest(request) {
		if ok {
			writeError(response, http.StatusBadRequest, "request is invalid")
		}
		return
	}
	proposal, err := h.store.GetMemoryProposal(request.Context(), device.PrincipalID, projectID, proposalID)
	if err != nil {
		writeStoreError(response, err)
		return
	}
	response.Header().Set("ETag", proposal.ETag)
	writeJSON(response, http.StatusOK, proposal)
}

func (h *handler) searchMemory(response http.ResponseWriter, request *http.Request) {
	device, projectID, ok := deviceProject(response, request)
	if !ok {
		return
	}
	fields, ok := readObject(response, request, "query", "limit")
	if !ok {
		return
	}
	var query string
	var limit int
	if !decodeString(fields["query"], &query) || !decodeInt(fields["limit"], &limit) || !validQuery(query) || limit < 1 || limit > 50 {
		writeError(response, http.StatusBadRequest, "request is invalid")
		return
	}
	page, err := h.store.SearchMemory(request.Context(), postgres.MemorySearchRequest{PrincipalID: device.PrincipalID, ProjectID: projectID, Query: query, Limit: limit})
	if err != nil {
		writeStoreError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, page)
}

func (h *handler) promptBrief(response http.ResponseWriter, request *http.Request) {
	device, projectID, ok := deviceProject(response, request)
	if !ok {
		return
	}
	fields, ok := readObject(response, request, "query")
	if !ok {
		return
	}
	var query string
	if !decodeString(fields["query"], &query) || !validQuery(query) {
		writeError(response, http.StatusBadRequest, "request is invalid")
		return
	}
	brief, err := h.store.BuildMemoryPromptBrief(request.Context(), postgres.MemoryPromptBriefRequest{PrincipalID: device.PrincipalID, ProjectID: projectID, Query: query})
	if err != nil {
		writeStoreError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, brief)
}

type changeCursor struct {
	InstallationID string
	TimelineID     string
	ChangeSequence int64
}

type changePage struct {
	Changes []postgres.MemoryChange `json:"changes"`
	Cursor  cursorOutput            `json:"cursor"`
	More    bool                    `json:"more"`
}

type cursorOutput struct {
	InstallationID string `json:"installation_id"`
	TimelineID     string `json:"timeline_id"`
	ChangeSequence int64  `json:"change_sequence"`
}

func (h *handler) memoryChanges(response http.ResponseWriter, request *http.Request) {
	device, projectID, ok := deviceProject(response, request)
	if !ok {
		return
	}
	fields, ok := readObject(response, request, "cursor", "limit")
	if !ok {
		return
	}
	cursor, ok := decodeCursor(fields["cursor"])
	var limit int
	if !ok || !decodeInt(fields["limit"], &limit) || limit < 1 || limit > 100 {
		writeError(response, http.StatusBadRequest, "request is invalid")
		return
	}
	page, err := h.store.FetchMemoryChanges(request.Context(), postgres.MemoryChangeRequest{PrincipalID: device.PrincipalID, ProjectID: projectID, Cursor: postgres.InstallationState{InstallationID: cursor.InstallationID, TimelineID: cursor.TimelineID, ChangeSequence: cursor.ChangeSequence}, Limit: limit})
	if err != nil {
		writeStoreError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, changePage{Changes: page.Changes, Cursor: cursorOutput{InstallationID: page.Cursor.InstallationID, TimelineID: page.Cursor.TimelineID, ChangeSequence: page.Cursor.ChangeSequence}, More: page.More})
}

func deviceProject(response http.ResponseWriter, request *http.Request) (postgres.AuthenticatedDevice, string, bool) {
	device, ok := authenticatedDevice(request.Context())
	if !ok {
		unauthenticated(response)
		return postgres.AuthenticatedDevice{}, "", false
	}
	projectID := request.PathValue("project")
	if !validID(projectID) {
		writeError(response, http.StatusBadRequest, "request is invalid")
		return postgres.AuthenticatedDevice{}, "", false
	}
	return device, projectID, true
}

func emptyRequest(request *http.Request) bool {
	return request.URL.RawQuery == "" && (request.Body == nil || request.Body == http.NoBody || request.ContentLength == 0)
}

func validID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value
}

func validQuery(value string) bool {
	return value != "" && strings.TrimSpace(value) != "" && utf8.ValidString(value) && len(value) <= 1024 && utf8.RuneCountInString(value) <= 256 && strings.IndexFunc(value, unicode.IsControl) < 0
}

func readObject(response http.ResponseWriter, request *http.Request, names ...string) (map[string]json.RawMessage, bool) {
	if request.URL.RawQuery != "" || !exactJSON(request) {
		writeError(response, http.StatusUnsupportedMediaType, "application/json is required")
		return nil, false
	}
	if request.ContentLength > maxRequestBytes {
		writeError(response, http.StatusRequestEntityTooLarge, "request is too large")
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxRequestBytes+1))
	if err != nil || len(body) > maxRequestBytes {
		writeError(response, http.StatusRequestEntityTooLarge, "request is too large")
		return nil, false
	}
	fields, err := decodeObject(body, names...)
	if err != nil {
		writeError(response, http.StatusBadRequest, "request is malformed")
		return nil, false
	}
	return fields, true
}

func decodeObject(body []byte, names ...string) (map[string]json.RawMessage, error) {
	allowed := make(map[string]struct{}, len(names))
	for _, name := range names {
		allowed[name] = struct{}{}
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, errors.New("not an object")
	}
	fields := make(map[string]json.RawMessage, len(names))
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok {
			return nil, errors.New("invalid field")
		}
		if _, ok := allowed[name]; !ok {
			return nil, errors.New("unknown field")
		}
		if _, duplicate := fields[name]; duplicate {
			return nil, errors.New("duplicate field")
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, errors.New("invalid value")
		}
		fields[name] = raw
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') || len(fields) != len(names) {
		return nil, errors.New("incomplete object")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing input")
	}
	return fields, nil
}

func decodeCursor(raw json.RawMessage) (changeCursor, bool) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return changeCursor{}, true
	}
	fields, err := decodeObject(raw, "installation_id", "timeline_id", "change_sequence")
	if err != nil {
		return changeCursor{}, false
	}
	var cursor changeCursor
	return cursor, decodeString(fields["installation_id"], &cursor.InstallationID) && validID(cursor.InstallationID) &&
		decodeString(fields["timeline_id"], &cursor.TimelineID) && validID(cursor.TimelineID) &&
		decodeInt64(fields["change_sequence"], &cursor.ChangeSequence) && cursor.ChangeSequence >= 0
}

func decodeString(raw json.RawMessage, destination *string) bool {
	return json.Unmarshal(raw, destination) == nil
}

func decodeInt(raw json.RawMessage, destination *int) bool {
	return json.Unmarshal(raw, destination) == nil
}

func decodeInt64(raw json.RawMessage, destination *int64) bool {
	return json.Unmarshal(raw, destination) == nil
}

func exactJSON(request *http.Request) bool {
	if len(request.Header.Values("Content-Type")) != 1 {
		return false
	}
	mediaType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return false
	}
	if len(parameters) == 0 {
		return true
	}
	charset, ok := parameters["charset"]
	return len(parameters) == 1 && ok && strings.EqualFold(charset, "utf-8")
}

func unauthenticated(response http.ResponseWriter) {
	response.Header().Set("WWW-Authenticate", "Bearer")
	writeError(response, http.StatusUnauthorized, "unauthenticated")
}

func writeStoreError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, postgres.ErrNotFound), errors.Is(err, postgres.ErrForbidden):
		writeError(response, http.StatusNotFound, "memory resource was not found")
	case errors.Is(err, postgres.ErrCursorTimelineChanged):
		writeCursorError(response, "timeline_changed")
	case errors.Is(err, postgres.ErrCursorFromFuture):
		writeCursorError(response, "from_future")
	default:
		writeError(response, http.StatusServiceUnavailable, "memory service is unavailable")
	}
}

func writeCursorError(response http.ResponseWriter, code string) {
	writeJSON(response, http.StatusConflict, map[string]string{"error": "memory cursor is invalid", "code": code})
}

func writeError(response http.ResponseWriter, status int, message string) {
	writeJSON(response, status, map[string]string{"error": message})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
