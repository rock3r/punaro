// Package memoryhttp exposes Punaro's bounded, device-authenticated native
// memory surface. Canonical authorization remains in the PostgreSQL store.
package memoryhttp

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/rock3r/punaro/internal/ingress"
	"github.com/rock3r/punaro/internal/postgres"
)

const (
	maxRequestBytes         = 4096
	maxMutationBytes        = (256 << 10) + (8 << 10)
	maxProposalBytes        = 1 << 20
	maxConcurrentOperations = 32
	operationTimeout        = 5 * time.Second
)

type store interface {
	AuthenticateDevice(context.Context, string) (postgres.AuthenticatedDevice, error)
	ResolveProjectIdentity(context.Context, string, postgres.ProjectIdentityKind, string) (postgres.ProjectIdentityResolution, error)
	GetMemory(context.Context, string, string, string) (postgres.MemoryItem, error)
	GetMemoryProposal(context.Context, string, string, string) (postgres.MemoryProposal, error)
	SearchMemory(context.Context, postgres.MemorySearchRequest) (postgres.MemorySearchPage, error)
	BuildMemoryPromptBrief(context.Context, postgres.MemoryPromptBriefRequest) (postgres.MemoryPromptBrief, error)
	FetchMemoryChanges(context.Context, postgres.MemoryChangeRequest) (postgres.MemoryChangePage, error)
	CreateMemory(context.Context, postgres.MemoryCreateRequest) (postgres.MemoryMutationResult, error)
	UpdateMemory(context.Context, postgres.MemoryUpdateRequest) (postgres.MemoryMutationResult, error)
	ArchiveMemory(context.Context, postgres.MemoryArchiveRequest) (postgres.MemoryMutationResult, error)
	DeleteMemory(context.Context, postgres.MemoryDeleteRequest) (postgres.MemoryMutationResult, error)
	ProposeMemory(context.Context, postgres.MemoryProposalCreateRequest) (postgres.MemoryProposalResult, error)
	ApproveMemoryProposal(context.Context, postgres.MemoryProposalDecisionRequest) (postgres.MemoryProposalResult, error)
	RejectMemoryProposal(context.Context, postgres.MemoryProposalDecisionRequest) (postgres.MemoryProposalResult, error)
}

type handler struct {
	store   store
	policy  *ingress.Policy
	mux     *http.ServeMux
	slots   chan struct{}
	timeout time.Duration
}

// New constructs the native memory handler. The caller independently decides
// whether the dark read surface and its mutation extension are mounted.
func New(database store, policy *ingress.Policy, mutationsEnabled bool) http.Handler {
	return newHandler(database, policy, maxConcurrentOperations, operationTimeout, mutationsEnabled)
}

func newHandler(database store, policy *ingress.Policy, concurrency int, timeout time.Duration, mutationsEnabled bool) http.Handler {
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
	if mutationsEnabled {
		h.mux.HandleFunc("POST /v1/projects/{project}/memories", h.createMemory)
		h.mux.HandleFunc("PUT /v1/projects/{project}/memories/{item}", h.updateMemory)
		h.mux.HandleFunc("POST /v1/projects/{project}/memories/{item}/state", h.setMemoryState)
		h.mux.HandleFunc("DELETE /v1/projects/{project}/memories/{item}", h.deleteMemory)
		h.mux.HandleFunc("POST /v1/projects/{project}/memory-proposals", h.createProposal)
		h.mux.HandleFunc("POST /v1/projects/{project}/memory-proposals/{proposal}/approve", h.approveProposal)
		h.mux.HandleFunc("POST /v1/projects/{project}/memory-proposals/{proposal}/reject", h.rejectProposal)
	}
	return h
}

type memoryWriteBody struct {
	LogicalKey string          `json:"logical_key"`
	Kind       string          `json:"kind"`
	Trust      string          `json:"trust"`
	Document   json.RawMessage `json:"document"`
}

func (h *handler) createMemory(response http.ResponseWriter, request *http.Request) {
	device, projectID, ok := deviceProject(response, request)
	if !ok {
		return
	}
	key, okHeader := mutationHeaders(response, request, "")
	if !okHeader {
		return
	}
	var body memoryWriteBody
	if !readStrictJSON(response, request, maxMutationBytes, &body) {
		return
	}
	if !validMemoryWriteBody(body) {
		writeError(response, http.StatusBadRequest, "request is invalid")
		return
	}
	result, err := h.store.CreateMemory(request.Context(), postgres.MemoryCreateRequest{PrincipalID: device.PrincipalID, ProjectID: projectID, IdempotencyKey: key, LogicalKey: body.LogicalKey, Kind: body.Kind, Trust: body.Trust, Document: body.Document})
	writeMutationResult(response, http.StatusCreated, result, err)
}

func (h *handler) updateMemory(response http.ResponseWriter, request *http.Request) {
	device, projectID, ok := deviceProject(response, request)
	if !ok {
		return
	}
	itemID := request.PathValue("item")
	if !validID(itemID) {
		writeError(response, http.StatusBadRequest, "request is invalid")
		return
	}
	key, etag, okHeader := mutationCASHeaders(response, request, "m1-")
	var body memoryWriteBody
	if !okHeader {
		return
	}
	if !readStrictJSON(response, request, maxMutationBytes, &body) {
		return
	}
	if !validMemoryWriteBody(body) {
		writeError(response, http.StatusBadRequest, "request is invalid")
		return
	}
	result, err := h.store.UpdateMemory(request.Context(), postgres.MemoryUpdateRequest{PrincipalID: device.PrincipalID, ProjectID: projectID, ItemID: itemID, IdempotencyKey: key, ExpectedETag: etag, LogicalKey: body.LogicalKey, Kind: body.Kind, Trust: body.Trust, Document: body.Document})
	writeMutationResult(response, http.StatusOK, result, err)
}

func (h *handler) setMemoryState(response http.ResponseWriter, request *http.Request) {
	device, projectID, ok := deviceProject(response, request)
	if !ok {
		return
	}
	itemID := request.PathValue("item")
	if !validID(itemID) {
		writeError(response, http.StatusBadRequest, "request is invalid")
		return
	}
	key, etag, okHeader := mutationCASHeaders(response, request, "m1-")
	var body struct {
		Archived *bool `json:"archived"`
	}
	if !okHeader {
		return
	}
	if !readStrictJSON(response, request, maxRequestBytes, &body) {
		return
	}
	if body.Archived == nil {
		writeError(response, http.StatusBadRequest, "request is invalid")
		return
	}
	result, err := h.store.ArchiveMemory(request.Context(), postgres.MemoryArchiveRequest{PrincipalID: device.PrincipalID, ProjectID: projectID, ItemID: itemID, IdempotencyKey: key, ExpectedETag: etag, Archived: *body.Archived})
	writeMutationResult(response, http.StatusOK, result, err)
}

func (h *handler) deleteMemory(response http.ResponseWriter, request *http.Request) {
	device, projectID, ok := deviceProject(response, request)
	if !ok {
		return
	}
	itemID := request.PathValue("item")
	if !validID(itemID) {
		writeError(response, http.StatusBadRequest, "request is invalid")
		return
	}
	key, etag, okHeader := mutationCASHeaders(response, request, "m1-")
	if !okHeader || !emptyMutationRequest(response, request) {
		return
	}
	result, err := h.store.DeleteMemory(request.Context(), postgres.MemoryDeleteRequest{PrincipalID: device.PrincipalID, ProjectID: projectID, ItemID: itemID, IdempotencyKey: key, ExpectedETag: etag})
	writeMutationResult(response, http.StatusOK, result, err)
}

type proposalBody struct {
	Action   postgres.MemoryProposalAction          `json:"action"`
	Steps    []postgres.MemoryProposalStepInput     `json:"steps"`
	Evidence []postgres.MemoryProposalEvidenceInput `json:"evidence"`
}

func (h *handler) createProposal(response http.ResponseWriter, request *http.Request) {
	device, projectID, ok := deviceProject(response, request)
	if !ok {
		return
	}
	key, okHeader := mutationHeaders(response, request, "")
	if !okHeader {
		return
	}
	var body proposalBody
	if !readStrictJSON(response, request, maxProposalBytes, &body) {
		return
	}
	if !validProposalBody(body) {
		writeError(response, http.StatusBadRequest, "request is invalid")
		return
	}
	for index := range body.Steps {
		if len(body.Steps[index].Document) != 0 {
			body.Steps[index].Document, _ = canonicalDocument(body.Steps[index].Document)
		}
	}
	payload, _ := json.Marshal(struct {
		ProjectID string                                 `json:"project_id"`
		Action    postgres.MemoryProposalAction          `json:"action"`
		Steps     []postgres.MemoryProposalStepInput     `json:"steps"`
		Evidence  []postgres.MemoryProposalEvidenceInput `json:"evidence,omitempty"`
	}{projectID, body.Action, body.Steps, body.Evidence})
	if len(payload) > 1<<20 {
		writeError(response, http.StatusRequestEntityTooLarge, "request is too large")
		return
	}
	result, err := h.store.ProposeMemory(request.Context(), postgres.MemoryProposalCreateRequest{PrincipalID: device.PrincipalID, ProjectID: projectID, IdempotencyKey: key, Action: body.Action, Steps: body.Steps, Evidence: body.Evidence})
	writeProposalResult(response, http.StatusCreated, result, err)
}

func (h *handler) approveProposal(response http.ResponseWriter, request *http.Request) {
	h.decideProposal(response, request, true)
}
func (h *handler) rejectProposal(response http.ResponseWriter, request *http.Request) {
	h.decideProposal(response, request, false)
}
func (h *handler) decideProposal(response http.ResponseWriter, request *http.Request, approve bool) {
	device, projectID, ok := deviceProject(response, request)
	if !ok {
		return
	}
	proposalID := request.PathValue("proposal")
	if !validID(proposalID) {
		writeError(response, http.StatusBadRequest, "request is invalid")
		return
	}
	key, etag, okHeader := mutationCASHeaders(response, request, "p1-")
	if !okHeader || !emptyMutationRequest(response, request) {
		return
	}
	r := postgres.MemoryProposalDecisionRequest{PrincipalID: device.PrincipalID, ProjectID: projectID, ProposalID: proposalID, IdempotencyKey: key, ExpectedETag: etag}
	var result postgres.MemoryProposalResult
	var err error
	if approve {
		result, err = h.store.ApproveMemoryProposal(request.Context(), r)
	} else {
		result, err = h.store.RejectMemoryProposal(request.Context(), r)
	}
	writeProposalResult(response, http.StatusOK, result, err)
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
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func validQuery(value string) bool {
	return value != "" && strings.TrimSpace(value) != "" && utf8.ValidString(value) && len(value) <= 1024 && utf8.RuneCountInString(value) <= 256 && strings.IndexFunc(value, unicode.IsControl) < 0
}

func mutationHeaders(response http.ResponseWriter, request *http.Request, _ string) (string, bool) {
	values := request.Header.Values("Idempotency-Key")
	if len(values) != 1 || !validID(values[0]) {
		writeError(response, http.StatusBadRequest, "Idempotency-Key is required")
		return "", false
	}
	return values[0], true
}

func mutationCASHeaders(response http.ResponseWriter, request *http.Request, prefix string) (string, string, bool) {
	key, ok := mutationHeaders(response, request, "")
	if !ok {
		return "", "", false
	}
	values := request.Header.Values("If-Match")
	if len(values) != 1 || !validStrongETag(values[0], prefix) {
		writeError(response, http.StatusBadRequest, "If-Match is required")
		return "", "", false
	}
	return key, values[0], true
}

func validStrongETag(value, prefix string) bool {
	if len(value) != 4+64+1 || value[0] != '"' || value[len(value)-1] != '"' || value[1:4] != prefix {
		return false
	}
	_, err := hex.DecodeString(value[4 : len(value)-1])
	return err == nil
}

func emptyMutationRequest(response http.ResponseWriter, request *http.Request) bool {
	if request.URL.RawQuery != "" || request.Body != nil && request.Body != http.NoBody && request.ContentLength != 0 {
		writeError(response, http.StatusBadRequest, "request is invalid")
		return false
	}
	return true
}

func validMemoryWriteBody(body memoryWriteBody) bool {
	return validLogicalKey(body.LogicalKey) && validToken(body.Kind) && validToken(body.Trust) && validDocument(body.Document)
}

func validLogicalKey(value string) bool {
	return utf8.ValidString(value) && len(value) <= 512 && utf8.RuneCountInString(value) <= 128 && strings.IndexFunc(value, unicode.IsControl) < 0
}

func validToken(value string) bool {
	if value == "" || !utf8.ValidString(value) || utf8.RuneCountInString(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, r := range value[1:] {
		if !validTokenRune(r) {
			return false
		}
	}
	return true
}

func validTokenRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == ':' || r == '-'
}

func validDocument(raw json.RawMessage) bool {
	_, err := canonicalDocument(raw)
	return err == nil
}

func canonicalDocument(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > 256<<10 || !utf8.Valid(raw) {
		return nil, errors.New("invalid document")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := validateUniqueJSON(decoder, 1, 32, true); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing document")
	}
	canonicalDecoder := json.NewDecoder(bytes.NewReader(raw))
	canonicalDecoder.UseNumber()
	var value map[string]any
	if canonicalDecoder.Decode(&value) != nil {
		return nil, errors.New("invalid document")
	}
	canonical, err := json.Marshal(value)
	if err != nil || len(canonical) > 256<<10 {
		return nil, errors.New("document is too large")
	}
	return canonical, nil
}

func validProposalBody(body proposalBody) bool {
	if len(body.Steps) < 1 || len(body.Steps) > 8 || len(body.Evidence) > 16 {
		return false
	}
	evidenceIDs := make(map[string]struct{}, len(body.Evidence))
	for _, evidence := range body.Evidence {
		if !validID(evidence.ItemID) || evidence.Revision < 1 {
			return false
		}
		if _, duplicate := evidenceIDs[evidence.ItemID]; duplicate {
			return false
		}
		evidenceIDs[evidence.ItemID] = struct{}{}
	}
	targetIDs, logicalKeys := map[string]struct{}{}, map[string]struct{}{}
	for _, step := range body.Steps {
		switch step.Operation {
		case postgres.MemoryProposalStepCreate:
			if step.ItemID != "" || step.ExpectedETag != "" || step.Archived || !validLogicalKey(step.LogicalKey) || !validToken(step.Kind) || !validToken(step.Trust) || !validDocument(step.Document) {
				return false
			}
		case postgres.MemoryProposalStepUpdate:
			if !validID(step.ItemID) || !validStrongETag(step.ExpectedETag, "m1-") || step.Archived || !validLogicalKey(step.LogicalKey) || !validToken(step.Kind) || !validToken(step.Trust) || !validDocument(step.Document) {
				return false
			}
		case postgres.MemoryProposalStepArchive:
			if !validID(step.ItemID) || !validStrongETag(step.ExpectedETag, "m1-") || step.LogicalKey != "" || step.Kind != "" || step.Trust != "" || len(step.Document) != 0 {
				return false
			}
		default:
			return false
		}
		if step.ItemID != "" {
			if _, duplicate := targetIDs[step.ItemID]; duplicate {
				return false
			}
			targetIDs[step.ItemID] = struct{}{}
		}
		if step.Operation == postgres.MemoryProposalStepCreate && step.LogicalKey != "" {
			if _, duplicate := logicalKeys[step.LogicalKey]; duplicate {
				return false
			}
			logicalKeys[step.LogicalKey] = struct{}{}
		}
	}
	switch body.Action {
	case postgres.MemoryProposalCreate:
		return len(body.Steps) == 1 && body.Steps[0].Operation == postgres.MemoryProposalStepCreate
	case postgres.MemoryProposalUpdate:
		return len(body.Steps) == 1 && body.Steps[0].Operation == postgres.MemoryProposalStepUpdate
	case postgres.MemoryProposalArchive:
		return len(body.Steps) == 1 && body.Steps[0].Operation == postgres.MemoryProposalStepArchive && body.Steps[0].Archived
	case postgres.MemoryProposalMerge:
		if len(body.Steps) < 2 || body.Steps[0].Operation != postgres.MemoryProposalStepUpdate {
			return false
		}
		for _, s := range body.Steps[1:] {
			if s.Operation != postgres.MemoryProposalStepArchive || !s.Archived {
				return false
			}
		}
		return true
	case postgres.MemoryProposalSplit:
		if len(body.Steps) < 3 || body.Steps[0].Operation != postgres.MemoryProposalStepArchive || !body.Steps[0].Archived {
			return false
		}
		for _, s := range body.Steps[1:] {
			if s.Operation != postgres.MemoryProposalStepCreate {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func readStrictJSON(response http.ResponseWriter, request *http.Request, limit int64, destination any) bool {
	if request.URL.RawQuery != "" {
		writeError(response, http.StatusBadRequest, "request is invalid")
		return false
	}
	if !exactJSON(request) {
		writeError(response, http.StatusUnsupportedMediaType, "application/json is required")
		return false
	}
	if request.ContentLength > limit {
		writeError(response, http.StatusRequestEntityTooLarge, "request is too large")
		return false
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, limit+1))
	if err != nil || int64(len(body)) > limit {
		writeError(response, http.StatusRequestEntityTooLarge, "request is too large")
		return false
	}
	if !utf8.Valid(body) {
		writeError(response, http.StatusBadRequest, "request is malformed")
		return false
	}
	unique := json.NewDecoder(bytes.NewReader(body))
	unique.UseNumber()
	if err := validateUniqueJSON(unique, 1, 40, true); err != nil {
		writeError(response, http.StatusBadRequest, "request is malformed")
		return false
	}
	if _, err := unique.Token(); !errors.Is(err, io.EOF) {
		writeError(response, http.StatusBadRequest, "request is malformed")
		return false
	}
	if err := validateExactObject(body, reflect.TypeOf(destination)); err != nil {
		writeError(response, http.StatusBadRequest, "request is malformed")
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		writeError(response, http.StatusBadRequest, "request is malformed")
		return false
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		writeError(response, http.StatusBadRequest, "request is malformed")
		return false
	}
	return true
}

func validateExactObject(raw []byte, destination reflect.Type) error {
	for destination.Kind() == reflect.Pointer {
		destination = destination.Elem()
	}
	if destination.Kind() != reflect.Struct {
		return errors.New("destination is not an object")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	allowed := make(map[string]reflect.Type, destination.NumField())
	for index := 0; index < destination.NumField(); index++ {
		field := destination.Field(index)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "" {
			name = field.Name
		}
		if name == "-" {
			continue
		}
		allowed[name] = field.Type
	}
	for name, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errors.New("null field")
		}
		fieldType, ok := allowed[name]
		if !ok {
			return errors.New("unknown field")
		}
		base := fieldType
		for base.Kind() == reflect.Pointer {
			base = base.Elem()
		}
		if base == reflect.TypeOf(json.RawMessage{}) {
			continue
		}
		if base.Kind() == reflect.Struct {
			if err := validateExactObject(value, base); err != nil {
				return err
			}
		}
		if base.Kind() == reflect.Slice {
			element := base.Elem()
			for element.Kind() == reflect.Pointer {
				element = element.Elem()
			}
			if element.Kind() == reflect.Struct {
				var entries []json.RawMessage
				if err := json.Unmarshal(value, &entries); err != nil {
					return err
				}
				for _, entry := range entries {
					if err := validateExactObject(entry, element); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func validateUniqueJSON(decoder *json.Decoder, depth, maxDepth int, requireObject bool) error {
	if depth > maxDepth {
		return errors.New("too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, composite := token.(json.Delim)
	if requireObject && (!composite || delim != '{') {
		return errors.New("not object")
	}
	if !composite {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			raw, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := raw.(string)
			if !ok {
				return errors.New("bad key")
			}
			if _, ok := seen[key]; ok {
				return errors.New("duplicate")
			}
			seen[key] = struct{}{}
			if err := validateUniqueJSON(decoder, depth+1, maxDepth, false); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("bad object")
		}
	case '[':
		for decoder.More() {
			if err := validateUniqueJSON(decoder, depth+1, maxDepth, false); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("bad array")
		}
	default:
		return errors.New("bad delimiter")
	}
	return nil
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
	var rejection postgres.MemorySecretRejection
	switch {
	case errors.Is(err, postgres.ErrNotFound), errors.Is(err, postgres.ErrForbidden):
		writeError(response, http.StatusNotFound, "memory resource was not found")
	case errors.Is(err, postgres.ErrStaleMemoryETag):
		writeCodedError(response, http.StatusConflict, "memory precondition failed", "stale_etag")
	case errors.Is(err, postgres.ErrStaleMemoryProposal):
		writeCodedError(response, http.StatusConflict, "memory proposal precondition failed", "stale_proposal")
	case errors.Is(err, postgres.ErrIdempotencyConflict):
		writeCodedError(response, http.StatusConflict, "memory mutation conflicts with an earlier request", "idempotency_conflict")
	case errors.Is(err, postgres.ErrMemoryLogicalKeyConflict):
		writeCodedError(response, http.StatusConflict, "memory logical key conflicts with an existing item", "logical_key_conflict")
	case errors.Is(err, postgres.ErrImmutableMemoryEvidence):
		writeCodedError(response, http.StatusConflict, "memory item is immutable", "immutable_memory")
	case errors.Is(err, postgres.ErrMemoryProposalCapacity):
		writeCodedError(response, http.StatusTooManyRequests, "memory proposal cannot be accepted", "proposal_capacity")
	case errors.Is(err, postgres.ErrMemoryProposalAlreadySatisfied):
		writeCodedError(response, http.StatusConflict, "memory proposal conflicts with current state", "proposal_already_satisfied")
	case errors.As(err, &rejection):
		writeJSON(response, http.StatusUnprocessableEntity, struct {
			Error       string `json:"error"`
			Code        string `json:"code"`
			RuleID      string `json:"rule_id"`
			FieldPath   string `json:"field_path"`
			RuleVersion int64  `json:"rule_version"`
		}{"memory content was rejected", "secret_rejected", rejection.Finding.RuleID, rejection.Finding.FieldPath, rejection.Finding.RuleVersion})
	case errors.Is(err, postgres.ErrMaintenance):
		response.Header().Set("Retry-After", "1")
		writeCodedError(response, http.StatusServiceUnavailable, "memory service is temporarily unavailable", "maintenance")
	case errors.Is(err, postgres.ErrCursorTimelineChanged):
		writeCursorError(response, "timeline_changed")
	case errors.Is(err, postgres.ErrCursorFromFuture):
		writeCursorError(response, "from_future")
	default:
		writeError(response, http.StatusServiceUnavailable, "memory service is unavailable")
	}
}

func writeMutationResult(response http.ResponseWriter, status int, result postgres.MemoryMutationResult, err error) {
	if err != nil {
		writeStoreError(response, err)
		return
	}
	if result.ETag != "" {
		response.Header().Set("ETag", result.ETag)
	}
	writeJSON(response, status, result)
}

func writeProposalResult(response http.ResponseWriter, status int, result postgres.MemoryProposalResult, err error) {
	if err != nil {
		writeStoreError(response, err)
		return
	}
	if result.ETag != "" {
		response.Header().Set("ETag", result.ETag)
	}
	writeJSON(response, status, result)
}

func writeCodedError(response http.ResponseWriter, status int, message, code string) {
	writeJSON(response, status, map[string]string{"error": message, "code": code})
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
