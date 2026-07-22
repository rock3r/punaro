// Package memoryclient implements the stateless, fixed-origin native memory protocol.
package memoryclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	maxErrorBytes            = 4096
	maxReadBytes             = 2 << 20
	maxBriefBytes            = 96 << 10
	maxMutationResponseBytes = 16 << 10
	maxRequestBytes          = 1 << 20
)

// Result is one validated JSON protocol response and its optional strong ETag.
type Result struct {
	JSON json.RawMessage
	ETag string
}

// RequestError is a content-free failure classification.
type RequestError struct {
	StatusCode int
	Code       string
	Retryable  bool
	RetryAfter time.Duration
}

func (*RequestError) Error() string { return "punaro memory request failed" }

// Client binds all operations to one origin and bearer credential.
type Client struct {
	base       *url.URL
	credential string
	http       *http.Client
}

// New validates a fixed HTTPS origin and installs direct, no-redirect HTTP behavior.
func New(rawOrigin, credential string) (*Client, error) {
	return newWithHTTPClient(rawOrigin, credential, nil)
}

func newWithHTTPClient(rawOrigin, credential string, provided *http.Client) (*Client, error) {
	base, err := url.Parse(rawOrigin)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || (base.Path != "" && base.Path != "/") || base.Opaque != "" {
		return nil, errors.New("invalid Punaro memory origin")
	}
	if !validCredential(credential) {
		return nil, errors.New("invalid Punaro memory credential")
	}
	if provided == nil {
		provided = &http.Client{Timeout: 15 * time.Second, Transport: directTransport()}
	}
	client := *provided
	switch transport := client.Transport.(type) {
	case nil:
		client.Transport = directTransport()
	case *http.Transport:
		clone := transport.Clone()
		clone.Proxy = nil
		clone.DisableKeepAlives = true
		clone.ForceAttemptHTTP2 = false
		clone.Protocols = http1OnlyProtocols()
		client.Transport = clone
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 15 * time.Second
	}
	base.Path = ""
	return &Client{base: base, credential: credential, http: &client}, nil
}

func directTransport() *http.Transport {
	if transport, ok := http.DefaultTransport.(*http.Transport); ok {
		clone := transport.Clone()
		clone.Proxy = nil
		clone.DisableKeepAlives = true
		clone.ForceAttemptHTTP2 = false
		clone.Protocols = http1OnlyProtocols()
		return clone
	}
	return &http.Transport{DisableKeepAlives: true, Protocols: http1OnlyProtocols()}
}

func http1OnlyProtocols() *http.Protocols {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	return protocols
}

// Resolve resolves one existing authorized project identity.
func (c *Client) Resolve(ctx context.Context, kind, locator string) (Result, error) {
	switch kind {
	case "local_git", "git_remote", "operator_alias", "workspace":
	default:
		return Result{}, errors.New("invalid project locator")
	}
	if strings.TrimSpace(locator) == "" || !utf8.ValidString(locator) || len(locator) > 2048 || strings.IndexFunc(locator, unicode.IsControl) >= 0 {
		return Result{}, errors.New("invalid project locator")
	}
	body, _ := json.Marshal(struct {
		Kind    string `json:"kind"`
		Locator string `json:"locator"`
	}{kind, locator})
	return c.do(ctx, http.MethodPost, "/v1/projects/resolve", body, nil, http.StatusOK, maxErrorBytes, "", nil, func(raw []byte) error {
		return validateResolveKind(raw, kind)
	})
}

// Get returns one authorized canonical memory item.
func (c *Client) Get(ctx context.Context, projectID, itemID string) (Result, error) {
	if !validID(projectID) || !validID(itemID) {
		return Result{}, errors.New("invalid memory lookup")
	}
	return c.do(ctx, http.MethodGet, "/v1/projects/"+projectID+"/memories/"+itemID, nil, nil, http.StatusOK, maxReadBytes, "m1-", map[string]string{"project_id": projectID, "item_id": itemID}, validateMemoryResponse)
}

// Search performs one bounded lexical memory search.
func (c *Client) Search(ctx context.Context, projectID, query string, limit int) (Result, error) {
	if !validQuery(query) || !validID(projectID) || limit < 1 || limit > 50 {
		return Result{}, errors.New("invalid memory search")
	}
	body, _ := json.Marshal(struct {
		Query string `json:"query"`
		Limit int    `json:"limit"`
	}{query, limit})
	return c.do(ctx, http.MethodPost, "/v1/projects/"+projectID+"/memories/search", body, nil, http.StatusOK, maxReadBytes, "", nil, func(raw []byte) error {
		return validateSearchFor(raw, limit)
	})
}

// Brief returns one bounded prompt brief with its untrusted-data envelope.
func (c *Client) Brief(ctx context.Context, projectID, query string) (Result, error) {
	if !validID(projectID) || !validQuery(query) {
		return Result{}, errors.New("invalid memory brief")
	}
	body, _ := json.Marshal(struct {
		Query string `json:"query"`
	}{query})
	return c.do(ctx, http.MethodPost, "/v1/projects/"+projectID+"/memories/brief", body, nil, http.StatusOK, maxBriefBytes, "", map[string]string{"project_id": projectID}, validateBriefResponse)
}

// Changes returns one timeline-bound content-free change page.
func (c *Client) Changes(ctx context.Context, projectID string, cursor json.RawMessage, limit int) (Result, error) {
	if !validID(projectID) || limit < 1 || limit > 100 {
		return Result{}, errors.New("invalid memory changes")
	}
	if len(cursor) == 0 {
		cursor = json.RawMessage("null")
	}
	if !validCursor(cursor) {
		return Result{}, errors.New("invalid memory cursor")
	}
	body, _ := json.Marshal(struct {
		Cursor json.RawMessage `json:"cursor"`
		Limit  int             `json:"limit"`
	}{cursor, limit})
	if !validJSONObject(body, maxErrorBytes) {
		return Result{}, errors.New("invalid memory cursor")
	}
	return c.do(ctx, http.MethodPost, "/v1/projects/"+projectID+"/memories/changes", body, nil, http.StatusOK, maxReadBytes, "", nil, func(raw []byte) error {
		return validateChangesFor(raw, cursor, limit)
	})
}

// Create creates one canonical memory with an explicit idempotency key.
func (c *Client) Create(ctx context.Context, projectID, key string, body json.RawMessage) (Result, error) {
	if !validID(projectID) || !validID(key) || !validJSONObject(body, 264<<10) {
		return Result{}, errors.New("invalid memory create")
	}
	return c.do(ctx, http.MethodPost, "/v1/projects/"+projectID+"/memories", body, mutationHeaders(key, ""), http.StatusCreated, maxMutationResponseBytes, "m1-", nil, validateCreateMutation)
}

// Update replaces one canonical memory through exact compare-and-swap.
func (c *Client) Update(ctx context.Context, projectID, itemID, key, etag string, body json.RawMessage) (Result, error) {
	if !validID(projectID) || !validID(itemID) || !validID(key) || !validETag(etag, "m1-") || !validJSONObject(body, 264<<10) {
		return Result{}, errors.New("invalid memory update")
	}
	return c.do(ctx, http.MethodPut, "/v1/projects/"+projectID+"/memories/"+itemID, body, mutationHeaders(key, etag), http.StatusOK, maxMutationResponseBytes, "m1-", map[string]string{"item_id": itemID}, validateMutationResponse)
}

// SetArchived archives or restores one canonical memory through exact compare-and-swap.
func (c *Client) SetArchived(ctx context.Context, projectID, itemID, key, etag string, archived bool) (Result, error) {
	if !validID(projectID) || !validID(itemID) || !validID(key) || !validETag(etag, "m1-") {
		return Result{}, errors.New("invalid memory state change")
	}
	body, _ := json.Marshal(struct {
		Archived bool `json:"archived"`
	}{archived})
	wantState := "active"
	if archived {
		wantState = "archived"
	}
	return c.do(ctx, http.MethodPost, "/v1/projects/"+projectID+"/memories/"+itemID+"/state", body, mutationHeaders(key, etag), http.StatusOK, maxMutationResponseBytes, "m1-", map[string]string{"item_id": itemID}, func(raw []byte) error {
		return validateMutationState(raw, wantState)
	})
}

// Delete irreversibly purges one canonical memory through exact compare-and-swap.
func (c *Client) Delete(ctx context.Context, projectID, itemID, key, etag string) (Result, error) {
	if !validID(projectID) || !validID(itemID) || !validID(key) || !validETag(etag, "m1-") {
		return Result{}, errors.New("invalid memory delete")
	}
	return c.do(ctx, http.MethodDelete, "/v1/projects/"+projectID+"/memories/"+itemID, nil, mutationHeaders(key, etag), http.StatusOK, maxMutationResponseBytes, "", map[string]string{"item_id": itemID}, validatePurgeResponse)
}

// CreateProposal stages one bounded immutable memory proposal.
func (c *Client) CreateProposal(ctx context.Context, projectID, key string, body json.RawMessage) (Result, error) {
	if !validID(projectID) || !validID(key) || !validJSONObject(body, maxRequestBytes) {
		return Result{}, errors.New("invalid memory proposal")
	}
	return c.do(ctx, http.MethodPost, "/v1/projects/"+projectID+"/memory-proposals", body, mutationHeaders(key, ""), http.StatusCreated, maxMutationResponseBytes, "p1-", nil, func(raw []byte) error {
		return validateProposalResultFor(raw, "pending", false, true)
	})
}

// GetProposal returns one authorized immutable memory proposal.
func (c *Client) GetProposal(ctx context.Context, projectID, proposalID string) (Result, error) {
	if !validID(projectID) || !validID(proposalID) {
		return Result{}, errors.New("invalid memory proposal lookup")
	}
	return c.do(ctx, http.MethodGet, "/v1/projects/"+projectID+"/memory-proposals/"+proposalID, nil, nil, http.StatusOK, maxReadBytes, "p1-", map[string]string{"project_id": projectID, "proposal_id": proposalID}, validateProposalResponse)
}

// DecideProposal approves or rejects one proposal through exact compare-and-swap.
func (c *Client) DecideProposal(ctx context.Context, projectID, proposalID, key, etag string, approve bool) (Result, error) {
	if !validID(projectID) || !validID(proposalID) || !validID(key) || !validETag(etag, "p1-") {
		return Result{}, errors.New("invalid memory proposal decision")
	}
	action := "reject"
	if approve {
		action = "approve"
	}
	wantState := "rejected"
	wantMutations := false
	if approve {
		wantState = "approved"
		wantMutations = true
	}
	return c.do(ctx, http.MethodPost, "/v1/projects/"+projectID+"/memory-proposals/"+proposalID+"/"+action, nil, mutationHeaders(key, etag), http.StatusOK, maxMutationResponseBytes, "p1-", map[string]string{"proposal_id": proposalID}, func(raw []byte) error {
		return validateProposalResultFor(raw, wantState, wantMutations, !wantMutations)
	})
}

func mutationHeaders(key, etag string) http.Header {
	headers := make(http.Header)
	headers.Set("Idempotency-Key", key)
	if etag != "" {
		headers.Set("If-Match", etag)
	}
	return headers
}

func (c *Client) do(ctx context.Context, method, path string, body []byte, headers http.Header, wantStatus int, maxResponse int64, etagPrefix string, identities map[string]string, validate func([]byte) error) (Result, error) {
	if c == nil {
		return Result{}, errors.New("memory client is unavailable")
	}
	target := *c.base
	target.Path = path
	var requestBody io.Reader
	if body != nil {
		requestBody = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, target.String(), requestBody)
	if err != nil {
		return Result{}, errors.New("memory request cannot be created")
	}
	// Request bodies are deliberately non-rewindable. Bodyless requests remain
	// truly empty; keep-alives are disabled so they never use a reusable
	// connection eligible for net/http's transparent replay.
	if body != nil {
		request.Body = io.NopCloser(bytes.NewReader(body))
		request.GetBody = nil
		request.ContentLength = int64(len(body))
	}
	request.Header.Set("Authorization", "Bearer "+c.credential)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	for name, values := range headers {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	response, err := c.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		return Result{}, &RequestError{Retryable: true}
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != wantStatus {
		return Result{}, classifyResponse(response)
	}
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return Result{}, &RequestError{StatusCode: response.StatusCode}
	}
	if !exactJSON(response.Header) || !hasNoStore(response.Header) {
		return Result{}, errors.New("memory response headers are malformed")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	if err != nil || int64(len(raw)) > maxResponse || !validJSONObject(raw, int(maxResponse)) {
		return Result{}, errors.New("memory response is malformed")
	}
	fields, err := rawFields(raw)
	if err != nil {
		return Result{}, errors.New("memory response is malformed")
	}
	if validate == nil || validate(raw) != nil {
		return Result{}, errors.New("memory response schema is invalid")
	}
	for name, expected := range identities {
		var value string
		if json.Unmarshal(fields[name], &value) != nil || value != expected {
			return Result{}, errors.New("memory response identity is inconsistent")
		}
	}
	result := Result{JSON: append(json.RawMessage(nil), raw...)}
	if etagPrefix != "" {
		if len(response.Header.Values("ETag")) != 1 {
			return Result{}, errors.New("memory response ETag is malformed")
		}
		var bodyETag string
		if json.Unmarshal(fields["etag"], &bodyETag) != nil || !validETag(bodyETag, etagPrefix) || bodyETag != response.Header.Get("ETag") {
			return Result{}, errors.New("memory response ETag is inconsistent")
		}
		result.ETag = bodyETag
	} else if len(response.Header.Values("ETag")) != 0 {
		return Result{}, errors.New("memory response ETag is unexpected")
	}
	return result, nil
}

func classifyResponse(response *http.Response) error {
	raw, _ := io.ReadAll(io.LimitReader(response.Body, maxErrorBytes+1))
	code := ""
	if len(raw) <= maxErrorBytes && utf8.Valid(raw) {
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) == nil {
			var candidate string
			if json.Unmarshal(fields["code"], &candidate) == nil && allowedCode(candidate) {
				code = candidate
			}
		}
	}
	retryable := response.StatusCode == http.StatusRequestTimeout || response.StatusCode == http.StatusTooEarly || response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= http.StatusInternalServerError && response.StatusCode <= http.StatusInsufficientStorage
	retryAfter := time.Duration(0)
	if seconds, err := strconv.Atoi(response.Header.Get("Retry-After")); err == nil && seconds > 0 && seconds <= 5 {
		retryAfter = time.Duration(seconds) * time.Second
	}
	return &RequestError{StatusCode: response.StatusCode, Code: code, Retryable: retryable, RetryAfter: retryAfter}
}

func allowedCode(code string) bool {
	switch code {
	case "stale_etag", "stale_proposal", "idempotency_conflict", "logical_key_conflict", "immutable_memory", "proposal_capacity", "proposal_already_satisfied", "maintenance", "timeline_changed", "from_future", "secret_rejected":
		return true
	default:
		return false
	}
}

func exactJSON(headers http.Header) bool {
	if len(headers.Values("Content-Type")) != 1 {
		return false
	}
	mediaType, parameters, err := mime.ParseMediaType(headers.Get("Content-Type"))
	return err == nil && mediaType == "application/json" && len(parameters) == 0
}

func hasNoStore(headers http.Header) bool {
	if len(headers.Values("Cache-Control")) != 1 {
		return false
	}
	for _, directive := range strings.Split(headers.Get("Cache-Control"), ",") {
		if strings.TrimSpace(strings.ToLower(directive)) == "no-store" {
			return true
		}
	}
	return false
}

func validID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func validQuery(value string) bool {
	return strings.TrimSpace(value) != "" && utf8.ValidString(value) && len(value) <= 1024 && utf8.RuneCountInString(value) <= 256 && strings.IndexFunc(value, unicode.IsControl) < 0
}

func validCursor(raw json.RawMessage) bool {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return true
	}
	if !validJSONObject(raw, maxErrorBytes) {
		return false
	}
	fields, err := rawFields(raw)
	if err != nil || len(fields) != 3 {
		return false
	}
	var installationID, timelineID string
	var sequence int64
	return json.Unmarshal(fields["installation_id"], &installationID) == nil && validID(installationID) &&
		json.Unmarshal(fields["timeline_id"], &timelineID) == nil && validID(timelineID) &&
		json.Unmarshal(fields["change_sequence"], &sequence) == nil && sequence >= 0
}

func validETag(value, prefix string) bool {
	if len(value) != 69 || value[0] != '"' || value[68] != '"' || value[1:4] != prefix {
		return false
	}
	if value[4:68] != strings.ToLower(value[4:68]) {
		return false
	}
	_, err := hex.DecodeString(value[4:68])
	return err == nil
}

func validJSONObject(raw []byte, limit int) bool {
	return validJSONObjectDepth(raw, limit, 40)
}

func validJSONObjectDepth(raw []byte, limit, maxDepth int) bool {
	if len(raw) == 0 || len(raw) > limit || !utf8.Valid(raw) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := uniqueValue(decoder, 1, maxDepth, true); err != nil {
		return false
	}
	_, err := decoder.Token()
	return errors.Is(err, io.EOF)
}

func uniqueValue(decoder *json.Decoder, depth, maxDepth int, object bool) error {
	if depth > maxDepth {
		return errors.New("JSON too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if object && (!composite || delimiter != '{') {
		return errors.New("not object")
	}
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("bad key")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("duplicate key")
			}
			seen[key] = struct{}{}
			if err := uniqueValue(decoder, depth+1, maxDepth, false); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("bad object")
		}
	case '[':
		for decoder.More() {
			if err := uniqueValue(decoder, depth+1, maxDepth, false); err != nil {
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

func rawFields(raw []byte) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	err := json.Unmarshal(raw, &fields)
	return fields, err
}
