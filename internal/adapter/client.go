package adapter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"
	attachmentv2 "github.com/rock3r/punaro/internal/attachment/v2"
	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
	"github.com/rock3r/punaro/internal/relay"
)

// AccessServiceToken holds the two headers required for Cloudflare Access
// service-token authentication. Callers must provide both fields or neither.
type AccessServiceToken struct {
	ClientID     string
	ClientSecret string
}

// HTTPRelayClient is the signed HTTPS client used by one enrolled adapter.
type HTTPRelayClient struct {
	baseURL     *url.URL
	machineID   string
	privateKey  ed25519.PrivateKey
	httpClient  *http.Client
	accessToken AccessServiceToken
}

type relayHTTPStatusError struct {
	status int
	err    error
}

func (e *relayHTTPStatusError) Error() string { return e.err.Error() }
func (e *relayHTTPStatusError) Unwrap() error { return e.err }

// PermanentOfferNoticeFailure is true only for append-route responses whose
// handler rejects before any message or idempotency row can be created.
func (e *relayHTTPStatusError) PermanentOfferNoticeFailure() bool {
	return e != nil && (e.status == http.StatusForbidden || e.status == http.StatusNotFound)
}

// NewHTTPRelayClient validates and creates a signed client for one machine.
func NewHTTPRelayClient(rawURL, machineID string, privateKey ed25519.PrivateKey, client *http.Client, accessToken AccessServiceToken) (*HTTPRelayClient, error) {
	baseURL, err := url.Parse(rawURL)
	if err != nil || baseURL.Scheme == "" || baseURL.Host == "" || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, fmt.Errorf("invalid relay URL")
	}
	if baseURL.Scheme != "https" && (baseURL.Scheme != "http" || !loopbackHost(baseURL.Hostname())) {
		return nil, fmt.Errorf("relay URL must use HTTPS except for a loopback development listener")
	}
	if strings.TrimSpace(machineID) == "" || len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("machine ID and Ed25519 private key are required")
	}
	if (accessToken.ClientID == "") != (accessToken.ClientSecret == "") {
		return nil, fmt.Errorf("cloudflare Access service token must contain both ID and secret")
	}
	if client == nil {
		client = http.DefaultClient
	}
	return &HTTPRelayClient{baseURL: baseURL, machineID: machineID, privateKey: append(ed25519.PrivateKey(nil), privateKey...), httpClient: client, accessToken: accessToken}, nil
}

// Advertise replaces the machine's current local endpoint attachment set.
func (c *HTTPRelayClient) Advertise(ctx context.Context, endpoints []string) error {
	_, err := c.doJSON(ctx, http.MethodPut, "/v1/machines/me/endpoints", map[string]any{"endpoints": endpoints}, nil)
	return err
}

// Lease obtains the current endpoint's bounded, durable delivery page.
func (c *HTTPRelayClient) Lease(ctx context.Context, endpoint string) ([]relay.Delivery, error) {
	var response struct {
		Deliveries []relay.Delivery `json:"deliveries"`
	}
	_, err := c.doJSON(ctx, http.MethodPost, "/v1/deliveries/lease", map[string]any{"endpoint": endpoint}, &response)
	return response.Deliveries, err
}

// CreateConversation bootstraps an explicit, membership-scoped room from an
// attached local endpoint. The relay still verifies endpoint ownership.
func (c *HTTPRelayClient) CreateConversation(ctx context.Context, creator string, members []relay.Member, idempotencyKey string) (relay.Conversation, error) {
	if strings.TrimSpace(creator) == "" || len(members) == 0 || strings.TrimSpace(idempotencyKey) == "" {
		return relay.Conversation{}, fmt.Errorf("creator, members, and idempotency key are required")
	}
	encoded := make([]map[string]any, 0, len(members))
	for _, member := range members {
		encoded = append(encoded, map[string]any{"endpoint": member.Endpoint, "capabilities": capabilityNames(member.Capabilities)})
	}
	var conversation relay.Conversation
	_, err := c.doJSONWithIdempotency(ctx, http.MethodPost, "/v1/conversations", map[string]any{"creator_endpoint": creator, "members": encoded}, idempotencyKey, &conversation)
	return conversation, err
}

func capabilityNames(capabilities relay.Capability) []string {
	result := make([]string, 0, 3)
	if capabilities&relay.CapSend != 0 {
		result = append(result, "send")
	}
	if capabilities&relay.CapReceive != 0 {
		result = append(result, "receive")
	}
	if capabilities&relay.CapAdmin != 0 {
		result = append(result, "admin")
	}
	return result
}

// Send appends an opaque local-agent reply to an existing conversation. The
// idempotency key belongs to the caller's retry domain and is never derived
// from the body or a machine credential.
func (c *HTTPRelayClient) Send(ctx context.Context, conversationID, fromEndpoint, body, idempotencyKey string) (relay.Message, error) {
	if strings.TrimSpace(conversationID) == "" || strings.TrimSpace(fromEndpoint) == "" || strings.TrimSpace(idempotencyKey) == "" {
		return relay.Message{}, fmt.Errorf("conversation, sender endpoint, and idempotency key are required")
	}
	var message relay.Message
	status, err := c.doJSONWithIdempotency(ctx, http.MethodPost, "/v1/conversations/"+url.PathEscape(conversationID)+"/messages", map[string]any{"from_endpoint": fromEndpoint, "body": body}, idempotencyKey, &message)
	if err != nil {
		return message, &relayHTTPStatusError{status: status, err: err}
	}
	return message, nil
}

// ValidateSender performs an authenticated, side-effect-free check that an
// attached local endpoint may send to one conversation. The subsequent Send
// still authorizes independently, so this cannot become a time-of-check grant.
func (c *HTTPRelayClient) ValidateSender(ctx context.Context, conversationID, fromEndpoint string) error {
	if strings.TrimSpace(conversationID) == "" || strings.TrimSpace(fromEndpoint) == "" {
		return fmt.Errorf("conversation and sender endpoint are required")
	}
	_, err := c.doJSON(ctx, http.MethodPost, "/v1/conversations/"+url.PathEscape(conversationID)+"/sender-validation", map[string]any{"from_endpoint": fromEndpoint}, nil)
	return err
}

// SendV3OfferNotice makes one idempotent attempt to make a completed attachment
// offer discoverable through the same durable, membership-scoped conversation
// as its control messages. It transports no plaintext and grants no attachment
// authority. Long-running callers must use OfferNoticeOutbox so the notice is
// persisted before this attempt and retried after process/network failure.
func (c *HTTPRelayClient) SendV3OfferNotice(ctx context.Context, conversationID, fromEndpoint string, rawOffer []byte, idempotencyKey string) (relay.Message, error) {
	notice, err := attachmentv3.EncodeOfferNotice(rawOffer)
	if err != nil {
		return relay.Message{}, fmt.Errorf("encode v3 attachment offer notice: %w", err)
	}
	return c.Send(ctx, conversationID, fromEndpoint, notice, idempotencyKey)
}

// Ack acknowledges a locally committed delivery using its live lease fence.
func (c *HTTPRelayClient) Ack(ctx context.Context, delivery relay.Delivery) error {
	_, err := c.doJSON(ctx, http.MethodPost, "/v1/deliveries/"+url.PathEscape(delivery.ID)+"/ack", map[string]any{"endpoint": delivery.RecipientEndpoint, "lease_token": delivery.LeaseToken, "lease_generation": delivery.LeaseGeneration}, nil)
	return err
}

const (
	directorySnapshotPath     = "/v2/directory"
	maxDirectorySnapshotBytes = 2 << 20
	permitIssuancePath        = "/v2/permits"
	v3PermitIssuancePath      = "/v3/permits"
	maxPermitResponseBytes    = 4 << 10
	maxV3AttachmentBody       = 256<<10 + 16
)

// IssuePermit submits an already holder-signed canonical permit request over
// the adapter's enrolled machine channel. The relay separately verifies the
// holder signature, fresh directory authority, and machine-to-holder binding.
func (c *HTTPRelayClient) IssuePermit(ctx context.Context, permitRequest attachmentv2.PermitRequest) (attachmentv2.Permit, error) {
	body, err := attachmentv2.EncodePermitRequest(permitRequest)
	if err != nil {
		return attachmentv2.Permit{}, fmt.Errorf("encode permit request: %w", err)
	}
	nonce, err := randomNonce()
	if err != nil {
		return attachmentv2.Permit{}, err
	}
	timestamp := time.Now().UTC()
	signed := relay.SignedRequest{MachineID: c.machineID, Method: http.MethodPost, Path: permitIssuancePath, Body: body, Timestamp: timestamp, Nonce: nonce}
	signed.Signature = ed25519.Sign(c.privateKey, relay.CanonicalRequest(signed))
	target := c.baseURL.ResolveReference(&url.URL{Path: permitIssuancePath})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return attachmentv2.Permit{}, fmt.Errorf("build permit request: %w", err)
	}
	request.Header.Set("Content-Type", "application/cbor")
	request.Header.Set("Accept", "application/cbor")
	request.Header.Set("X-Punaro-Machine", signed.MachineID)
	request.Header.Set("X-Punaro-Timestamp", signed.Timestamp.Format(time.RFC3339Nano))
	request.Header.Set("X-Punaro-Nonce", signed.Nonce)
	request.Header.Set("X-Punaro-Signature", base64.RawURLEncoding.EncodeToString(signed.Signature))
	if c.accessToken.ClientID != "" {
		request.Header.Set("CF-Access-Client-Id", c.accessToken.ClientID)
		request.Header.Set("CF-Access-Client-Secret", c.accessToken.ClientSecret)
	}
	client := *c.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return attachmentv2.Permit{}, fmt.Errorf("permit request failed: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/cbor" {
		return attachmentv2.Permit{}, fmt.Errorf("permit request rejected with HTTP %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxPermitResponseBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxPermitResponseBytes {
		return attachmentv2.Permit{}, errors.New("invalid permit response")
	}
	permit, err := attachmentv2.DecodePermit(raw)
	if err != nil {
		return attachmentv2.Permit{}, errors.New("invalid permit response")
	}
	return permit, nil
}

// IssueV3Permit submits an already holder-signed canonical v3 permit request.
// The relay independently authenticates this machine and binds it to the
// request's holder device before it considers the holder signature.
func (c *HTTPRelayClient) IssueV3Permit(ctx context.Context, permitRequest attachmentv3.PermitRequest) (attachmentv3.Permit, error) {
	body, err := attachmentv3.EncodePermitRequest(permitRequest)
	if err != nil {
		return attachmentv3.Permit{}, fmt.Errorf("encode v3 permit request: %w", err)
	}
	raw, err := c.doSignedCBOR(ctx, http.MethodPost, v3PermitIssuancePath, body, "application/cbor", maxPermitResponseBytes)
	if err != nil {
		return attachmentv3.Permit{}, err
	}
	permit, err := attachmentv3.DecodePermit(raw)
	if err != nil {
		return attachmentv3.Permit{}, errors.New("invalid v3 permit response")
	}
	return permit, nil
}

// DoV3Attachment sends one exact permit-bound v3 attachment operation. The
// caller must obtain the operation-specific permit first and construct its
// holder-signed operation record with BuildSignedAttachmentOperation. A relay
// response is either canonical CBOR lifecycle state or, for download, raw
// ciphertext; no response is interpreted as plaintext here.
func (c *HTTPRelayClient) DoV3Attachment(ctx context.Context, method, path string, body []byte, permit attachmentv3.Permit, operation attachmentv3.OperationRecord) ([]byte, error) {
	if len(body) > maxV3AttachmentBody || method == "" || path == "" {
		return nil, errors.New("invalid v3 attachment request")
	}
	permitRaw, err := attachmentv3.EncodePermit(permit)
	if err != nil {
		return nil, errors.New("invalid v3 attachment permit")
	}
	operationRaw, err := attachmentv3.EncodeOperation(operation)
	if err != nil {
		return nil, errors.New("invalid v3 attachment operation")
	}
	route, err := attachmentv3.ParseAttachmentRoute(method, path)
	if err != nil || attachmentv3.VerifyAttachmentRoute(route, permit) != nil {
		return nil, errors.New("invalid v3 attachment route")
	}
	nonce, err := randomNonce()
	if err != nil {
		return nil, err
	}
	timestamp := time.Now().UTC()
	signed := relay.SignedRequest{MachineID: c.machineID, Method: method, Path: path, Body: body, Timestamp: timestamp, Nonce: nonce}
	signed.Signature = ed25519.Sign(c.privateKey, relay.CanonicalRequest(signed))
	target := c.baseURL.ResolveReference(&url.URL{Path: path})
	request, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build v3 attachment request: %w", err)
	}
	request.Header.Set("X-Punaro-Machine", signed.MachineID)
	request.Header.Set("X-Punaro-Timestamp", signed.Timestamp.Format(time.RFC3339Nano))
	request.Header.Set("X-Punaro-Nonce", signed.Nonce)
	request.Header.Set("X-Punaro-Signature", base64.RawURLEncoding.EncodeToString(signed.Signature))
	request.Header.Set("X-Punaro-Attachment-Permit", base64.RawURLEncoding.EncodeToString(permitRaw))
	request.Header.Set("X-Punaro-Attachment-Operation", base64.RawURLEncoding.EncodeToString(operationRaw))
	if len(body) > 0 {
		request.Header.Set("Content-Type", "application/octet-stream")
	}
	if c.accessToken.ClientID != "" {
		request.Header.Set("CF-Access-Client-Id", c.accessToken.ClientID)
		request.Header.Set("CF-Access-Client-Secret", c.accessToken.ClientSecret)
	}
	client := *c.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("v3 attachment request failed: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK || (response.Header.Get("Content-Type") != "application/cbor" && response.Header.Get("Content-Type") != "application/octet-stream") {
		return nil, fmt.Errorf("v3 attachment request rejected with HTTP %d", response.StatusCode)
	}
	maximum := maxV3AttachmentBody
	if response.Header.Get("Content-Type") == "application/cbor" {
		maximum = 256
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(maximum)+1))
	if err != nil || len(raw) == 0 || len(raw) > maximum {
		return nil, errors.New("invalid v3 attachment response")
	}
	return raw, nil
}

// doSignedCBOR is the strict non-redirecting transport primitive shared by
// versioned attachment protocol records. The opaque body is authenticated as
// received; callers still validate its version-specific canonical CBOR.
func (c *HTTPRelayClient) doSignedCBOR(ctx context.Context, method, path string, body []byte, contentType string, maximum int) ([]byte, error) {
	if c == nil || maximum <= 0 || len(body) == 0 || path == "" || contentType != "application/cbor" {
		return nil, errors.New("invalid signed CBOR request")
	}
	nonce, err := randomNonce()
	if err != nil {
		return nil, err
	}
	timestamp := time.Now().UTC()
	signed := relay.SignedRequest{MachineID: c.machineID, Method: method, Path: path, Body: body, Timestamp: timestamp, Nonce: nonce}
	signed.Signature = ed25519.Sign(c.privateKey, relay.CanonicalRequest(signed))
	target := c.baseURL.ResolveReference(&url.URL{Path: path})
	request, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build signed CBOR request: %w", err)
	}
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Accept", contentType)
	request.Header.Set("X-Punaro-Machine", signed.MachineID)
	request.Header.Set("X-Punaro-Timestamp", signed.Timestamp.Format(time.RFC3339Nano))
	request.Header.Set("X-Punaro-Nonce", signed.Nonce)
	request.Header.Set("X-Punaro-Signature", base64.RawURLEncoding.EncodeToString(signed.Signature))
	if c.accessToken.ClientID != "" {
		request.Header.Set("CF-Access-Client-Id", c.accessToken.ClientID)
		request.Header.Set("CF-Access-Client-Secret", c.accessToken.ClientSecret)
	}
	client := *c.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("signed CBOR request failed: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != contentType {
		return nil, fmt.Errorf("signed CBOR request rejected with HTTP %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(maximum)+1))
	if err != nil || len(raw) == 0 || len(raw) > maximum {
		return nil, errors.New("invalid signed CBOR response")
	}
	return raw, nil
}

// FetchDirectorySnapshot retrieves the complete current root-signed directory
// view. It is machine-authenticated in addition to any Cloudflare Access
// policy: directory membership and public-key metadata are not public relay
// content. Callers must still root-verify the returned snapshot before use.
func (c *HTTPRelayClient) FetchDirectorySnapshot(ctx context.Context) (attachmentv2.DirectorySnapshot, error) {
	nonce, err := randomNonce()
	if err != nil {
		return attachmentv2.DirectorySnapshot{}, err
	}
	timestamp := time.Now().UTC()
	signed := relay.SignedRequest{MachineID: c.machineID, Method: http.MethodGet, Path: directorySnapshotPath, Timestamp: timestamp, Nonce: nonce}
	signed.Signature = ed25519.Sign(c.privateKey, relay.CanonicalRequest(signed))
	target := c.baseURL.ResolveReference(&url.URL{Path: directorySnapshotPath})
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return attachmentv2.DirectorySnapshot{}, fmt.Errorf("build directory request: %w", err)
	}
	request.Header.Set("Accept", "application/cbor")
	request.Header.Set("X-Punaro-Machine", signed.MachineID)
	request.Header.Set("X-Punaro-Timestamp", signed.Timestamp.Format(time.RFC3339Nano))
	request.Header.Set("X-Punaro-Nonce", signed.Nonce)
	request.Header.Set("X-Punaro-Signature", base64.RawURLEncoding.EncodeToString(signed.Signature))
	if c.accessToken.ClientID != "" {
		request.Header.Set("CF-Access-Client-Id", c.accessToken.ClientID)
		request.Header.Set("CF-Access-Client-Secret", c.accessToken.ClientSecret)
	}
	client := *c.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return attachmentv2.DirectorySnapshot{}, fmt.Errorf("directory request failed: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/cbor" {
		return attachmentv2.DirectorySnapshot{}, fmt.Errorf("directory rejected request with HTTP %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxDirectorySnapshotBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxDirectorySnapshotBytes {
		return attachmentv2.DirectorySnapshot{}, errors.New("invalid directory response")
	}
	snapshot, err := attachmentv2.DecodeDirectorySnapshot(raw)
	if err != nil {
		return attachmentv2.DirectorySnapshot{}, errors.New("invalid directory response")
	}
	return snapshot, nil
}

// ReadNotifications consumes a signed, content-free wake stream until ctx or
// the connection ends. Durable polling remains authoritative.
func (c *HTTPRelayClient) ReadNotifications(ctx context.Context, receive func(relay.WakeEvent)) error {
	path := "/v1/notifications"
	nonce, err := randomNonce()
	if err != nil {
		return err
	}
	timestamp := time.Now().UTC()
	signed := relay.SignedRequest{MachineID: c.machineID, Method: http.MethodGet, Path: path, Timestamp: timestamp, Nonce: nonce}
	signed.Signature = ed25519.Sign(c.privateKey, relay.CanonicalRequest(signed))
	target := *c.baseURL
	if target.Scheme == "https" {
		target.Scheme = "wss"
	} else {
		target.Scheme = "ws"
	}
	target.Path = path
	headers := http.Header{}
	headers.Set("X-Punaro-Machine", signed.MachineID)
	headers.Set("X-Punaro-Timestamp", signed.Timestamp.Format(time.RFC3339Nano))
	headers.Set("X-Punaro-Nonce", signed.Nonce)
	headers.Set("X-Punaro-Signature", base64.RawURLEncoding.EncodeToString(signed.Signature))
	if c.accessToken.ClientID != "" {
		headers.Set("CF-Access-Client-Id", c.accessToken.ClientID)
		headers.Set("CF-Access-Client-Secret", c.accessToken.ClientSecret)
	}
	connection, response, err := websocket.Dial(ctx, target.String(), &websocket.DialOptions{HTTPHeader: headers, CompressionMode: websocket.CompressionDisabled})
	if response != nil && response.Body != nil {
		defer func() { _ = response.Body.Close() }()
	}
	if err != nil {
		return fmt.Errorf("connect relay notifications: %w", err)
	}
	defer func() { _ = connection.Close(websocket.StatusNormalClosure, "") }()
	for {
		_, data, err := connection.Read(ctx)
		if err != nil {
			if websocket.CloseStatus(err) == websocket.StatusNormalClosure || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read relay notification: %w", err)
		}
		var event relay.WakeEvent
		if err := json.Unmarshal(data, &event); err != nil || event.Type != "wake" || event.TopicID == "" || event.Sequence < 1 {
			return fmt.Errorf("invalid relay notification")
		}
		receive(event)
	}
}

func (c *HTTPRelayClient) doJSON(ctx context.Context, method, path string, requestValue, responseValue any) (int, error) {
	return c.doJSONWithIdempotency(ctx, method, path, requestValue, "", responseValue)
}

func (c *HTTPRelayClient) doJSONWithIdempotency(ctx context.Context, method, path string, requestValue any, idempotencyKey string, responseValue any) (int, error) {
	body, err := json.Marshal(requestValue)
	if err != nil {
		return 0, fmt.Errorf("encode relay request: %w", err)
	}
	nonce, err := randomNonce()
	if err != nil {
		return 0, err
	}
	timestamp := time.Now().UTC()
	signed := relay.SignedRequest{MachineID: c.machineID, Method: method, Path: path, Body: body, Timestamp: timestamp, Nonce: nonce}
	signed.Signature = ed25519.Sign(c.privateKey, relay.CanonicalRequest(signed))
	target := c.baseURL.ResolveReference(&url.URL{Path: path})
	httpRequest, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("build relay request: %w", err)
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("X-Punaro-Machine", signed.MachineID)
	httpRequest.Header.Set("X-Punaro-Timestamp", signed.Timestamp.Format(time.RFC3339Nano))
	httpRequest.Header.Set("X-Punaro-Nonce", signed.Nonce)
	httpRequest.Header.Set("X-Punaro-Signature", base64.RawURLEncoding.EncodeToString(signed.Signature))
	if idempotencyKey != "" {
		httpRequest.Header.Set("Idempotency-Key", idempotencyKey)
	}
	if c.accessToken.ClientID != "" {
		httpRequest.Header.Set("CF-Access-Client-Id", c.accessToken.ClientID)
		httpRequest.Header.Set("CF-Access-Client-Secret", c.accessToken.ClientSecret)
	}
	// Signed relay requests carry machine and, optionally, Access credentials.
	// A redirect is therefore a rejection, never an instruction to replay the
	// opaque body or these headers at a different origin.
	client := *c.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(httpRequest)
	if err != nil {
		return 0, fmt.Errorf("relay request failed: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return response.StatusCode, fmt.Errorf("relay rejected request with HTTP %d", response.StatusCode)
	}
	if responseValue == nil || response.StatusCode == http.StatusNoContent {
		return response.StatusCode, nil
	}
	limited := io.LimitReader(response.Body, maxRelayResponseBytes+1)
	decoder := json.NewDecoder(limited)
	if err := decoder.Decode(responseValue); err != nil {
		return response.StatusCode, fmt.Errorf("decode relay response: %w", err)
	}
	return response.StatusCode, nil
}

const maxRelayResponseBytes = 128 << 10

func randomNonce() (string, error) {
	value := make([]byte, 24)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate request nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
