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
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
	attachmentv2 "github.com/rock3r/punaro/internal/attachment/v2"
	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
	"github.com/rock3r/punaro/internal/clienttransport"
	"github.com/rock3r/punaro/internal/relay"
)

// AccessServiceToken holds the two headers required for Cloudflare Access
// service-token authentication. Callers must provide both fields or neither.
type AccessServiceToken struct {
	ClientID     string
	ClientSecret string
}

// DoctorProbeResult contains only stable reachability decisions. It never
// carries provider response text, URLs, credentials, or response bodies.
type DoctorProbeResult struct {
	Transport        bool
	Origin           bool
	Access           bool
	Enrolled         bool
	Protocol         bool
	Attached         bool
	AttachmentsKnown bool
	ActiveEndpoints  int
	ExpiredEndpoints int
	ActiveRoles      int
	ExpiredRoles     int
}

// OpenAccessSession validates and copies the HTTP client used to reach a
// Cloudflare Access-protected origin. Service-token policies authenticate each
// protected request from its headers, so this deliberately does not establish
// or retain a browser authorization-cookie session.
func OpenAccessSession(ctx context.Context, rawURL string, client *http.Client, token AccessServiceToken) (*http.Client, error) {
	return OpenAccessSessionWithPolicy(ctx, rawURL, client, token, clienttransport.Policy{})
}

// OpenAccessSessionWithPolicy applies the same explicit trusted-LAN transport
// boundary used by the long-running relay client.
func OpenAccessSessionWithPolicy(_ context.Context, rawURL string, client *http.Client, token AccessServiceToken, policy clienttransport.Policy) (*http.Client, error) {
	baseURL, err := clienttransport.ValidateOrigin(rawURL, policy)
	if err != nil {
		return nil, fmt.Errorf("invalid relay URL")
	}
	if (token.ClientID == "") != (token.ClientSecret == "") {
		return nil, fmt.Errorf("cloudflare Access service token must contain both ID and secret")
	}
	if token.ClientID != "" && baseURL.Scheme != "https" && !loopbackHost(baseURL.Hostname()) {
		return nil, fmt.Errorf("cloudflare Access service token requires HTTPS")
	}
	hardened, err := clienttransport.HardenClient(client, rawURL, policy)
	if err != nil {
		return nil, fmt.Errorf("invalid relay URL")
	}
	clientCopy := *hardened
	// Service-token policies authenticate each protected request from its
	// headers. They do not necessarily mint a browser cookie, so probing a
	// relay-only path for CF_Authorization would reject valid admission before
	// the caller can make its authenticated request.
	if token.ClientID != "" {
		clientCopy.Jar = nil
	}
	return &clientCopy, nil
}

// HTTPRelayClient is the signed HTTPS client used by one enrolled adapter.
type HTTPRelayClient struct {
	baseURL       *url.URL
	machineID     string
	privateKey    ed25519.PrivateKey
	credential    string
	httpClient    *http.Client
	consumerID    string
	accessToken   AccessServiceToken
	requireAccess bool
}

type relayHTTPStatusError struct {
	status int
	err    error
}

type relayRejectionError struct {
	status    int
	confirmed bool
}

func (e *relayRejectionError) Error() string {
	return fmt.Sprintf("relay rejected request with HTTP %d", e.status)
}

func (e *relayHTTPStatusError) Error() string { return e.err.Error() }
func (e *relayHTTPStatusError) Unwrap() error { return e.err }

// PermanentOfferNoticeFailure is true only for append-route responses whose
// handler rejects before any message or idempotency row can be created.
func (e *relayHTTPStatusError) PermanentOfferNoticeFailure() bool {
	return e.PermanentRelayFailure()
}

// PermanentRelayFailure reports signed relay rejections that happened before
// an inbound message or idempotency row could be created.
func (e *relayHTTPStatusError) PermanentRelayFailure() bool {
	if e == nil || e.status != http.StatusForbidden && e.status != http.StatusNotFound {
		return false
	}
	var rejection *relayRejectionError
	return errors.As(e.err, &rejection) && rejection.confirmed
}

// RelayHTTPStatus reports the HTTP status carried by a signed relay error.
func RelayHTTPStatus(err error) int {
	var status *relayHTTPStatusError
	if errors.As(err, &status) {
		return status.status
	}
	return 0
}

// NewHTTPRelayClient validates and creates a signed client for one machine.
func NewHTTPRelayClient(rawURL, machineID string, privateKey ed25519.PrivateKey, client *http.Client, accessToken AccessServiceToken) (*HTTPRelayClient, error) {
	return NewHTTPRelayClientWithPolicy(rawURL, machineID, privateKey, client, accessToken, clienttransport.Policy{})
}

// NewHTTPRelayClientWithPolicy creates a signed client with an explicit
// client-side trusted-LAN plaintext boundary when requested.
func NewHTTPRelayClientWithPolicy(rawURL, machineID string, privateKey ed25519.PrivateKey, client *http.Client, accessToken AccessServiceToken, policy clienttransport.Policy) (*HTTPRelayClient, error) {
	return newHTTPRelayClientWithPolicy(rawURL, machineID, privateKey, "", client, accessToken, policy)
}

// NewDeviceHTTPRelayClientWithPolicy creates a bearer-authenticated relay
// client for one legacy identity that completed device-credential migration.
func NewDeviceHTTPRelayClientWithPolicy(rawURL, machineID, credential string, client *http.Client, accessToken AccessServiceToken, policy clienttransport.Policy) (*HTTPRelayClient, error) {
	return newHTTPRelayClientWithPolicy(rawURL, machineID, nil, credential, client, accessToken, policy)
}

func newHTTPRelayClientWithPolicy(rawURL, machineID string, privateKey ed25519.PrivateKey, credential string, client *http.Client, accessToken AccessServiceToken, policy clienttransport.Policy) (*HTTPRelayClient, error) {
	baseURL, err := clienttransport.ValidateOrigin(rawURL, policy)
	if err != nil {
		return nil, fmt.Errorf("invalid relay URL")
	}
	validCredential := credential != "" && credential == strings.TrimSpace(credential) && len(credential) <= 1024 && !strings.ContainsAny(credential, "\r\n\x00")
	validPrivateKey := len(privateKey) == ed25519.PrivateKeySize
	if strings.TrimSpace(machineID) == "" || (validPrivateKey && validCredential) || (!validPrivateKey && !validCredential) || (!validPrivateKey && len(privateKey) != 0) {
		return nil, fmt.Errorf("machine ID and exactly one relay credential are required")
	}
	if (accessToken.ClientID == "") != (accessToken.ClientSecret == "") {
		return nil, fmt.Errorf("cloudflare Access service token must contain both ID and secret")
	}
	if accessToken.ClientID != "" && baseURL.Scheme != "https" && !loopbackHost(baseURL.Hostname()) {
		return nil, fmt.Errorf("cloudflare Access service token requires HTTPS")
	}
	hardened, err := clienttransport.HardenClient(client, rawURL, policy)
	if err != nil {
		return nil, fmt.Errorf("invalid relay URL")
	}
	clientCopy := *hardened
	consumerID, err := randomConsumerID()
	if err != nil {
		return nil, fmt.Errorf("create relay consumer identity: %w", err)
	}
	// A Service Auth policy authenticates every request from the service-token
	// headers below. Never combine those credentials with a browser
	// CF_Authorization cookie: Cloudflare can reject that mixed identity before
	// the signed relay request reaches the origin.
	if accessToken.ClientID != "" {
		clientCopy.Jar = nil
	}
	result := &HTTPRelayClient{baseURL: baseURL, machineID: machineID, privateKey: append(ed25519.PrivateKey(nil), privateKey...), credential: credential, httpClient: &clientCopy, consumerID: consumerID, accessToken: accessToken, requireAccess: requiresAccessAdmission(baseURL)}
	return result, nil
}

func (c *HTTPRelayClient) authenticateRequest(request *http.Request, method, path string, body []byte) (string, error) {
	if c == nil || request == nil {
		return "", errors.New("relay client is unavailable")
	}
	nonce, err := randomNonce()
	if err != nil {
		return "", err
	}
	if c.credential != "" {
		request.Header.Set("Authorization", "Bearer "+c.credential)
		request.Header.Set(relay.RequestCorrelationHeader, nonce)
		return nonce, nil
	}
	timestamp := time.Now().UTC()
	signed := relay.SignedRequest{MachineID: c.machineID, Method: method, Path: path, Body: body, Timestamp: timestamp, Nonce: nonce}
	signed.Signature = ed25519.Sign(c.privateKey, relay.CanonicalRequest(signed))
	request.Header.Set("X-Punaro-Machine", signed.MachineID)
	request.Header.Set("X-Punaro-Timestamp", signed.Timestamp.Format(time.RFC3339Nano))
	request.Header.Set("X-Punaro-Nonce", signed.Nonce)
	request.Header.Set("X-Punaro-Signature", base64.RawURLEncoding.EncodeToString(signed.Signature))
	return nonce, nil
}

func (c *HTTPRelayClient) authenticationHeaders(method, path string, body []byte) (http.Header, string, error) {
	request, err := http.NewRequestWithContext(context.Background(), method, "http://punaro.invalid", nil)
	if err != nil {
		return nil, "", err
	}
	nonce, err := c.authenticateRequest(request, method, path, body)
	return request.Header, nonce, err
}

func requiresAccessAdmission(baseURL *url.URL) bool {
	return baseURL != nil && baseURL.Scheme == "https" && !loopbackHost(baseURL.Hostname())
}

// Doctor performs the signed, non-mutating relay reachability probe. A nonce
// echo is required before interpreting an HTTP status as a Punaro-origin
// result; intermediary rejections therefore cannot masquerade as enrollment
// or protocol failures.
func (c *HTTPRelayClient) Doctor(ctx context.Context) (DoctorProbeResult, error) {
	return c.doctor(ctx, "")
}

// DoctorEndpoint adds a read-only durable attachment assertion for one exact
// endpoint already authorized to this enrolled machine.
func (c *HTTPRelayClient) DoctorEndpoint(ctx context.Context, endpoint string) (DoctorProbeResult, error) {
	if !relay.ValidEndpoint(endpoint) {
		return DoctorProbeResult{}, errors.New("relay doctor endpoint is invalid")
	}
	return c.doctor(ctx, endpoint)
}

func (c *HTTPRelayClient) doctor(ctx context.Context, endpoint string) (DoctorProbeResult, error) {
	if c == nil || c.httpClient == nil || c.baseURL == nil {
		return DoctorProbeResult{}, errors.New("relay doctor client is unavailable")
	}
	target := c.baseURL.ResolveReference(&url.URL{Path: relay.DoctorPath})
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, target.String(), nil)
	if err != nil {
		return DoctorProbeResult{}, errors.New("build relay doctor request")
	}
	nonce, err := c.authenticateRequest(request, http.MethodHead, relay.DoctorPath, []byte(endpoint))
	if err != nil {
		return DoctorProbeResult{}, err
	}
	if endpoint != "" {
		request.Header.Set(relay.DoctorEndpointHeader, endpoint)
	}
	if c.accessToken.ClientID != "" {
		request.Header.Set("CF-Access-Client-Id", c.accessToken.ClientID)
		request.Header.Set("CF-Access-Client-Secret", c.accessToken.ClientSecret)
	}
	c.addAccessCookies(request.Header)
	client := *c.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return DoctorProbeResult{}, errors.New("relay doctor transport failed")
	}
	defer func() { _ = response.Body.Close() }()
	result := DoctorProbeResult{Transport: true}
	responseNonces := response.Header.Values(relay.ResponseNonceHeader)
	if len(responseNonces) != 1 || responseNonces[0] != nonce {
		return result, errors.New("relay doctor origin was not confirmed")
	}
	result.Origin = true
	if (c.requireAccess || c.accessToken.ClientID != "") && (c.accessToken.ClientID == "" || !c.doctorAccessIsEnforced(ctx, endpoint)) {
		return result, errors.New("relay doctor Access admission was not enforced")
	}
	result.Access = true
	if response.StatusCode != http.StatusNoContent {
		return result, errors.New("relay doctor authorization failed")
	}
	result.Enrolled = true
	protocols := response.Header.Values(relay.ProtocolHeader)
	if len(protocols) != 1 || protocols[0] != strconv.Itoa(relay.ProtocolVersion) {
		return result, errors.New("relay doctor protocol is incompatible")
	}
	result.Protocol = true
	if activeEndpoints, ok := parseDoctorCountHeader(response.Header, relay.DoctorActiveEndpointsHeader); ok {
		expiredEndpoints, endpointsOK := parseDoctorCountHeader(response.Header, relay.DoctorExpiredEndpointsHeader)
		activeRoles, activeRolesOK := parseDoctorCountHeader(response.Header, relay.DoctorActiveRolesHeader)
		expiredRoles, expiredRolesOK := parseDoctorCountHeader(response.Header, relay.DoctorExpiredRolesHeader)
		if endpointsOK && activeRolesOK && expiredRolesOK {
			result.AttachmentsKnown = true
			result.ActiveEndpoints, result.ExpiredEndpoints = activeEndpoints, expiredEndpoints
			result.ActiveRoles, result.ExpiredRoles = activeRoles, expiredRoles
			result.Attached = activeEndpoints > 0
		}
	}
	if endpoint != "" {
		result.Attached = response.Header.Get(relay.DoctorAttachmentHeader) == "true"
	}
	return result, nil
}

func (c *HTTPRelayClient) doctorAccessIsEnforced(ctx context.Context, endpoint string) bool {
	target := c.baseURL.ResolveReference(&url.URL{Path: relay.DoctorPath})
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, target.String(), nil)
	if err != nil {
		return false
	}
	nonce, err := c.authenticateRequest(request, http.MethodHead, relay.DoctorPath, []byte(endpoint))
	if err != nil {
		return false
	}
	if endpoint != "" {
		request.Header.Set(relay.DoctorEndpointHeader, endpoint)
	}
	client := *c.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	defer func() { _ = response.Body.Close() }()
	responseNonces := response.Header.Values(relay.ResponseNonceHeader)
	if len(responseNonces) == 1 && responseNonces[0] == nonce {
		return false
	}
	return accessRejectionStatus(response.StatusCode)
}

func accessRejectionStatus(status int) bool {
	return status >= http.StatusMultipleChoices && status < http.StatusBadRequest || status == http.StatusUnauthorized || status == http.StatusForbidden
}

func parseDoctorCountHeader(header http.Header, name string) (int, bool) {
	values := header.Values(name)
	if len(values) != 1 {
		return 0, false
	}
	value, err := strconv.Atoi(values[0])
	return value, err == nil && value >= 0 && value <= 10000
}

// DoctorNotifications performs only the signed WebSocket upgrade handshake on
// the dedicated doctor route. It does not register for, read, or acknowledge
// notification events and does not consume a durable request nonce.
func (c *HTTPRelayClient) DoctorNotifications(ctx context.Context) (DoctorProbeResult, error) {
	if c == nil || c.httpClient == nil || c.baseURL == nil {
		return DoctorProbeResult{}, errors.New("relay notification doctor client is unavailable")
	}
	connection, response, nonce, dialErr := c.openDoctorNotification(ctx, true)
	if response != nil && response.Body != nil {
		defer func() { _ = response.Body.Close() }()
	}
	if response == nil {
		return DoctorProbeResult{}, errors.New("relay notification doctor transport failed")
	}
	result := DoctorProbeResult{Transport: true}
	responseNonces := response.Header.Values(relay.ResponseNonceHeader)
	if len(responseNonces) != 1 || responseNonces[0] != nonce {
		if connection != nil {
			_ = connection.CloseNow()
		}
		return result, errors.New("relay notification doctor origin was not confirmed")
	}
	result.Origin = true
	if (c.requireAccess || c.accessToken.ClientID != "") && (c.accessToken.ClientID == "" || !c.doctorNotificationAccessIsEnforced(ctx)) {
		if connection != nil {
			_ = connection.CloseNow()
		}
		return result, errors.New("relay notification doctor Access admission was not enforced")
	}
	result.Access = true
	if dialErr != nil || connection == nil || response.StatusCode != http.StatusSwitchingProtocols {
		if connection != nil {
			_ = connection.CloseNow()
		}
		return result, errors.New("relay notification doctor authorization failed")
	}
	result.Enrolled = true
	protocols := response.Header.Values(relay.ProtocolHeader)
	if len(protocols) != 1 || protocols[0] != strconv.Itoa(relay.ProtocolVersion) {
		_ = connection.CloseNow()
		return result, errors.New("relay notification doctor protocol is incompatible")
	}
	result.Protocol = true
	_ = connection.Close(websocket.StatusNormalClosure, "")
	return result, nil
}

func (c *HTTPRelayClient) openDoctorNotification(ctx context.Context, includeAccess bool) (*websocket.Conn, *http.Response, string, error) {
	headers, nonce, err := c.authenticationHeaders(http.MethodGet, relay.DoctorNotificationsPath, nil)
	if err != nil {
		return nil, nil, "", err
	}
	target := *c.baseURL
	if target.Scheme == "https" {
		target.Scheme = "wss"
	} else {
		target.Scheme = "ws"
	}
	target.Path = relay.DoctorNotificationsPath
	if includeAccess && c.accessToken.ClientID != "" {
		headers.Set("CF-Access-Client-Id", c.accessToken.ClientID)
		headers.Set("CF-Access-Client-Secret", c.accessToken.ClientSecret)
	}
	if includeAccess {
		c.addAccessCookies(headers)
	}
	client := *c.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	connection, response, dialErr := websocket.Dial(ctx, target.String(), &websocket.DialOptions{HTTPClient: &client, HTTPHeader: headers, CompressionMode: websocket.CompressionDisabled})
	return connection, response, nonce, dialErr
}

func (c *HTTPRelayClient) doctorNotificationAccessIsEnforced(ctx context.Context) bool {
	connection, response, nonce, _ := c.openDoctorNotification(ctx, false)
	if connection != nil {
		_ = connection.CloseNow()
	}
	if response == nil {
		return false
	}
	if response.Body != nil {
		defer func() { _ = response.Body.Close() }()
	}
	responseNonces := response.Header.Values(relay.ResponseNonceHeader)
	if len(responseNonces) == 1 && responseNonces[0] == nonce {
		return false
	}
	return accessRejectionStatus(response.StatusCode)
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
	_, err := c.doJSON(ctx, http.MethodPost, "/v1/deliveries/lease", map[string]any{"endpoint": endpoint, "consumer_id": c.consumerID}, &response)
	return response.Deliveries, err
}

// BindRole renewably connects one durable role to a currently advertised local
// session. The relay verifies both the role's configured machine owner and the
// session attachment. Advertisements renew a binding only while they retain
// that exact live session generation; a new or reclaimed session must bind.
func (c *HTTPRelayClient) BindRole(ctx context.Context, role, sessionEndpoint string) error {
	if !relay.ValidRole(role) || !relay.ValidEndpoint(sessionEndpoint) {
		return fmt.Errorf("role and session endpoint are required")
	}
	_, err := c.doJSON(ctx, http.MethodPost, "/v1/roles/bindings", map[string]any{"role": role, "session_endpoint": sessionEndpoint}, nil)
	return err
}

// RegisterRole creates or updates one machine-owned canonical role profile.
// The authenticated machine is the owner; callers never send a machine field.
func (c *HTTPRelayClient) RegisterRole(ctx context.Context, role, displayName string, directAddressable bool, idempotencyKey string) (relay.RoleProfile, error) {
	if !relay.CanonicalRoleHandle(role) || !relay.ValidRequestToken(idempotencyKey) {
		return relay.RoleProfile{}, fmt.Errorf("canonical role and idempotency key are required")
	}
	request := map[string]any{"role": role, "direct_addressable": directAddressable}
	if displayName != "" {
		request["display_name"] = displayName
	}
	var profile relay.RoleProfile
	_, err := c.doJSONWithIdempotency(ctx, http.MethodPost, "/v1/roles/register", request, idempotencyKey, &profile)
	return profile, err
}

// ListRoles returns one bounded page of opted-in public roles.
func (c *HTTPRelayClient) ListRoles(ctx context.Context, cursor string, limit int) (relay.RoleListPage, error) {
	if limit == 0 {
		limit = relay.DefaultRoleListLimit
	}
	var page relay.RoleListPage
	_, err := c.doJSON(ctx, http.MethodPost, "/v1/roles/list", map[string]any{"cursor": cursor, "limit": limit}, &page)
	if page.Roles == nil {
		page.Roles = []relay.RoleContact{}
	}
	return page, err
}

// ResolveRole answers one public name. Ambiguity and not-found are result
// statuses, not guessed targets.
func (c *HTTPRelayClient) ResolveRole(ctx context.Context, name string) (relay.RoleResolveResult, error) {
	var result relay.RoleResolveResult
	status, err := c.doJSONAllowing(ctx, http.MethodPost, "/v1/roles/resolve", map[string]any{"name": name}, &result, http.StatusOK, http.StatusNotFound, http.StatusConflict)
	if err != nil {
		return relay.RoleResolveResult{}, err
	}
	switch status {
	case http.StatusNotFound:
		result.Status = relay.RoleResolveNotFound
	case http.StatusConflict:
		if result.Status == "" {
			result.Status = relay.RoleResolveAmbiguous
		}
	case http.StatusOK:
		if result.Status == "" {
			result.Status = relay.RoleResolveResolved
		}
	}
	return result, nil
}

// LeaseInvocations obtains content-free, server-authorized local runtime work.
func (c *HTTPRelayClient) LeaseInvocations(ctx context.Context) ([]relay.Invocation, error) {
	var response struct {
		Invocations []relay.Invocation `json:"invocations"`
	}
	// A runtime handoff can take the full invocation timeout. Claim only one
	// record per sync so queued work never burns leases while waiting locally.
	_, err := c.doJSON(ctx, http.MethodPost, "/v1/invocations/lease", map[string]any{"consumer_id": c.consumerID, "limit": 1}, &response)
	return response.Invocations, err
}

// ReportInvocation records the host-local runtime outcome using the relay
// lease fence. A failed report leaves the durable handoff for retry.
func (c *HTTPRelayClient) ReportInvocation(ctx context.Context, invocation relay.Invocation, accepted bool) error {
	if strings.TrimSpace(invocation.ID) == "" || !relay.ValidRequestToken(invocation.LeaseToken) || invocation.LeaseGeneration < 1 {
		return fmt.Errorf("invocation lease is required")
	}
	_, err := c.doJSON(ctx, http.MethodPost, "/v1/invocations/"+url.PathEscape(invocation.ID)+"/outcome", map[string]any{"lease_token": invocation.LeaseToken, "lease_generation": invocation.LeaseGeneration, "accepted": accepted}, nil)
	return err
}

// CreateConversation bootstraps an explicit, membership-scoped room from an
// attached local endpoint. The relay still verifies endpoint ownership.
func (c *HTTPRelayClient) CreateConversation(ctx context.Context, creator string, members []relay.Member, displayName, idempotencyKey string) (relay.Conversation, error) {
	if strings.TrimSpace(creator) == "" || len(members) == 0 || strings.TrimSpace(idempotencyKey) == "" {
		return relay.Conversation{}, fmt.Errorf("creator, members, and idempotency key are required")
	}
	encoded := make([]map[string]any, 0, len(members))
	for _, member := range members {
		encodedMember := map[string]any{"capabilities": capabilityNames(member.Capabilities)}
		if member.Role != "" {
			encodedMember["role"] = member.Role
			encodedMember["role_machine_id"] = member.RoleMachineID
		} else {
			encodedMember["endpoint"] = member.Endpoint
		}
		encoded = append(encoded, encodedMember)
	}
	request := map[string]any{"creator_endpoint": creator, "members": encoded}
	if displayName != "" {
		request["display_name"] = displayName
	}
	var conversation relay.Conversation
	_, err := c.doJSONWithIdempotency(ctx, http.MethodPost, "/v1/conversations", request, idempotencyKey, &conversation)
	return conversation, err
}

// ClaimConversation reserves a Telegram claim for a named conversation.
func (c *HTTPRelayClient) ClaimConversation(ctx context.Context, conversationID, endpoint, idempotencyKey string) (relay.TelegramClaim, error) {
	if strings.TrimSpace(conversationID) == "" || strings.TrimSpace(endpoint) == "" || strings.TrimSpace(idempotencyKey) == "" {
		return relay.TelegramClaim{}, fmt.Errorf("conversation, endpoint, and idempotency key are required")
	}
	var claim relay.TelegramClaim
	status, err := c.doJSONWithIdempotency(ctx, http.MethodPost, "/v1/conversations/"+url.PathEscape(conversationID)+"/telegram-claim", map[string]any{"endpoint": endpoint}, idempotencyKey, &claim)
	if err != nil {
		return relay.TelegramClaim{}, &relayHTTPStatusError{status: status, err: err}
	}
	return claim, nil
}

// CompleteTelegramClaim finishes a reserved claim as the live telegram/primary owner.
func (c *HTTPRelayClient) CompleteTelegramClaim(ctx context.Context, conversationID string) (relay.TelegramClaim, error) {
	if strings.TrimSpace(conversationID) == "" {
		return relay.TelegramClaim{}, fmt.Errorf("conversation is required")
	}
	var claim relay.TelegramClaim
	_, err := c.doJSON(ctx, http.MethodPost, "/v1/conversations/"+url.PathEscape(conversationID)+"/telegram-claim/complete", map[string]any{}, &claim)
	return claim, err
}

// PendingTelegramClaims polls pending claim reservations. It is not a lease.
func (c *HTTPRelayClient) PendingTelegramClaims(ctx context.Context, limit int, after string) ([]relay.TelegramClaim, error) {
	if limit < 1 {
		limit = 1
	}
	var response struct {
		Claims []relay.TelegramClaim `json:"claims"`
	}
	_, err := c.doJSON(ctx, http.MethodPost, "/v1/telegram/claims/pending", map[string]any{"limit": limit, "after": after}, &response)
	return response.Claims, err
}

// ListUnclaimed returns the last named rooms without a completed claim.
func (c *HTTPRelayClient) ListUnclaimed(ctx context.Context) ([]relay.UnclaimedTopic, error) {
	var response struct {
		Topics []relay.UnclaimedTopic `json:"topics"`
	}
	_, err := c.doJSON(ctx, http.MethodGet, "/v1/telegram/unclaimed", map[string]any{}, &response)
	return response.Topics, err
}

// GetSessionTopic returns the live endpoint's sole named or claimed occupancy.
func (c *HTTPRelayClient) GetSessionTopic(ctx context.Context, endpoint string) (relay.SessionTopic, error) {
	if strings.TrimSpace(endpoint) == "" {
		return relay.SessionTopic{}, fmt.Errorf("endpoint is required")
	}
	var topic relay.SessionTopic
	status, err := c.doJSON(ctx, http.MethodPost, "/v1/sessions/topic", map[string]any{"endpoint": endpoint}, &topic)
	if err != nil {
		return relay.SessionTopic{}, &relayHTTPStatusError{status: status, err: err}
	}
	return topic, nil
}

// SendTelegramInbound submits gateway inbound mail plus inert reply metadata.
func (c *HTTPRelayClient) SendTelegramInbound(ctx context.Context, conversationID, fromEndpoint, fromParticipant, body, inReplyToMessageID, inReplyToEndpoint string, telegramThreadID int64, idempotencyKey string) (relay.Message, error) {
	if strings.TrimSpace(conversationID) == "" || strings.TrimSpace(fromEndpoint) == "" || strings.TrimSpace(fromParticipant) == "" || strings.TrimSpace(idempotencyKey) == "" {
		return relay.Message{}, fmt.Errorf("conversation, sender, participant, and idempotency key are required")
	}
	request := map[string]any{"from_endpoint": fromEndpoint, "from_participant": fromParticipant, "body": body}
	if inReplyToMessageID != "" {
		request["in_reply_to_punaro_message_id"] = inReplyToMessageID
	}
	if inReplyToEndpoint != "" {
		request["in_reply_to_endpoint"] = inReplyToEndpoint
	}
	if telegramThreadID != 0 {
		request["telegram_thread_id"] = telegramThreadID
	}
	var message relay.Message
	status, err := c.doJSONWithIdempotency(ctx, http.MethodPost, "/v1/conversations/"+url.PathEscape(conversationID)+"/telegram-inbound", request, idempotencyKey, &message)
	if err != nil {
		return relay.Message{}, &relayHTTPStatusError{status: status, err: err}
	}
	return message, nil
}

// SetConversationDisplayName renames a room through a live admin session.
func (c *HTTPRelayClient) SetConversationDisplayName(ctx context.Context, conversationID, actor, displayName, idempotencyKey string) (relay.Conversation, error) {
	if strings.TrimSpace(conversationID) == "" || strings.TrimSpace(actor) == "" || strings.TrimSpace(displayName) == "" || strings.TrimSpace(idempotencyKey) == "" {
		return relay.Conversation{}, fmt.Errorf("conversation, actor, display name, and idempotency key are required")
	}
	var conversation relay.Conversation
	_, err := c.doJSONWithIdempotency(ctx, http.MethodPost, "/v1/conversations/"+url.PathEscape(conversationID)+"/display-name", map[string]any{"actor_endpoint": actor, "display_name": displayName}, idempotencyKey, &conversation)
	return conversation, err
}

// ControlMembership sends a typed membership control record. It never routes
// through Send, so local agents can keep all delivery bodies inert.
func (c *HTTPRelayClient) ControlMembership(ctx context.Context, conversationID, actor string, operation relay.ControlOperation, member relay.Member, idempotencyKey string) (relay.ControlEvent, error) {
	if strings.TrimSpace(conversationID) == "" || strings.TrimSpace(actor) == "" || strings.TrimSpace(member.Endpoint) == "" || strings.TrimSpace(idempotencyKey) == "" {
		return relay.ControlEvent{}, fmt.Errorf("conversation, actor, member, and idempotency key are required")
	}
	request := map[string]any{"actor_endpoint": actor, "operation": operation, "member": map[string]any{"endpoint": member.Endpoint}}
	if operation == relay.ControlUpsertMember {
		request["member"].(map[string]any)["capabilities"] = capabilityNames(member.Capabilities)
	}
	var event relay.ControlEvent
	_, err := c.doJSONWithIdempotency(ctx, http.MethodPost, "/v1/conversations/"+url.PathEscape(conversationID)+"/controls", request, idempotencyKey, &event)
	return event, err
}

// ControlAudit reads the bounded, content-free control history as a current
// admin endpoint; it is separate from message deliveries and their bodies.
func (c *HTTPRelayClient) ControlAudit(ctx context.Context, conversationID, actor string) ([]relay.ControlEvent, error) {
	var response struct {
		Events []relay.ControlEvent `json:"events"`
	}
	_, err := c.doJSON(ctx, http.MethodPost, "/v1/conversations/"+url.PathEscape(conversationID)+"/controls/audit", map[string]any{"actor_endpoint": actor}, &response)
	return response.Events, err
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
	if capabilities&relay.CapInvoke != 0 {
		result = append(result, "invoke")
	}
	return result
}

// Send appends an opaque local-agent reply to an existing conversation. The
// idempotency key belongs to the caller's retry domain and is never derived
// from the body or a machine credential.
func (c *HTTPRelayClient) Send(ctx context.Context, conversationID, fromEndpoint, body, idempotencyKey string) (relay.Message, error) {
	return c.send(ctx, conversationID, fromEndpoint, "", body, idempotencyKey)
}

// SendToRole appends a message whose durable delivery is restricted to one
// receiving role membership. An empty role is never accepted here; callers
// that need the compatible broadcast behavior must use Send.
func (c *HTTPRelayClient) SendToRole(ctx context.Context, conversationID, fromEndpoint, targetRole, body, idempotencyKey string) (relay.Message, error) {
	if !relay.ValidRole(targetRole) {
		return relay.Message{}, fmt.Errorf("target role is required")
	}
	return c.send(ctx, conversationID, fromEndpoint, targetRole, body, idempotencyKey)
}

// SendDirectMessage creates or reuses the unique opted-in role conversation and
// appends one targeted body. The caller supplies canonical directory handles.
func (c *HTTPRelayClient) SendDirectMessage(ctx context.Context, fromRole, toRole, body, idempotencyKey string) (relay.Message, error) {
	if !relay.CanonicalRoleHandle(fromRole) || !relay.CanonicalRoleHandle(toRole) || !relay.ValidRequestToken(idempotencyKey) {
		return relay.Message{}, fmt.Errorf("canonical roles and idempotency key are required")
	}
	var message relay.Message
	_, err := c.doJSONWithIdempotency(ctx, http.MethodPost, "/v1/direct-messages", map[string]any{"from_role": fromRole, "to_role": toRole, "body": body}, idempotencyKey, &message)
	return message, err
}

func (c *HTTPRelayClient) send(ctx context.Context, conversationID, fromEndpoint, targetRole, body, idempotencyKey string) (relay.Message, error) {
	if strings.TrimSpace(conversationID) == "" || strings.TrimSpace(fromEndpoint) == "" || strings.TrimSpace(idempotencyKey) == "" {
		return relay.Message{}, fmt.Errorf("conversation, sender endpoint, and idempotency key are required")
	}
	var message relay.Message
	request := map[string]any{"from_endpoint": fromEndpoint, "body": body}
	if targetRole != "" {
		request["target_role"] = targetRole
	}
	status, err := c.doJSONWithIdempotency(ctx, http.MethodPost, "/v1/conversations/"+url.PathEscape(conversationID)+"/messages", request, idempotencyKey, &message)
	if err != nil {
		return message, &relayHTTPStatusError{status: status, err: err}
	}
	return message, nil
}

// Invoke requests a body-free server-authorized handoff for an offline
// receiving member. The target machine and pending work are derived server-side.
func (c *HTTPRelayClient) Invoke(ctx context.Context, conversationID, fromEndpoint, targetEndpoint, idempotencyKey string) (relay.Invocation, error) {
	if strings.TrimSpace(conversationID) == "" || strings.TrimSpace(fromEndpoint) == "" || strings.TrimSpace(targetEndpoint) == "" || strings.TrimSpace(idempotencyKey) == "" {
		return relay.Invocation{}, fmt.Errorf("conversation, invoking endpoint, target endpoint, and idempotency key are required")
	}
	var invocation relay.Invocation
	_, err := c.doJSONWithIdempotency(ctx, http.MethodPost, "/v1/conversations/"+url.PathEscape(conversationID)+"/invocations", map[string]any{"from_endpoint": fromEndpoint, "target_endpoint": targetEndpoint}, idempotencyKey, &invocation)
	return invocation, err
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
	target := c.baseURL.ResolveReference(&url.URL{Path: permitIssuancePath})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return attachmentv2.Permit{}, fmt.Errorf("build permit request: %w", err)
	}
	request.Header.Set("Content-Type", "application/cbor")
	request.Header.Set("Accept", "application/cbor")
	if _, err := c.authenticateRequest(request, http.MethodPost, permitIssuancePath, body); err != nil {
		return attachmentv2.Permit{}, err
	}
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
	target := c.baseURL.ResolveReference(&url.URL{Path: path})
	request, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build v3 attachment request: %w", err)
	}
	if _, err := c.authenticateRequest(request, method, path, body); err != nil {
		return nil, err
	}
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
	target := c.baseURL.ResolveReference(&url.URL{Path: path})
	request, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build signed CBOR request: %w", err)
	}
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Accept", contentType)
	if _, err := c.authenticateRequest(request, method, path, body); err != nil {
		return nil, err
	}
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
	target := c.baseURL.ResolveReference(&url.URL{Path: directorySnapshotPath})
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return attachmentv2.DirectorySnapshot{}, fmt.Errorf("build directory request: %w", err)
	}
	request.Header.Set("Accept", "application/cbor")
	if _, err := c.authenticateRequest(request, http.MethodGet, directorySnapshotPath, nil); err != nil {
		return attachmentv2.DirectorySnapshot{}, err
	}
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
	headers, _, err := c.authenticationHeaders(http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	target := *c.baseURL
	if target.Scheme == "https" {
		target.Scheme = "wss"
	} else {
		target.Scheme = "ws"
	}
	target.Path = path
	if c.accessToken.ClientID != "" {
		headers.Set("CF-Access-Client-Id", c.accessToken.ClientID)
		headers.Set("CF-Access-Client-Secret", c.accessToken.ClientSecret)
	}
	c.addAccessCookies(headers)
	connection, response, err := websocket.Dial(ctx, target.String(), &websocket.DialOptions{HTTPClient: c.httpClient, HTTPHeader: headers, CompressionMode: websocket.CompressionDisabled})
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

func (c *HTTPRelayClient) addAccessCookies(headers http.Header) {
	if c == nil || c.accessToken.ClientID != "" || c.httpClient == nil || c.httpClient.Jar == nil {
		return
	}
	for _, cookie := range c.httpClient.Jar.Cookies(c.baseURL) {
		headers.Add("Cookie", cookie.Name+"="+cookie.Value)
	}
}

const maxFleetReleaseBytes = 8 << 20

// FleetDesired fetches content-free desired-revision metadata.
func (c *HTTPRelayClient) FleetDesired(ctx context.Context) (relay.FleetDesiredMetadata, error) {
	var payload struct {
		Generation   int64  `json:"generation"`
		Digest       string `json:"digest"`
		SourceCommit string `json:"source_commit"`
		SkillCount   int    `json:"skill_count"`
		TotalBytes   int64  `json:"total_bytes"`
	}
	if _, err := c.doSignedEmpty(ctx, http.MethodGet, "/v1/fleet-config/desired", "application/json", 32<<10, &payload); err != nil {
		return relay.FleetDesiredMetadata{}, err
	}
	return relay.FleetDesiredMetadata{
		Generation:   payload.Generation,
		Digest:       payload.Digest,
		SourceCommit: payload.SourceCommit,
		SkillCount:   payload.SkillCount,
		TotalBytes:   payload.TotalBytes,
	}, nil
}

// FleetRelease fetches exact archive bytes for one digest.
func (c *HTTPRelayClient) FleetRelease(ctx context.Context, digest string) ([]byte, error) {
	if !validFleetDigest(digest) {
		return nil, errors.New("fleet-config digest is invalid")
	}
	path := "/v1/fleet-config/releases/" + digest
	raw, err := c.doSignedEmpty(ctx, http.MethodGet, path, "application/octet-stream", maxFleetReleaseBytes, nil)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, errors.New("fleet-config release is unavailable")
	}
	return raw, nil
}

// PutFleetStatus writes one bounded client status row.
func (c *HTTPRelayClient) PutFleetStatus(ctx context.Context, report relay.FleetStatusReport) error {
	if report.IdempotencyKey == "" {
		return errors.New("fleet-config status idempotency key is required")
	}
	payload := map[string]any{
		"generation":          report.Generation,
		"applied_digest":      report.AppliedDigest,
		"state":               report.State,
		"activation":          report.Activation,
		"trailer_state":       report.TrailerState,
		"alias_state":         report.AliasState,
		"project_match_state": report.ProjectMatchState,
		"report_generation":   report.ReportGeneration,
	}
	_, err := c.doJSONWithIdempotency(ctx, http.MethodPut, "/v1/fleet-config/status", payload, report.IdempotencyKey, nil)
	return err
}

func validFleetDigest(digest string) bool {
	if len(digest) != 64 {
		return false
	}
	for _, c := range digest {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func (c *HTTPRelayClient) doSignedEmpty(ctx context.Context, method, path, accept string, maximum int, responseValue any) ([]byte, error) {
	if c == nil || c.httpClient == nil || c.baseURL == nil || path == "" || maximum <= 0 {
		return nil, errors.New("relay client is unavailable")
	}
	target := c.baseURL.ResolveReference(&url.URL{Path: path})
	request, err := http.NewRequestWithContext(ctx, method, target.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build relay request: %w", err)
	}
	if accept != "" {
		request.Header.Set("Accept", accept)
	}
	if _, err := c.authenticateRequest(request, method, path, nil); err != nil {
		return nil, err
	}
	if c.accessToken.ClientID != "" {
		request.Header.Set("CF-Access-Client-Id", c.accessToken.ClientID)
		request.Header.Set("CF-Access-Client-Secret", c.accessToken.ClientSecret)
	}
	client := *c.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("relay request failed: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, &relayRejectionError{status: response.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(maximum)+1))
	if err != nil || len(raw) > maximum {
		return nil, errors.New("invalid relay response")
	}
	if responseValue == nil {
		return raw, nil
	}
	if err := json.Unmarshal(raw, responseValue); err != nil {
		return nil, fmt.Errorf("decode relay response: %w", err)
	}
	return raw, nil
}

func (c *HTTPRelayClient) doJSON(ctx context.Context, method, path string, requestValue, responseValue any) (int, error) {
	return c.doJSONAllowing(ctx, method, path, requestValue, responseValue)
}

func (c *HTTPRelayClient) doJSONWithIdempotency(ctx context.Context, method, path string, requestValue any, idempotencyKey string, responseValue any) (int, error) {
	return c.doJSONAllowingWithIdempotency(ctx, method, path, requestValue, idempotencyKey, responseValue)
}

func (c *HTTPRelayClient) doJSONAllowing(ctx context.Context, method, path string, requestValue, responseValue any, allowed ...int) (int, error) {
	return c.doJSONAllowingWithIdempotency(ctx, method, path, requestValue, "", responseValue, allowed...)
}

func (c *HTTPRelayClient) doJSONAllowingWithIdempotency(ctx context.Context, method, path string, requestValue any, idempotencyKey string, responseValue any, allowed ...int) (int, error) {
	body, err := json.Marshal(requestValue)
	if err != nil {
		return 0, fmt.Errorf("encode relay request: %w", err)
	}
	target := c.baseURL.ResolveReference(&url.URL{Path: path})
	httpRequest, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("build relay request: %w", err)
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	nonce, err := c.authenticateRequest(httpRequest, method, path, body)
	if err != nil {
		return 0, err
	}
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
	responseNonces := response.Header.Values(relay.ResponseNonceHeader)
	originConfirmed := len(responseNonces) == 1 && responseNonces[0] == nonce
	if !allowedHTTPStatus(response.StatusCode, allowed) {
		return response.StatusCode, &relayRejectionError{
			status:    response.StatusCode,
			confirmed: originConfirmed,
		}
	}
	if c.credential != "" && !originConfirmed {
		return response.StatusCode, errors.New("relay response origin was not confirmed")
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

func allowedHTTPStatus(status int, allowed []int) bool {
	if len(allowed) == 0 {
		return status >= http.StatusOK && status < http.StatusMultipleChoices
	}
	for _, code := range allowed {
		if status == code {
			return true
		}
	}
	return false
}

const maxRelayResponseBytes = 128 << 10

func randomNonce() (string, error) {
	value := make([]byte, 24)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate request nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func randomConsumerID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
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
