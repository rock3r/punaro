package adapter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/rock3r/punaro/internal/relay"
)

type AccessServiceToken struct {
	ClientID     string
	ClientSecret string
}

type HTTPRelayClient struct {
	baseURL     *url.URL
	machineID   string
	privateKey  ed25519.PrivateKey
	httpClient  *http.Client
	accessToken AccessServiceToken
}

func NewHTTPRelayClient(rawURL, machineID string, privateKey ed25519.PrivateKey, client *http.Client, accessToken AccessServiceToken) (*HTTPRelayClient, error) {
	baseURL, err := url.Parse(rawURL)
	if err != nil || baseURL.Scheme == "" || baseURL.Host == "" || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, fmt.Errorf("invalid relay URL")
	}
	if baseURL.Scheme != "https" && !(baseURL.Scheme == "http" && loopbackHost(baseURL.Hostname())) {
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

func (c *HTTPRelayClient) Advertise(ctx context.Context, endpoints []string) error {
	_, err := c.doJSON(ctx, http.MethodPut, "/v1/machines/me/endpoints", map[string]any{"endpoints": endpoints}, nil)
	return err
}

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
	_, err := c.doJSONWithIdempotency(ctx, http.MethodPost, "/v1/conversations/"+url.PathEscape(conversationID)+"/messages", map[string]any{"from_endpoint": fromEndpoint, "body": body}, idempotencyKey, &message)
	return message, err
}

func (c *HTTPRelayClient) Ack(ctx context.Context, delivery relay.Delivery) error {
	_, err := c.doJSON(ctx, http.MethodPost, "/v1/deliveries/"+url.PathEscape(delivery.ID)+"/ack", map[string]any{"endpoint": delivery.RecipientEndpoint, "lease_token": delivery.LeaseToken, "lease_generation": delivery.LeaseGeneration}, nil)
	return err
}

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
	connection, _, err := websocket.Dial(ctx, target.String(), &websocket.DialOptions{HTTPHeader: headers, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return fmt.Errorf("connect relay notifications: %w", err)
	}
	defer connection.Close(websocket.StatusNormalClosure, "")
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
	response, err := c.httpClient.Do(httpRequest)
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
