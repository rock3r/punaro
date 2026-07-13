package relay

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const maxRequestBodyBytes = 64 << 10

// HandlerOptions make lease timing explicit and injectable for tests.
type HandlerOptions struct {
	Now              func() time.Time
	EndpointLeaseTTL time.Duration
	DeliveryLeaseTTL time.Duration
}

// NewHandler returns the authenticated relay API. It intentionally does not
// mount WebSockets or attachment routes; those have separate release gates.
func NewHandler(store *Store, auth *Authenticator, options HandlerOptions) http.Handler {
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.EndpointLeaseTTL <= 0 {
		options.EndpointLeaseTTL = 2 * time.Minute
	}
	if options.DeliveryLeaseTTL <= 0 {
		options.DeliveryLeaseTTL = time.Minute
	}
	h := &handler{store: store, auth: auth, now: options.Now, endpointLeaseTTL: options.EndpointLeaseTTL, deliveryLeaseTTL: options.DeliveryLeaseTTL}
	return http.HandlerFunc(h.serveHTTP)
}

type handler struct {
	store            *Store
	auth             *Authenticator
	now              func() time.Time
	endpointLeaseTTL time.Duration
	deliveryLeaseTTL time.Duration
}

func (h *handler) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "query parameters are not accepted")
		return
	}
	body, err := readBoundedBody(r)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request body is too large")
		return
	}
	machineID, err := h.authenticate(r, body)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	now := h.now().UTC()
	switch {
	case r.Method == http.MethodPut && r.URL.Path == "/v1/machines/me/endpoints":
		h.advertiseEndpoints(w, body, machineID, now)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/conversations":
		h.createConversation(w, body, machineID, now, r.Header.Get("Idempotency-Key"))
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/conversations/") && strings.HasSuffix(r.URL.Path, "/messages"):
		conversationID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/conversations/"), "/messages")
		if conversationID == "" || strings.Contains(conversationID, "/") {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		h.appendMessage(w, body, machineID, conversationID, now, r.Header.Get("Idempotency-Key"))
	case r.Method == http.MethodPost && r.URL.Path == "/v1/deliveries/lease":
		h.leaseDeliveries(w, body, machineID, now)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/deliveries/") && strings.HasSuffix(r.URL.Path, "/ack"):
		deliveryID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/deliveries/"), "/ack")
		if deliveryID == "" || strings.Contains(deliveryID, "/") {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		h.ackDelivery(w, body, machineID, deliveryID, now)
	default:
		writeError(w, http.StatusNotFound, "route not found")
	}
}

func (h *handler) authenticate(r *http.Request, body []byte) (string, error) {
	timestamp, err := time.Parse(time.RFC3339Nano, r.Header.Get("X-Punaro-Timestamp"))
	if err != nil {
		return "", ErrForbidden
	}
	signature, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Punaro-Signature"))
	if err != nil {
		return "", ErrForbidden
	}
	request := SignedRequest{MachineID: r.Header.Get("X-Punaro-Machine"), Method: r.Method, Path: r.URL.Path, Body: body, Timestamp: timestamp, Nonce: r.Header.Get("X-Punaro-Nonce"), Signature: signature}
	if err := h.auth.Verify(request, h.now().UTC()); err != nil {
		return "", err
	}
	return request.MachineID, nil
}

func (h *handler) advertiseEndpoints(w http.ResponseWriter, body []byte, machineID string, now time.Time) {
	var request struct {
		Endpoints []string `json:"endpoints"`
	}
	if err := decodeJSON(body, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid endpoint advertisement")
		return
	}
	for _, endpoint := range request.Endpoints {
		if !h.auth.AllowsEndpoint(machineID, endpoint) {
			writeError(w, http.StatusForbidden, "authorization denied")
			return
		}
	}
	if err := h.store.AdvertiseEndpoints(machineID, request.Endpoints, now, h.endpointLeaseTTL); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"lease_until": now.Add(h.endpointLeaseTTL).Format(time.RFC3339Nano)})
}

func (h *handler) createConversation(w http.ResponseWriter, body []byte, machineID string, now time.Time, idempotencyKey string) {
	if idempotencyKey == "" {
		writeError(w, http.StatusBadRequest, "Idempotency-Key is required")
		return
	}
	var request struct {
		CreatorEndpoint string `json:"creator_endpoint"`
		Members         []struct {
			Endpoint     string   `json:"endpoint"`
			Capabilities []string `json:"capabilities"`
		} `json:"members"`
	}
	if err := decodeJSON(body, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid conversation request")
		return
	}
	if !h.auth.AllowsEndpoint(machineID, request.CreatorEndpoint) {
		writeError(w, http.StatusForbidden, "authorization denied")
		return
	}
	if err := h.store.AssertEndpointOwnership(machineID, request.CreatorEndpoint, now); err != nil {
		writeStoreError(w, err)
		return
	}
	members := make([]Member, 0, len(request.Members))
	for _, member := range request.Members {
		capabilities, err := parseCapabilities(member.Capabilities)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid conversation capabilities")
			return
		}
		members = append(members, Member{Endpoint: member.Endpoint, Capabilities: capabilities})
	}
	conversation, err := h.store.CreateConversation(request.CreatorEndpoint, members, now)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, conversation)
}

func (h *handler) appendMessage(w http.ResponseWriter, body []byte, machineID, conversationID string, now time.Time, idempotencyKey string) {
	if idempotencyKey == "" {
		writeError(w, http.StatusBadRequest, "Idempotency-Key is required")
		return
	}
	var request struct {
		FromEndpoint string `json:"from_endpoint"`
		Body         string `json:"body"`
	}
	if err := decodeJSON(body, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid message request")
		return
	}
	if !h.auth.AllowsEndpoint(machineID, request.FromEndpoint) {
		writeError(w, http.StatusForbidden, "authorization denied")
		return
	}
	message, duplicate, err := h.store.AppendMessage(AppendInput{ConversationID: conversationID, SenderMachineID: machineID, FromEndpoint: request.FromEndpoint, Body: request.Body, IdempotencyKey: idempotencyKey, Now: now})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	status := http.StatusCreated
	if duplicate {
		status = http.StatusOK
	}
	writeJSON(w, status, message)
}

func (h *handler) leaseDeliveries(w http.ResponseWriter, body []byte, machineID string, now time.Time) {
	var request struct {
		Endpoint       string `json:"endpoint"`
		ConversationID string `json:"conversation_id"`
		Limit          int    `json:"limit"`
	}
	if err := decodeJSON(body, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid delivery lease request")
		return
	}
	if !h.auth.AllowsEndpoint(machineID, request.Endpoint) {
		writeError(w, http.StatusForbidden, "authorization denied")
		return
	}
	if request.Limit == 0 {
		request.Limit = 50
	}
	deliveries, err := h.store.LeaseDeliveries(machineID, request.Endpoint, request.ConversationID, now, h.deliveryLeaseTTL, request.Limit)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deliveries": deliveries})
}

func (h *handler) ackDelivery(w http.ResponseWriter, body []byte, machineID, deliveryID string, now time.Time) {
	var request struct {
		Endpoint        string `json:"endpoint"`
		LeaseToken      string `json:"lease_token"`
		LeaseGeneration int64  `json:"lease_generation"`
	}
	if err := decodeJSON(body, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid delivery acknowledgement")
		return
	}
	if !h.auth.AllowsEndpoint(machineID, request.Endpoint) {
		writeError(w, http.StatusForbidden, "authorization denied")
		return
	}
	if err := h.store.AckDelivery(machineID, request.Endpoint, deliveryID, request.LeaseToken, request.LeaseGeneration, now); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func readBoundedBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer func() { _ = r.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBodyBytes+1))
	if err != nil || len(body) > maxRequestBodyBytes {
		return nil, fmt.Errorf("bounded request body: %w", err)
	}
	return body, nil
}

func decodeJSON(body []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("request has trailing JSON")
	}
	return nil
}

func parseCapabilities(values []string) (Capability, error) {
	var capabilities Capability
	for _, value := range values {
		switch value {
		case "send":
			capabilities |= CapSend
		case "receive":
			capabilities |= CapReceive
		case "admin":
			capabilities |= CapAdmin
		default:
			return 0, fmt.Errorf("unknown capability")
		}
	}
	if capabilities == 0 {
		return 0, fmt.Errorf("no capabilities")
	}
	return capabilities, nil
}

func writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrForbidden):
		writeError(w, http.StatusForbidden, "authorization denied")
	case errors.Is(err, ErrConflict):
		writeError(w, http.StatusConflict, "request conflicts with durable state")
	default:
		writeError(w, http.StatusBadRequest, "invalid request")
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
