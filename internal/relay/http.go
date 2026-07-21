package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
)

const (
	maxRequestBodyBytes              = 64 << 10
	maximumSessionFenceAge           = 2 * time.Second
	defaultSessionRevalidateInterval = maximumSessionFenceAge / 2
)

// HandlerOptions make lease timing explicit and injectable for tests.
type HandlerOptions struct {
	Now                       func() time.Time
	EndpointLeaseTTL          time.Duration
	DeliveryLeaseTTL          time.Duration
	Notifier                  *Notifier
	SessionRevalidateInterval time.Duration
}

// NewHandler returns the authenticated relay API, including the wake-metadata
// notification WebSocket. Attachment routes remain separate release gates.
func NewHandler(store Backend, auth *Authenticator, options HandlerOptions) http.Handler {
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.EndpointLeaseTTL <= 0 {
		options.EndpointLeaseTTL = 2 * time.Minute
	}
	if options.DeliveryLeaseTTL <= 0 {
		options.DeliveryLeaseTTL = time.Minute
	}
	if options.Notifier == nil {
		options.Notifier = NewNotifier()
	}
	if options.SessionRevalidateInterval <= 0 || options.SessionRevalidateInterval > maximumSessionFenceAge/2 {
		options.SessionRevalidateInterval = defaultSessionRevalidateInterval
	}
	h := &handler{store: store, auth: auth, notifier: options.Notifier, now: options.Now, endpointLeaseTTL: options.EndpointLeaseTTL, deliveryLeaseTTL: options.DeliveryLeaseTTL, sessionRevalidateInterval: options.SessionRevalidateInterval}
	return http.HandlerFunc(h.serveHTTP)
}

type handler struct {
	store                     Backend
	auth                      *Authenticator
	notifier                  *Notifier
	now                       func() time.Time
	endpointLeaseTTL          time.Duration
	deliveryLeaseTTL          time.Duration
	sessionRevalidateInterval time.Duration
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
	session, err := h.authenticate(r, body)
	if err != nil {
		if errors.Is(err, ErrMaintenance) {
			writeStoreError(w, err)
			return
		}
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	machineID := session.MachineID
	authority := PrincipalAuthority{PrincipalID: session.PrincipalID, CredentialLookupID: session.CredentialLookupID, CredentialGeneration: session.CredentialGeneration}
	now := h.now().UTC()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/conversations":
		h.listConversations(w, machineID, now)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/notifications":
		h.notifications(w, r, session)
	case r.Method == http.MethodPut && r.URL.Path == "/v1/machines/me/endpoints":
		h.advertiseEndpoints(w, body, machineID, authority, now)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/conversations":
		h.createConversation(w, body, machineID, authority, now, r.Header.Get("Idempotency-Key"))
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/conversations/") && strings.HasSuffix(r.URL.Path, "/messages"):
		conversationID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/conversations/"), "/messages")
		if conversationID == "" || strings.Contains(conversationID, "/") {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		h.appendMessage(w, body, machineID, authority, conversationID, now, r.Header.Get("Idempotency-Key"))
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/conversations/") && strings.HasSuffix(r.URL.Path, "/sender-validation"):
		conversationID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/conversations/"), "/sender-validation")
		if conversationID == "" || strings.Contains(conversationID, "/") {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		h.validateSender(w, body, machineID, conversationID, now)
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

func (h *handler) validateSender(w http.ResponseWriter, body []byte, machineID, conversationID string, now time.Time) {
	var request struct {
		FromEndpoint string `json:"from_endpoint"`
	}
	if err := decodeJSON(body, &request); err != nil || !h.auth.AllowsEndpoint(machineID, request.FromEndpoint) {
		writeError(w, http.StatusForbidden, "authorization denied")
		return
	}
	if err := h.store.AuthorizeSender(conversationID, machineID, request.FromEndpoint, now); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"authorized": true})
}

func (h *handler) listConversations(w http.ResponseWriter, machineID string, now time.Time) {
	conversations, err := h.store.ConversationsForMachine(machineID, now)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"conversations": conversations})
}

func (h *handler) notifications(w http.ResponseWriter, r *http.Request, session MachineSession) {
	connection, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer func() { _ = connection.Close(websocket.StatusNormalClosure, "") }()
	client := h.notifier.Register(session.MachineID)
	defer client.Close()
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	authenticationExpired := make(chan struct{})
	revalidationDone := make(chan struct{})
	go h.revalidateNotificationSession(ctx, cancel, connection, session, authenticationExpired, revalidationDone)
	go func() {
		defer cancel()
		for {
			if _, _, err := connection.Read(ctx); err != nil {
				return
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			waitForAuthenticationClose(authenticationExpired, revalidationDone)
			return
		case event := <-client.Events():
			payload, err := json.Marshal(event)
			if err != nil {
				return
			}
			if err := connection.Write(ctx, websocket.MessageText, payload); err != nil {
				waitForAuthenticationClose(authenticationExpired, revalidationDone)
				return
			}
		}
	}
}

func (h *handler) revalidateNotificationSession(ctx context.Context, cancel context.CancelFunc, connection *websocket.Conn, session MachineSession, authenticationExpired chan<- struct{}, done chan<- struct{}) {
	defer close(done)
	revalidate := time.NewTicker(h.sessionRevalidateInterval)
	defer revalidate.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-revalidate.C:
			// A check starts halfway through the maximum fence age and receives
			// only the remaining half as its deadline. It runs independently of
			// wake writes, and canceling ctx unblocks a slow/non-reading client.
			checkCtx, checkCancel := context.WithTimeout(ctx, h.sessionRevalidateInterval)
			err := session.Current(checkCtx)
			checkCancel()
			if err != nil {
				close(authenticationExpired)
				cancel()
				// Cancel first to interrupt any blocked Read/Write, then close the
				// transport immediately. A close-frame status is not an authority
				// guarantee and cannot be delivered reliably to a non-reading peer.
				_ = connection.CloseNow()
				return
			}
		}
	}
}

func waitForAuthenticationClose(authenticationExpired <-chan struct{}, revalidationDone <-chan struct{}) {
	select {
	case <-authenticationExpired:
		<-revalidationDone
	default:
	}
}

func (h *handler) authenticate(r *http.Request, body []byte) (MachineSession, error) {
	return h.auth.AuthenticateHTTPSession(r, body, h.now())
}

func (h *handler) advertiseEndpoints(w http.ResponseWriter, body []byte, machineID string, authority PrincipalAuthority, now time.Time) {
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
	var err error
	if authority.CredentialLookupID != "" {
		if principalStore, ok := h.store.(PrincipalEndpointBackend); ok {
			err = principalStore.AdvertiseEndpointsForPrincipal(machineID, authority, request.Endpoints, now, h.endpointLeaseTTL)
		} else {
			err = h.store.AdvertiseEndpoints(machineID, request.Endpoints, now, h.endpointLeaseTTL)
		}
	} else {
		err = h.store.AdvertiseEndpoints(machineID, request.Endpoints, now, h.endpointLeaseTTL)
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"lease_until": now.Add(h.endpointLeaseTTL).Format(time.RFC3339Nano)})
}

func (h *handler) createConversation(w http.ResponseWriter, body []byte, machineID string, authority PrincipalAuthority, now time.Time, idempotencyKey string) {
	if !ValidRequestToken(idempotencyKey) {
		writeError(w, http.StatusBadRequest, "Idempotency-Key is required")
		return
	}
	var request struct {
		CreatorEndpoint string `json:"creator_endpoint"`
		ProjectID       string `json:"project_id"`
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
	conversation, err := h.store.CreateConversationIdempotent(CreateConversationInput{MachineID: machineID, PrincipalID: authority.PrincipalID, CredentialLookupID: authority.CredentialLookupID, CredentialGeneration: authority.CredentialGeneration, ProjectID: request.ProjectID, IdempotencyKey: idempotencyKey, CreatorEndpoint: request.CreatorEndpoint, Members: members, Now: now})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, conversation)
}

func (h *handler) appendMessage(w http.ResponseWriter, body []byte, machineID string, authority PrincipalAuthority, conversationID string, now time.Time, idempotencyKey string) {
	if !ValidRequestToken(idempotencyKey) {
		writeError(w, http.StatusBadRequest, "Idempotency-Key is required")
		return
	}
	var request struct {
		FromEndpoint string   `json:"from_endpoint"`
		Body         string   `json:"body"`
		ArtifactIDs  []string `json:"artifact_ids"`
	}
	if err := decodeJSON(body, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid message request")
		return
	}
	if !h.auth.AllowsEndpoint(machineID, request.FromEndpoint) {
		writeError(w, http.StatusForbidden, "authorization denied")
		return
	}
	message, duplicate, err := h.store.AppendMessage(AppendInput{ConversationID: conversationID, SenderMachineID: machineID, PrincipalID: authority.PrincipalID, CredentialLookupID: authority.CredentialLookupID, CredentialGeneration: authority.CredentialGeneration, FromEndpoint: request.FromEndpoint, Body: request.Body, ArtifactIDs: request.ArtifactIDs, IdempotencyKey: idempotencyKey, Now: now})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if !duplicate {
		machines, err := h.store.RecipientMachines(message.ID, now)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		for _, recipientMachine := range machines {
			h.notifier.Publish(recipientMachine, message.ConversationID, message.Sequence)
		}
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
		ConsumerID     string `json:"consumer_id"`
		ConversationID string `json:"conversation_id"`
		Limit          int    `json:"limit"`
	}
	if err := decodeJSON(body, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid delivery lease request")
		return
	}
	if !ValidRequestToken(request.ConsumerID) {
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
	page, err := h.store.LeaseDeliveries(machineID, request.ConsumerID, request.Endpoint, request.ConversationID, now, h.deliveryLeaseTTL, request.Limit)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
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
	case errors.Is(err, ErrMaintenance):
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusServiceUnavailable, "relay maintenance in progress")
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
