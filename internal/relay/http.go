package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
)

const (
	maxRequestBodyBytes              = 64 << 10
	maximumSessionFenceAge           = 2 * time.Second
	defaultSessionRevalidateInterval = maximumSessionFenceAge / 2
	// DoctorPath is the exact signed, read-only relay reachability probe.
	DoctorPath = "/v1/doctor"
	// DoctorNotificationsPath is the exact signed, read-only WebSocket
	// handshake probe. It never registers for or emits wake events.
	DoctorNotificationsPath = "/v1/doctor/notifications"
	// ResponseNonceHeader confirms that a response came from the authenticated
	// Punaro route rather than an intermediary which rejected the request.
	ResponseNonceHeader = "X-Punaro-Response-Nonce"
	// ProtocolHeader carries the bounded relay protocol identity.
	ProtocolHeader = "X-Punaro-Protocol"
	// DoctorEndpointHeader selects one endpoint owned by the authenticated
	// machine for a read-only attachment check.
	DoctorEndpointHeader = "X-Punaro-Doctor-Endpoint"
	// DoctorAttachmentHeader and the following aggregate headers report only
	// bounded, content-free endpoint and role attachment state.
	DoctorAttachmentHeader = "X-Punaro-Endpoint-Attached"
	// DoctorActiveEndpointsHeader reports a bounded count of active endpoints.
	DoctorActiveEndpointsHeader = "X-Punaro-Active-Endpoints"
	// DoctorExpiredEndpointsHeader reports a bounded count of expired endpoints.
	DoctorExpiredEndpointsHeader = "X-Punaro-Expired-Endpoints"
	// DoctorActiveRolesHeader reports a bounded count of active roles.
	DoctorActiveRolesHeader = "X-Punaro-Active-Roles"
	// DoctorExpiredRolesHeader reports a bounded count of expired roles.
	DoctorExpiredRolesHeader = "X-Punaro-Expired-Roles"
	// ProtocolVersion is the relay doctor protocol supported by this release.
	ProtocolVersion = 1
)

// HandlerOptions make lease timing explicit and injectable for tests.
type HandlerOptions struct {
	Now                       func() time.Time
	EndpointLeaseTTL          time.Duration
	DeliveryLeaseTTL          time.Duration
	Notifier                  *Notifier
	SessionRevalidateInterval time.Duration
	Metrics                   *Metrics
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
	if options.Metrics == nil {
		options.Metrics = &Metrics{}
	}
	h := &handler{store: store, auth: auth, notifier: options.Notifier, now: options.Now, endpointLeaseTTL: options.EndpointLeaseTTL, deliveryLeaseTTL: options.DeliveryLeaseTTL, sessionRevalidateInterval: options.SessionRevalidateInterval, metrics: options.Metrics}
	if setter, ok := store.(interface{ SetMetrics(*Metrics) }); ok {
		setter.SetMetrics(options.Metrics)
	}
	return h
}

type handler struct {
	store                     Backend
	auth                      *Authenticator
	notifier                  *Notifier
	now                       func() time.Time
	endpointLeaseTTL          time.Duration
	deliveryLeaseTTL          time.Duration
	sessionRevalidateInterval time.Duration
	metrics                   *Metrics
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.serveHTTP(w, r)
}

// MetricsSnapshot returns content-free relay counters for the local health listener.
func (h *handler) MetricsSnapshot() MetricsSnapshot {
	return h.metrics.Snapshot()
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
	if r.Method == http.MethodHead && r.URL.Path == DoctorPath {
		h.doctor(w, r, body)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == DoctorNotificationsPath {
		h.doctorNotifications(w, r, body)
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
	w.Header().Set(ResponseNonceHeader, r.Header.Get("X-Punaro-Nonce"))
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
	case r.Method == http.MethodPost && r.URL.Path == "/v1/roles/bindings":
		h.bindRole(w, body, machineID, now)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/roles/register":
		h.registerRole(w, body, machineID, now, r.Header.Get("Idempotency-Key"))
	case r.Method == http.MethodPost && r.URL.Path == "/v1/roles/list":
		h.listRoles(w, body, now)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/roles/resolve":
		h.resolveRole(w, body, now)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/direct-messages":
		h.sendDirectMessage(w, body, machineID, now, r.Header.Get("Idempotency-Key"))
	case r.Method == http.MethodPost && r.URL.Path == "/v1/conversations":
		h.createConversation(w, body, machineID, authority, now, r.Header.Get("Idempotency-Key"))
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/conversations/") && strings.HasSuffix(r.URL.Path, "/messages"):
		conversationID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/conversations/"), "/messages")
		if conversationID == "" || strings.Contains(conversationID, "/") {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		h.appendMessage(w, body, machineID, authority, conversationID, now, r.Header.Get("Idempotency-Key"))
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/conversations/") && strings.HasSuffix(r.URL.Path, "/invocations"):
		conversationID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/conversations/"), "/invocations")
		if conversationID == "" || strings.Contains(conversationID, "/") {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		h.requestInvocation(w, body, machineID, conversationID, now, r.Header.Get("Idempotency-Key"))
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/conversations/") && strings.HasSuffix(r.URL.Path, "/sender-validation"):
		conversationID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/conversations/"), "/sender-validation")
		if conversationID == "" || strings.Contains(conversationID, "/") {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		h.validateSender(w, body, machineID, conversationID, now)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/conversations/") && strings.HasSuffix(r.URL.Path, "/controls"):
		conversationID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/conversations/"), "/controls")
		if conversationID == "" || strings.Contains(conversationID, "/") {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		h.applyControl(w, body, machineID, conversationID, now, r.Header.Get("Idempotency-Key"))
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/conversations/") && strings.HasSuffix(r.URL.Path, "/controls/audit"):
		conversationID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/conversations/"), "/controls/audit")
		if conversationID == "" || strings.Contains(conversationID, "/") {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		h.controlAudit(w, body, machineID, conversationID, now)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/conversations/") && strings.HasSuffix(r.URL.Path, "/display-name"):
		conversationID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/conversations/"), "/display-name")
		if conversationID == "" || strings.Contains(conversationID, "/") {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		h.setConversationDisplayName(w, body, machineID, conversationID, now, r.Header.Get("Idempotency-Key"))
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/conversations/") && strings.HasSuffix(r.URL.Path, "/telegram-claim/complete"):
		conversationID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/conversations/"), "/telegram-claim/complete")
		if conversationID == "" || strings.Contains(conversationID, "/") {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		h.completeTelegramClaim(w, body, machineID, conversationID, now)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/conversations/") && strings.HasSuffix(r.URL.Path, "/telegram-claim"):
		conversationID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/conversations/"), "/telegram-claim")
		if conversationID == "" || strings.Contains(conversationID, "/") {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		h.reserveTelegramClaim(w, body, machineID, conversationID, now, r.Header.Get("Idempotency-Key"))
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/conversations/") && strings.HasSuffix(r.URL.Path, "/telegram-inbound"):
		conversationID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/conversations/"), "/telegram-inbound")
		if conversationID == "" || strings.Contains(conversationID, "/") {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		h.appendTelegramInbound(w, body, machineID, conversationID, now, r.Header.Get("Idempotency-Key"))
	case r.Method == http.MethodPost && r.URL.Path == "/v1/telegram/claims/pending":
		h.pendingTelegramClaims(w, body, machineID, now)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/telegram/unclaimed":
		h.unclaimedTelegramTopics(w, machineID, now)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/sessions/topic":
		h.sessionTopic(w, body, machineID, now)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/deliveries/lease":
		h.leaseDeliveries(w, body, machineID, now)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/invocations/lease":
		h.leaseInvocations(w, body, machineID, now)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/invocations/") && strings.HasSuffix(r.URL.Path, "/outcome"):
		invocationID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/invocations/"), "/outcome")
		if invocationID == "" || strings.Contains(invocationID, "/") {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		h.reportInvocation(w, body, machineID, invocationID, now)
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

func (h *handler) doctor(w http.ResponseWriter, r *http.Request, body []byte) {
	if len(body) != 0 || r.URL.RawPath != "" || r.URL.EscapedPath() != r.URL.Path {
		writeError(w, http.StatusBadRequest, "invalid doctor request")
		return
	}
	session, err := h.auth.AuthenticateReadOnlyDoctor(r, body, h.now())
	if err != nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set(ResponseNonceHeader, r.Header.Get("X-Punaro-Nonce"))
	w.Header().Set(ProtocolHeader, strconv.Itoa(ProtocolVersion))
	if backend, ok := h.store.(AttachmentDoctorBackend); ok {
		if snapshot, snapshotErr := backend.DoctorAttachments(session.MachineID, h.now().UTC()); snapshotErr == nil {
			w.Header().Set(DoctorActiveEndpointsHeader, strconv.Itoa(snapshot.ActiveEndpoints))
			w.Header().Set(DoctorExpiredEndpointsHeader, strconv.Itoa(snapshot.ExpiredEndpoints))
			w.Header().Set(DoctorActiveRolesHeader, strconv.Itoa(snapshot.ActiveRoles))
			w.Header().Set(DoctorExpiredRolesHeader, strconv.Itoa(snapshot.ExpiredRoles))
		}
	}
	if endpoint := r.Header.Get(DoctorEndpointHeader); endpoint != "" {
		attached := ValidEndpoint(endpoint) && h.auth.AllowsEndpoint(session.MachineID, endpoint) && h.store.AssertEndpointOwnership(session.MachineID, endpoint, h.now().UTC()) == nil
		w.Header().Set(DoctorAttachmentHeader, strconv.FormatBool(attached))
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) doctorNotifications(w http.ResponseWriter, r *http.Request, body []byte) {
	if len(body) != 0 || r.URL.RawPath != "" || r.URL.EscapedPath() != r.URL.Path {
		writeError(w, http.StatusBadRequest, "invalid doctor request")
		return
	}
	if _, err := h.auth.AuthenticateReadOnlyDoctor(r, body, h.now()); err != nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set(ResponseNonceHeader, r.Header.Get("X-Punaro-Nonce"))
	w.Header().Set(ProtocolHeader, strconv.Itoa(ProtocolVersion))
	connection, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	_ = connection.Close(websocket.StatusNormalClosure, "")
}

func (h *handler) registerRole(w http.ResponseWriter, body []byte, machineID string, now time.Time, idempotencyKey string) {
	if !ValidRequestToken(idempotencyKey) {
		writeError(w, http.StatusBadRequest, "Idempotency-Key is required")
		return
	}
	store, ok := h.store.(RoleProfileBackend)
	if !ok {
		writeError(w, http.StatusForbidden, "authorization denied")
		return
	}
	var request struct {
		Role              string  `json:"role"`
		DisplayName       *string `json:"display_name"`
		DirectAddressable *bool   `json:"direct_addressable"`
	}
	if err := decodeJSON(body, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid role registration")
		return
	}
	displayName := ""
	if request.DisplayName != nil {
		displayName = *request.DisplayName
	}
	directAddressable := false
	if request.DirectAddressable != nil {
		directAddressable = *request.DirectAddressable
	}
	profile, created, err := store.RegisterRoleProfile(RegisterRoleInput{
		MachineID: machineID, Role: request.Role, DisplayName: displayName, DirectAddressable: directAddressable, IdempotencyKey: idempotencyKey, Now: now,
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, profile)
}

func (h *handler) listRoles(w http.ResponseWriter, body []byte, now time.Time) {
	store, ok := h.store.(RoleProfileBackend)
	if !ok {
		writeError(w, http.StatusForbidden, "authorization denied")
		return
	}
	var request struct {
		Cursor string `json:"cursor"`
		Limit  *int   `json:"limit"`
	}
	if err := decodeJSON(body, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid role directory request")
		return
	}
	limit := DefaultRoleListLimit
	if request.Limit != nil {
		limit = *request.Limit
	}
	page, err := store.ListAddressableRoles(RoleListInput{Cursor: request.Cursor, Limit: limit, Now: now})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (h *handler) resolveRole(w http.ResponseWriter, body []byte, now time.Time) {
	store, ok := h.store.(RoleProfileBackend)
	if !ok {
		writeError(w, http.StatusForbidden, "authorization denied")
		return
	}
	var request struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(body, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid role resolution request")
		return
	}
	result, err := store.ResolveAddressableRole(RoleResolveInput{Name: request.Name, Now: now})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	switch result.Status {
	case RoleResolveResolved:
		writeJSON(w, http.StatusOK, result)
	case RoleResolveAmbiguous:
		writeJSON(w, http.StatusConflict, result)
	default:
		writeError(w, http.StatusNotFound, "role not found")
	}
}

func (h *handler) sendDirectMessage(w http.ResponseWriter, body []byte, machineID string, now time.Time, idempotencyKey string) {
	if !ValidRequestToken(idempotencyKey) {
		writeError(w, http.StatusBadRequest, "Idempotency-Key is required")
		return
	}
	store, ok := h.store.(DirectMessageBackend)
	if !ok {
		writeError(w, http.StatusForbidden, "authorization denied")
		return
	}
	var request struct {
		FromRole string `json:"from_role"`
		ToRole   string `json:"to_role"`
		Body     string `json:"body"`
	}
	if err := decodeJSON(body, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid direct message request")
		return
	}
	message, duplicate, err := store.SendDirectMessage(DirectMessageInput{
		SenderMachineID: machineID, FromRole: request.FromRole, ToRole: request.ToRole, Body: request.Body, IdempotencyKey: idempotencyKey, Now: now,
	})
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

func (h *handler) bindRole(w http.ResponseWriter, body []byte, machineID string, now time.Time) {
	var request struct {
		Role            string `json:"role"`
		SessionEndpoint string `json:"session_endpoint"`
	}
	if err := decodeJSON(body, &request); err != nil || !h.auth.AllowsEndpoint(machineID, request.SessionEndpoint) {
		writeError(w, http.StatusForbidden, "authorization denied")
		return
	}
	store, ok := h.store.(RoleBindingBackend)
	if !ok {
		writeError(w, http.StatusForbidden, "authorization denied")
		return
	}
	if err := store.BindRoleToSession(machineID, request.Role, request.SessionEndpoint, now, h.endpointLeaseTTL); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) applyControl(w http.ResponseWriter, body []byte, machineID, conversationID string, now time.Time, idempotencyKey string) {
	if !ValidRequestToken(idempotencyKey) {
		writeError(w, http.StatusBadRequest, "Idempotency-Key is required")
		return
	}
	store, ok := h.store.(ControlBackend)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "control plane is unavailable")
		return
	}
	var request struct {
		ActorEndpoint string           `json:"actor_endpoint"`
		Operation     ControlOperation `json:"operation"`
		Member        struct {
			Endpoint     string   `json:"endpoint"`
			Capabilities []string `json:"capabilities"`
		} `json:"member"`
	}
	if err := decodeJSON(body, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid control request")
		return
	}
	if !h.auth.AllowsEndpoint(machineID, request.ActorEndpoint) {
		writeError(w, http.StatusForbidden, "authorization denied")
		return
	}
	capabilities := Capability(0)
	var err error
	if request.Operation == ControlUpsertMember {
		capabilities, err = parseCapabilities(request.Member.Capabilities)
	} else if request.Operation != ControlRemoveMember || len(request.Member.Capabilities) != 0 {
		err = fmt.Errorf("invalid control operation")
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid control request")
		return
	}
	event, duplicate, err := store.ApplyControl(ControlInput{ConversationID: conversationID, ActorMachineID: machineID, ActorEndpoint: request.ActorEndpoint, Operation: request.Operation, Member: Member{Endpoint: request.Member.Endpoint, Capabilities: capabilities}, IdempotencyKey: idempotencyKey, Now: now})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	status := http.StatusCreated
	if duplicate {
		status = http.StatusOK
	}
	writeJSON(w, status, event)
}

func (h *handler) controlAudit(w http.ResponseWriter, body []byte, machineID, conversationID string, now time.Time) {
	store, ok := h.store.(ControlBackend)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "control plane is unavailable")
		return
	}
	var request struct {
		ActorEndpoint string `json:"actor_endpoint"`
	}
	if err := decodeJSON(body, &request); err != nil || !h.auth.AllowsEndpoint(machineID, request.ActorEndpoint) {
		writeError(w, http.StatusForbidden, "authorization denied")
		return
	}
	events, err := store.ControlAudit(conversationID, machineID, request.ActorEndpoint, now)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (h *handler) validateSender(w http.ResponseWriter, body []byte, machineID, conversationID string, now time.Time) {
	var request struct {
		FromEndpoint string `json:"from_endpoint"`
	}
	if err := decodeJSON(body, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid sender validation request")
		return
	}
	if !h.auth.AllowsEndpoint(machineID, request.FromEndpoint) {
		writeError(w, http.StatusForbidden, "authorization denied")
		return
	}
	if err := h.store.AuthorizeSender(conversationID, machineID, request.FromEndpoint, now); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"authorized": true})
}

func (h *handler) setConversationDisplayName(w http.ResponseWriter, body []byte, machineID, conversationID string, now time.Time, idempotencyKey string) {
	if !ValidRequestToken(idempotencyKey) {
		writeError(w, http.StatusBadRequest, "Idempotency-Key is required")
		return
	}
	store, ok := h.store.(DisplayNameBackend)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "display name plane is unavailable")
		return
	}
	var request struct {
		ActorEndpoint string `json:"actor_endpoint"`
		DisplayName   string `json:"display_name"`
	}
	if err := decodeJSON(body, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid display name request")
		return
	}
	if !h.auth.AllowsEndpoint(machineID, request.ActorEndpoint) {
		writeError(w, http.StatusForbidden, "authorization denied")
		return
	}
	conversation, duplicate, err := store.SetConversationDisplayName(SetDisplayNameInput{ConversationID: conversationID, ActorMachineID: machineID, ActorEndpoint: request.ActorEndpoint, DisplayName: request.DisplayName, IdempotencyKey: idempotencyKey, Now: now})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	status := http.StatusCreated
	if duplicate {
		status = http.StatusOK
	}
	writeJSON(w, status, conversation)
}

func (h *handler) telegramClaimStore() (TelegramClaimBackend, bool) {
	store, ok := h.store.(TelegramClaimBackend)
	return store, ok
}

func (h *handler) reserveTelegramClaim(w http.ResponseWriter, body []byte, machineID, conversationID string, now time.Time, idempotencyKey string) {
	if !ValidRequestToken(idempotencyKey) {
		writeError(w, http.StatusBadRequest, "Idempotency-Key is required")
		return
	}
	store, ok := h.telegramClaimStore()
	if !ok {
		writeStoreError(w, ErrMaintenance)
		return
	}
	var request struct {
		Endpoint string `json:"endpoint"`
	}
	if err := decodeJSON(body, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid telegram claim request")
		return
	}
	if !h.auth.AllowsEndpoint(machineID, request.Endpoint) {
		writeError(w, http.StatusForbidden, "authorization denied")
		return
	}
	claim, duplicate, err := store.ReserveTelegramClaim(TelegramClaimInput{ConversationID: conversationID, MachineID: machineID, Endpoint: request.Endpoint, IdempotencyKey: idempotencyKey, Now: now})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	status := http.StatusCreated
	if duplicate {
		status = http.StatusOK
	}
	writeJSON(w, status, claim)
}

func (h *handler) completeTelegramClaim(w http.ResponseWriter, body []byte, machineID, conversationID string, now time.Time) {
	store, ok := h.telegramClaimStore()
	if !ok {
		writeStoreError(w, ErrMaintenance)
		return
	}
	var request struct{}
	if err := decodeJSON(body, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid telegram claim complete request")
		return
	}
	if !h.auth.AllowsEndpoint(machineID, TelegramGatewayEndpoint) {
		writeError(w, http.StatusForbidden, "authorization denied")
		return
	}
	claim, duplicate, err := store.CompleteTelegramClaim(TelegramClaimCompleteInput{ConversationID: conversationID, MachineID: machineID, Now: now})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	status := http.StatusCreated
	if duplicate {
		status = http.StatusOK
	}
	writeJSON(w, status, claim)
}

func (h *handler) pendingTelegramClaims(w http.ResponseWriter, body []byte, machineID string, now time.Time) {
	store, ok := h.telegramClaimStore()
	if !ok {
		writeStoreError(w, ErrMaintenance)
		return
	}
	var request struct {
		Limit int    `json:"limit"`
		After string `json:"after"`
	}
	if err := decodeJSON(body, &request); err != nil || request.Limit < 1 || request.Limit > 100 {
		writeError(w, http.StatusBadRequest, "invalid pending claim request")
		return
	}
	if !h.auth.AllowsEndpoint(machineID, TelegramGatewayEndpoint) {
		writeError(w, http.StatusForbidden, "authorization denied")
		return
	}
	claims, err := store.PendingTelegramClaims(machineID, now, request.Limit, request.After)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"claims": claims})
}

func (h *handler) unclaimedTelegramTopics(w http.ResponseWriter, machineID string, now time.Time) {
	store, ok := h.telegramClaimStore()
	if !ok {
		writeStoreError(w, ErrMaintenance)
		return
	}
	if !h.auth.AllowsEndpoint(machineID, TelegramGatewayEndpoint) {
		writeError(w, http.StatusForbidden, "authorization denied")
		return
	}
	topics, err := store.UnclaimedNamedConversations(machineID, now, 10)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"topics": topics})
}

func (h *handler) sessionTopic(w http.ResponseWriter, body []byte, machineID string, now time.Time) {
	store, ok := h.telegramClaimStore()
	if !ok {
		writeStoreError(w, ErrMaintenance)
		return
	}
	var request struct {
		Endpoint string `json:"endpoint"`
	}
	if err := decodeJSON(body, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid session topic request")
		return
	}
	if !h.auth.AllowsEndpoint(machineID, request.Endpoint) {
		writeError(w, http.StatusForbidden, "authorization denied")
		return
	}
	topic, err := store.SessionTopic(machineID, request.Endpoint, now)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, topic)
}

func (h *handler) appendTelegramInbound(w http.ResponseWriter, body []byte, machineID, conversationID string, now time.Time, idempotencyKey string) {
	if !ValidRequestToken(idempotencyKey) {
		writeError(w, http.StatusBadRequest, "Idempotency-Key is required")
		return
	}
	store, ok := h.telegramClaimStore()
	if !ok {
		writeStoreError(w, ErrMaintenance)
		return
	}
	var request struct {
		FromEndpoint           string `json:"from_endpoint"`
		FromParticipant        string `json:"from_participant"`
		Body                   string `json:"body"`
		InReplyToPunaroMessage string `json:"in_reply_to_punaro_message_id"`
		InReplyToEndpoint      string `json:"in_reply_to_endpoint"`
		TelegramThreadID       int64  `json:"telegram_thread_id"`
	}
	if err := decodeJSON(body, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid telegram inbound request")
		return
	}
	if !h.auth.AllowsEndpoint(machineID, TelegramGatewayEndpoint) {
		writeError(w, http.StatusForbidden, "authorization denied")
		return
	}
	message, duplicate, err := store.AppendTelegramInbound(TelegramInboundInput{
		ConversationID:     conversationID,
		SenderMachineID:    machineID,
		FromEndpoint:       request.FromEndpoint,
		FromParticipant:    request.FromParticipant,
		Body:               request.Body,
		InReplyToMessageID: request.InReplyToPunaroMessage,
		InReplyToEndpoint:  request.InReplyToEndpoint,
		TelegramThreadID:   request.TelegramThreadID,
		IdempotencyKey:     idempotencyKey,
		Now:                now,
	})
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

func (h *handler) listConversations(w http.ResponseWriter, machineID string, now time.Time) {
	conversations, err := h.store.ConversationsForMachine(machineID, now)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"conversations": conversations})
}

func (h *handler) notifications(w http.ResponseWriter, r *http.Request, session MachineSession) {
	// Register before completing the WebSocket handshake so a publisher that
	// observes a successful dial cannot lose its first wake hint to setup race.
	client := h.notifier.Register(session.MachineID)
	defer client.Close()
	connection, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer func() { _ = connection.Close(websocket.StatusNormalClosure, "") }()
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
		DisplayName     string `json:"display_name"`
		ProjectID       string `json:"project_id"`
		Members         []struct {
			Endpoint      string   `json:"endpoint"`
			Role          string   `json:"role"`
			RoleMachineID string   `json:"role_machine_id"`
			Capabilities  []string `json:"capabilities"`
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
		if member.Role != "" && capabilities&CapInvoke != 0 {
			writeError(w, http.StatusBadRequest, "invalid conversation capabilities")
			return
		}
		if member.RoleMachineID != "" {
			if _, found := h.auth.machines[member.RoleMachineID]; !found {
				writeError(w, http.StatusForbidden, "authorization denied")
				return
			}
		}
		members = append(members, Member{Endpoint: member.Endpoint, Role: member.Role, RoleMachineID: member.RoleMachineID, Capabilities: capabilities})
	}
	conversation, err := h.store.CreateConversationIdempotent(CreateConversationInput{MachineID: machineID, PrincipalID: authority.PrincipalID, CredentialLookupID: authority.CredentialLookupID, CredentialGeneration: authority.CredentialGeneration, ProjectID: request.ProjectID, IdempotencyKey: idempotencyKey, CreatorEndpoint: request.CreatorEndpoint, DisplayName: request.DisplayName, Members: members, Now: now})
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
		TargetRole   string   `json:"target_role"`
		Body         string   `json:"body"`
		ArtifactIDs  []string `json:"artifact_ids"`
	}
	if err := decodeJSON(body, &request); err != nil || (request.TargetRole != "" && !ValidRole(request.TargetRole)) {
		writeError(w, http.StatusBadRequest, "invalid message request")
		return
	}
	if !h.auth.AllowsEndpoint(machineID, request.FromEndpoint) {
		writeError(w, http.StatusForbidden, "authorization denied")
		return
	}
	message, duplicate, err := h.store.AppendMessage(AppendInput{ConversationID: conversationID, SenderMachineID: machineID, PrincipalID: authority.PrincipalID, CredentialLookupID: authority.CredentialLookupID, CredentialGeneration: authority.CredentialGeneration, FromEndpoint: request.FromEndpoint, TargetRole: request.TargetRole, Body: request.Body, ArtifactIDs: request.ArtifactIDs, IdempotencyKey: idempotencyKey, Now: now})
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

func (h *handler) requestInvocation(w http.ResponseWriter, body []byte, machineID, conversationID string, now time.Time, idempotencyKey string) {
	if !ValidRequestToken(idempotencyKey) {
		writeError(w, http.StatusBadRequest, "Idempotency-Key is required")
		return
	}
	invocations, ok := h.store.(InvocationBackend)
	if !ok {
		writeStoreError(w, ErrMaintenance)
		return
	}
	var request struct {
		FromEndpoint   string `json:"from_endpoint"`
		TargetEndpoint string `json:"target_endpoint"`
	}
	if err := decodeJSON(body, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid invocation request")
		return
	}
	if !h.auth.AllowsEndpoint(machineID, request.FromEndpoint) {
		writeError(w, http.StatusForbidden, "authorization denied")
		return
	}
	invocation, duplicate, err := invocations.RequestInvocation(InvokeInput{ConversationID: conversationID, SenderMachineID: machineID, FromEndpoint: request.FromEndpoint, TargetEndpoint: request.TargetEndpoint, IdempotencyKey: idempotencyKey, Now: now})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	status := http.StatusCreated
	if duplicate || invocation.Status == InvocationAlreadyRunning {
		status = http.StatusOK
	}
	if !duplicate && invocation.Status == InvocationPending && h.auth.AllowsEndpoint(invocation.TargetMachineID, invocation.TargetEndpoint) {
		// This only accelerates the adapter's durable invocation lease. As with a
		// message wake, loss or duplication of the hint cannot change the start
		// decision and carries no control body.
		h.notifier.Publish(invocation.TargetMachineID, invocation.ConversationID, 1)
	}
	writeJSON(w, status, invocation)
}

func (h *handler) leaseInvocations(w http.ResponseWriter, body []byte, machineID string, now time.Time) {
	invocations, ok := h.store.(InvocationBackend)
	if !ok {
		writeStoreError(w, ErrMaintenance)
		return
	}
	var request struct {
		ConsumerID string `json:"consumer_id"`
		Limit      int    `json:"limit"`
	}
	if err := decodeJSON(body, &request); err != nil || !ValidRequestToken(request.ConsumerID) {
		writeError(w, http.StatusBadRequest, "invalid invocation lease request")
		return
	}
	if request.Limit == 0 {
		request.Limit = 50
	}
	leased, err := invocations.LeaseInvocations(machineID, request.ConsumerID, now, h.deliveryLeaseTTL, request.Limit)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	allowed := leased[:0]
	for _, invocation := range leased {
		if h.auth.AllowsEndpoint(machineID, invocation.TargetEndpoint) {
			allowed = append(allowed, invocation)
			continue
		}
		// An enrollment scope may narrow after the server queued work. Never
		// return process-start authority for an endpoint that is no longer in
		// scope. This is terminal policy rejection, not a runtime failure, so it
		// must not consume the bounded runtime retry budget.
		if err := invocations.RejectInvocation(machineID, invocation.ID, invocation.LeaseToken, invocation.LeaseGeneration, now); err != nil {
			writeStoreError(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"invocations": allowed})
}

func (h *handler) reportInvocation(w http.ResponseWriter, body []byte, machineID, invocationID string, now time.Time) {
	invocations, ok := h.store.(InvocationBackend)
	if !ok {
		writeStoreError(w, ErrMaintenance)
		return
	}
	var request struct {
		LeaseToken      string `json:"lease_token"`
		LeaseGeneration int64  `json:"lease_generation"`
		Accepted        bool   `json:"accepted"`
	}
	if err := decodeJSON(body, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid invocation outcome")
		return
	}
	if err := invocations.ReportInvocation(machineID, invocationID, request.LeaseToken, request.LeaseGeneration, request.Accepted, now); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
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
		case "invoke":
			capabilities |= CapInvoke
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
	case errors.Is(err, ErrRateLimited):
		retryAfter := RateLimitRetryAfterMin
		var limited *RateLimitedError
		if errors.As(err, &limited) && limited.RetryAfterSeconds > retryAfter {
			retryAfter = limited.RetryAfterSeconds
		}
		if retryAfter > RateLimitRetryAfterMaxBound {
			retryAfter = RateLimitRetryAfterMaxBound
		}
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		writeError(w, http.StatusTooManyRequests, "rate limited")
	case errors.Is(err, ErrCapacityExceeded):
		retryAfter := RateLimitRetryAfterMin
		var limited *CapacityError
		if errors.As(err, &limited) && limited.RetryAfterSeconds > retryAfter {
			retryAfter = limited.RetryAfterSeconds
		}
		if retryAfter > RateLimitRetryAfterMaxBound {
			retryAfter = RateLimitRetryAfterMaxBound
		}
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		writeError(w, http.StatusTooManyRequests, "capacity exceeded")
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
