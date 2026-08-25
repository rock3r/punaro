// Package devicehttp exposes the bounded network edge for device enrollment
// and bearer authentication. Host-local administration is deliberately absent.
package devicehttp

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rock3r/punaro/internal/ingress"
	punaropostgres "github.com/rock3r/punaro/internal/postgres"
)

const maxRequestBytes = 4096

const (
	maxConcurrentRequests = 32
	storeOperationTimeout = 5 * time.Second
)

type store interface {
	RedeemEnrollment(context.Context, punaropostgres.RedeemEnrollment) (punaropostgres.DeviceCredential, error)
	AuthenticateDevice(context.Context, string) (punaropostgres.AuthenticatedDevice, error)
	SelfRevokeDevice(context.Context, string, string) (punaropostgres.DeviceRevocation, error)
}

type legacyEnrollmentStore interface {
	RedeemLegacyEnrollment(context.Context, punaropostgres.LegacyExchangeProof, punaropostgres.RedeemEnrollment) (punaropostgres.DeviceCredential, error)
}

type handler struct {
	store   store
	policy  *ingress.Policy
	mux     *http.ServeMux
	slots   chan struct{}
	timeout time.Duration
}

// New builds the only device credential ingress routes.
func New(database store, policy *ingress.Policy) http.Handler {
	return newHandler(database, policy, maxConcurrentRequests, storeOperationTimeout)
}

func newHandler(database store, policy *ingress.Policy, concurrency int, timeout time.Duration) http.Handler {
	if concurrency < 1 {
		concurrency = 1
	}
	h := &handler{store: database, policy: policy, mux: http.NewServeMux(), slots: make(chan struct{}, concurrency), timeout: timeout}
	h.mux.HandleFunc("POST /v1/enrollments/redeem", h.redeem)
	h.mux.HandleFunc("POST /v1/legacy-enrollments/redeem", h.redeemLegacy)
	h.mux.Handle("GET /v1/device/session", h.authenticate(http.HandlerFunc(h.session)))
	h.mux.HandleFunc("POST /v1/device/session/revoke", h.selfRevoke)
	return h
}

func (h *handler) redeemLegacy(w http.ResponseWriter, r *http.Request) {
	if len(r.Header.Values("Content-Type")) != 1 {
		writeError(w, http.StatusUnsupportedMediaType, "application/json is required")
		return
	}
	mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || len(params) != 0 {
		writeError(w, http.StatusUnsupportedMediaType, "application/json is required")
		return
	}
	if r.ContentLength > maxRequestBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "request is too large")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "request is malformed")
		return
	}
	if len(body) > maxRequestBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "request is too large")
		return
	}
	redeem, proof, err := decodeLegacyRedeem(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "request is malformed")
		return
	}
	store, ok := h.store.(legacyEnrollmentStore)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "enrollment service is unavailable")
		return
	}
	operationCtx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()
	credential, err := store.RedeemLegacyEnrollment(operationCtx, proof, redeem)
	if err != nil {
		if errors.Is(err, punaropostgres.ErrInvalidEnrollment) {
			unauthenticated(w)
			return
		}
		writeError(w, http.StatusServiceUnavailable, "enrollment service is unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, credential)
}

func decodeLegacyRedeem(body []byte) (punaropostgres.RedeemEnrollment, punaropostgres.LegacyExchangeProof, error) {
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return punaropostgres.RedeemEnrollment{}, punaropostgres.LegacyExchangeProof{}, errors.New("invalid legacy redemption")
	}
	values := make(map[string]string, 6)
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok {
			return punaropostgres.RedeemEnrollment{}, punaropostgres.LegacyExchangeProof{}, errors.New("invalid legacy redemption")
		}
		if _, duplicate := values[name]; duplicate {
			return punaropostgres.RedeemEnrollment{}, punaropostgres.LegacyExchangeProof{}, errors.New("invalid legacy redemption")
		}
		switch name {
		case "enrollment_id", "client_binding", "code", "idempotency_key", "legacy_public_key", "legacy_signature":
		default:
			return punaropostgres.RedeemEnrollment{}, punaropostgres.LegacyExchangeProof{}, errors.New("invalid legacy redemption")
		}
		var value string
		if decoder.Decode(&value) != nil || value == "" {
			return punaropostgres.RedeemEnrollment{}, punaropostgres.LegacyExchangeProof{}, errors.New("invalid legacy redemption")
		}
		values[name] = value
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') || len(values) != 6 {
		return punaropostgres.RedeemEnrollment{}, punaropostgres.LegacyExchangeProof{}, errors.New("invalid legacy redemption")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return punaropostgres.RedeemEnrollment{}, punaropostgres.LegacyExchangeProof{}, errors.New("invalid legacy redemption")
	}
	publicKey, publicErr := base64.RawURLEncoding.Strict().DecodeString(values["legacy_public_key"])
	signature, signatureErr := base64.RawURLEncoding.Strict().DecodeString(values["legacy_signature"])
	if publicErr != nil || signatureErr != nil || len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(publicKey) != values["legacy_public_key"] || base64.RawURLEncoding.EncodeToString(signature) != values["legacy_signature"] {
		return punaropostgres.RedeemEnrollment{}, punaropostgres.LegacyExchangeProof{}, errors.New("invalid legacy redemption")
	}
	redeem := punaropostgres.RedeemEnrollment{EnrollmentID: values["enrollment_id"], ClientBinding: values["client_binding"], Code: values["code"], IdempotencyKey: values["idempotency_key"]}
	proof := punaropostgres.LegacyExchangeProof{PublicKey: ed25519.PublicKey(publicKey), Signature: signature}
	return redeem, proof, nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.store == nil || h.policy == nil || !h.policy.AllowsCredential(r) {
		writeError(w, http.StatusForbidden, "credential transport is forbidden")
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, "credential ingress is busy")
		return
	}
	h.mux.ServeHTTP(w, r)
}

func (h *handler) redeem(w http.ResponseWriter, r *http.Request) {
	if len(r.Header.Values("Content-Type")) != 1 {
		writeError(w, http.StatusUnsupportedMediaType, "application/json is required")
		return
	}
	mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || len(params) != 0 {
		writeError(w, http.StatusUnsupportedMediaType, "application/json is required")
		return
	}
	if r.ContentLength > maxRequestBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "request is too large")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "request is malformed")
		return
	}
	if len(body) > maxRequestBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "request is too large")
		return
	}
	redeem, err := decodeRedeem(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "request is malformed")
		return
	}
	operationCtx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()
	credential, err := h.store.RedeemEnrollment(operationCtx, redeem)
	if err != nil {
		if errors.Is(err, punaropostgres.ErrInvalidEnrollment) {
			unauthenticated(w)
			return
		}
		writeError(w, http.StatusServiceUnavailable, "enrollment service is unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, credential)
}

func decodeRedeem(body []byte) (punaropostgres.RedeemEnrollment, error) {
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return punaropostgres.RedeemEnrollment{}, errors.New("not an object")
	}
	values := make(map[string]string, 4)
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok {
			return punaropostgres.RedeemEnrollment{}, errors.New("invalid field")
		}
		if _, duplicate := values[name]; duplicate {
			return punaropostgres.RedeemEnrollment{}, errors.New("duplicate field")
		}
		switch name {
		case "enrollment_id", "client_binding", "code", "idempotency_key":
		default:
			return punaropostgres.RedeemEnrollment{}, errors.New("unknown field")
		}
		var value string
		if err := decoder.Decode(&value); err != nil || value == "" {
			return punaropostgres.RedeemEnrollment{}, errors.New("invalid value")
		}
		values[name] = value
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') || len(values) != 4 {
		return punaropostgres.RedeemEnrollment{}, errors.New("incomplete object")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return punaropostgres.RedeemEnrollment{}, errors.New("trailing input")
	}
	return punaropostgres.RedeemEnrollment{EnrollmentID: values["enrollment_id"], ClientBinding: values["client_binding"], Code: values["code"], IdempotencyKey: values["idempotency_key"]}, nil
}

type authenticatedKey struct{}

// AuthenticatedDevice returns the independently authenticated device identity.
func AuthenticatedDevice(ctx context.Context) (punaropostgres.AuthenticatedDevice, bool) {
	device, ok := ctx.Value(authenticatedKey{}).(punaropostgres.AuthenticatedDevice)
	return device, ok
}

func (h *handler) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.Header.Values("Authorization")) != 1 {
			unauthenticated(w)
			return
		}
		authorization := r.Header.Get("Authorization")
		if !strings.HasPrefix(authorization, "Bearer ") {
			unauthenticated(w)
			return
		}
		credential := strings.TrimPrefix(authorization, "Bearer ")
		if credential == "" || strings.ContainsAny(credential, " \t\r\n") {
			unauthenticated(w)
			return
		}
		operationCtx, cancel := context.WithTimeout(r.Context(), h.timeout)
		defer cancel()
		device, err := h.store.AuthenticateDevice(operationCtx, credential)
		if err != nil {
			unauthenticated(w)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), authenticatedKey{}, device)))
	})
}

func (h *handler) session(w http.ResponseWriter, r *http.Request) {
	if _, ok := AuthenticatedDevice(r.Context()); !ok {
		unauthenticated(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "authenticated"})
}

func (h *handler) selfRevoke(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > 0 {
		writeError(w, http.StatusBadRequest, "request is malformed")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1))
	if err != nil || len(body) != 0 || len(r.Header.Values("Idempotency-Key")) != 1 {
		writeError(w, http.StatusBadRequest, "request is malformed")
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	parsedKey, err := uuid.Parse(idempotencyKey)
	if err != nil || parsedKey == uuid.Nil || parsedKey.String() != idempotencyKey {
		writeError(w, http.StatusBadRequest, "request is malformed")
		return
	}
	credential, ok := bearerCredential(r)
	if !ok {
		unauthenticated(w)
		return
	}
	operationCtx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()
	result, err := h.store.SelfRevokeDevice(operationCtx, credential, idempotencyKey)
	if err != nil {
		if errors.Is(err, punaropostgres.ErrUnauthenticated) {
			unauthenticated(w)
			return
		}
		writeError(w, http.StatusServiceUnavailable, "revocation service is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func bearerCredential(r *http.Request) (string, bool) {
	if len(r.Header.Values("Authorization")) != 1 {
		return "", false
	}
	authorization := r.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Bearer ") {
		return "", false
	}
	credential := strings.TrimPrefix(authorization, "Bearer ")
	return credential, credential != "" && !strings.ContainsAny(credential, " \t\r\n")
}

func unauthenticated(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeError(w, http.StatusUnauthorized, "unauthenticated")
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
