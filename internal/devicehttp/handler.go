// Package devicehttp exposes the bounded network edge for device enrollment
// and bearer authentication. Host-local administration is deliberately absent.
package devicehttp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

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
	h.mux.Handle("GET /v1/device/session", h.authenticate(http.HandlerFunc(h.session)))
	return h
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
