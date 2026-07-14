package relay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"time"
)

type authenticatedMachineContextKey struct{}

// AuthenticatedMachineID obtains the enrolled transport identity inserted by
// MachineAuthenticationMiddleware. It is intentionally absent unless the
// request passed durable replay-protected signature verification.
func AuthenticatedMachineID(ctx context.Context) (string, bool) {
	machineID, found := ctx.Value(authenticatedMachineContextKey{}).(string)
	return machineID, found && machineID != ""
}

// NewMachineAuthenticationMiddleware authenticates the exact bounded body of
// a route request, restores that body for the downstream handler, and binds
// the enrolled machine identity in request context. It rejects URL components
// outside CanonicalRequest before nonce use because they are not signed.
func NewMachineAuthenticationMiddleware(auth *Authenticator, maxBodyBytes int64, now func() time.Time) (func(http.Handler) http.Handler, error) {
	if auth == nil || maxBodyBytes < 0 {
		return nil, errors.New("invalid machine authentication middleware")
	}
	if now == nil {
		now = time.Now
	}
	return func(next http.Handler) http.Handler {
		if next == nil {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				writeError(w, http.StatusInternalServerError, "handler unavailable")
			})
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r == nil || r.URL == nil || r.Body == nil || r.URL.RawQuery != "" || r.URL.RawPath != "" || r.URL.EscapedPath() != r.URL.Path || r.ContentLength > maxBodyBytes {
				writeError(w, http.StatusBadRequest, "invalid signed request")
				return
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
			if err != nil || int64(len(body)) > maxBodyBytes {
				writeError(w, http.StatusBadRequest, "invalid signed request")
				return
			}
			machineID, err := auth.AuthenticateHTTP(r, body, now().UTC())
			if err != nil {
				writeError(w, http.StatusUnauthorized, "authentication required")
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
			r = r.WithContext(context.WithValue(r.Context(), authenticatedMachineContextKey{}, machineID))
			next.ServeHTTP(w, r)
		})
	}, nil
}
