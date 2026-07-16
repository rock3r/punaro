package v2

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"
)

// PermitIssuanceAuthorityProvider obtains the one fresh directory authority
// used to authorize a permit request. It must never serve a stale cached view.
type PermitIssuanceAuthorityProvider interface {
	ResolvePermitIssuanceAuthority(context.Context, time.Time) (PermitIssuanceAuthority, error)
}

// PermitRequestAuthorizer binds a holder-signed permit request to an
// independently authenticated transport identity. The issuer must not rely on
// possession of a holder signature as network admission: callers configure
// this with the enrolled machine-to-directory-device binding.
type PermitRequestAuthorizer interface {
	AuthorizePermitRequest(context.Context, PermitRequest) error
}

type permitHTTPHandler struct {
	issuer    *PermitIssuer
	authority PermitIssuanceAuthorityProvider
	authorize PermitRequestAuthorizer
	now       func() time.Time
}

// NewPermitHTTPHandler exposes only canonical holder-signed permit requests.
// It requires a separate route-admission binding in addition to verifying the
// directory device key, so a signature copied from one machine cannot be
// submitted by another enrolled machine.
func NewPermitHTTPHandler(issuer *PermitIssuer, authority PermitIssuanceAuthorityProvider, authorize PermitRequestAuthorizer, now func() time.Time) (http.Handler, error) {
	if issuer == nil || authority == nil || authorize == nil {
		return nil, errors.New("permit HTTP handler requires issuer, authority, and route admission")
	}
	if now == nil {
		now = time.Now
	}
	return &permitHTTPHandler{issuer: issuer, authority: authority, authorize: authorize, now: now}, nil
}

func (h *permitHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/v2/permits" {
		attachmentHTTPError(w, http.StatusNotFound)
		return
	}
	if r.URL.RawQuery != "" || r.URL.RawPath != "" || r.URL.EscapedPath() != r.URL.Path || r.Header.Get("Content-Encoding") != "" || r.Header.Get("Content-Type") != "application/cbor" || r.ContentLength <= 0 || r.ContentLength > maxPermitEncodedBytes {
		attachmentHTTPError(w, http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxPermitEncodedBytes+1))
	if err != nil || len(body) == 0 || len(body) > maxPermitEncodedBytes {
		attachmentHTTPError(w, http.StatusBadRequest)
		return
	}
	request, err := DecodePermitRequest(body)
	if err != nil {
		attachmentHTTPError(w, http.StatusBadRequest)
		return
	}
	if err := h.authorize.AuthorizePermitRequest(r.Context(), request); err != nil {
		attachmentHTTPError(w, http.StatusForbidden)
		return
	}
	now := h.now().UTC()
	authority, err := h.authority.ResolvePermitIssuanceAuthority(r.Context(), now)
	if err != nil || authority == nil {
		attachmentHTTPError(w, http.StatusForbidden)
		return
	}
	permit, _, err := h.issuer.Issue(r.Context(), request, authority)
	if err != nil {
		attachmentHTTPError(w, http.StatusForbidden)
		return
	}
	raw, err := EncodePermit(permit)
	if err != nil {
		attachmentHTTPError(w, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/cbor")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
	w.WriteHeader(http.StatusOK)
	// #nosec G705 -- raw is a bounded canonical permit generated locally and
	// emitted with a non-rendering CBOR content type.
	_, _ = w.Write(raw)
}
