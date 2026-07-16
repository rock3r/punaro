package v3

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"
)

// PermitIssuanceAuthorityProvider obtains one newly verified directory view
// for each holder-signed request. It must not serve stale cached authority.
type PermitIssuanceAuthorityProvider interface {
	ResolvePermitIssuanceAuthority(context.Context, time.Time) (PermitIssuanceAuthority, error)
}

// PermitRequestAuthorizer binds the holder named in the signed request to the
// independently authenticated enrolled machine that submitted it.
type PermitRequestAuthorizer interface {
	AuthorizePermitRequest(context.Context, PermitRequest) error
}

type permitHTTPHandler struct {
	issuer    *PermitIssuer
	authority PermitIssuanceAuthorityProvider
	authorize PermitRequestAuthorizer
	now       func() time.Time
}

// NewPermitHTTPHandler exposes only one strict CBOR issuance route. It does
// not accept a holder signature as transport authentication; callers must
// supply enrolled-machine route admission separately.
func NewPermitHTTPHandler(issuer *PermitIssuer, authority PermitIssuanceAuthorityProvider, authorize PermitRequestAuthorizer, now func() time.Time) (http.Handler, error) {
	if issuer == nil || issuer.store == nil || authority == nil || authorize == nil {
		return nil, errors.New("v3 permit HTTP handler requires issuer, authority, and route admission")
	}
	if now == nil {
		now = time.Now
	}
	return &permitHTTPHandler{issuer: issuer, authority: authority, authorize: authorize, now: now}, nil
}

func (h *permitHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/v3/permits" {
		attachmentHTTPError(w, http.StatusNotFound)
		return
	}
	contentTypes := r.Header.Values("Content-Type")
	if r.URL.RawQuery != "" || r.URL.Fragment != "" || r.URL.RawPath != "" || r.URL.EscapedPath() != r.URL.Path || len(r.Header.Values("Content-Encoding")) != 0 || len(contentTypes) != 1 || contentTypes[0] != "application/cbor" || r.ContentLength <= 0 || r.ContentLength > maxPermitRequestEncodedBytes {
		attachmentHTTPError(w, http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxPermitRequestEncodedBytes+1))
	if err != nil || len(body) == 0 || len(body) > maxPermitRequestEncodedBytes {
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
	permit, replayed, err := h.issuer.Issue(r.Context(), request, authority)
	if err != nil {
		attachmentHTTPError(w, http.StatusForbidden)
		return
	}
	// Source-init creates its source and records its permit in the same source
	// transaction. Every later operation must be registered first, so issuance
	// alone can never create a redeemable capability for an unknown lifecycle.
	nowUnix := now.Unix()
	if nowUnix < 0 {
		attachmentHTTPError(w, http.StatusForbidden)
		return
	}
	if permit.Operation != permitOperationSourceInit {
		// An expired exact issuance replay is an outcome-correlation receipt,
		// not a renewed capability. It must already be durably registered with
		// the source; never pass it through fresh admission or expiry checks.
		if replayed && permit.ExpiresAt <= uint64(nowUnix) {
			if err := h.issuer.store.hasIssuedPermit(r.Context(), permit); err != nil {
				attachmentHTTPError(w, http.StatusForbidden)
				return
			}
		} else if err := h.issuer.store.issuePermit(r.Context(), permit, authority, now); err != nil {
			attachmentHTTPError(w, http.StatusForbidden)
			return
		}
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
	// #nosec G705 -- raw is a bounded canonical permit generated and verified
	// locally, emitted as non-rendering CBOR.
	_, _ = w.Write(raw)
}
