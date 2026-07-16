package v3

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"
)

const (
	attachmentPermitHeader    = "X-Punaro-Attachment-Permit"
	attachmentOperationHeader = "X-Punaro-Attachment-Operation"
	maxAttachmentHTTPBody     = 256<<10 + 16
)

// AttachmentAuthority is one freshly resolved v3 directory view. It supplies
// every key check needed by the request and never permits cached authority.
type AttachmentAuthority interface {
	DirectoryKeyResolver
	PermitAuthorityResolver
	OperationHolderResolver
}
type AttachmentAuthorityProvider interface {
	ResolveAttachmentAuthority(context.Context, time.Time) (AttachmentAuthority, error)
}
type AttachmentRequestAuthorizer interface {
	AuthorizeAttachmentRequest(context.Context, Permit) error
}
type AttachmentHTTPHandlerOptions struct {
	Store     *sourceStore
	Authority AttachmentAuthorityProvider
	Authorize AttachmentRequestAuthorizer
	Now       func() time.Time
}
type attachmentHTTPHandler struct {
	store     *sourceStore
	authority AttachmentAuthorityProvider
	authorize AttachmentRequestAuthorizer
	now       func() time.Time
}

// NewAttachmentHTTPHandler has no transport defaults: callers must provide
// independently authenticated machine-to-holder admission and fresh authority.
func NewAttachmentHTTPHandler(options AttachmentHTTPHandlerOptions) (http.Handler, error) {
	if options.Store == nil || options.Authority == nil || options.Authorize == nil {
		return nil, errors.New("v3 attachment handler requires store, authority, and route admission")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &attachmentHTTPHandler{store: options.Store, authority: options.Authority, authorize: options.Authorize, now: options.Now}, nil
}

func (h *attachmentHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" || r.URL.Fragment != "" || r.URL.RawPath != "" || r.URL.EscapedPath() != r.URL.Path || len(r.Header.Values("Content-Encoding")) != 0 {
		attachmentHTTPError(w, http.StatusBadRequest)
		return
	}
	route, err := ParseAttachmentRoute(r.Method, r.URL.Path)
	if err != nil {
		attachmentHTTPError(w, http.StatusNotFound)
		return
	}
	body, err := readAttachmentHTTPBody(r)
	if err != nil {
		attachmentHTTPError(w, http.StatusRequestEntityTooLarge)
		return
	}
	permit, operation, err := decodeAttachmentCredentials(r)
	if err != nil {
		attachmentHTTPError(w, http.StatusUnauthorized)
		return
	}
	if err := VerifyAttachmentRoute(route, permit); err != nil {
		attachmentHTTPError(w, http.StatusUnauthorized)
		return
	}
	if err := h.authorize.AuthorizeAttachmentRequest(r.Context(), permit); err != nil {
		attachmentHTTPError(w, http.StatusForbidden)
		return
	}
	now := h.now().UTC()
	authority, err := h.authority.ResolveAttachmentAuthority(r.Context(), now)
	if err != nil || authority == nil {
		attachmentHTTPError(w, http.StatusForbidden)
		return
	}
	_, request, err := NewAttachmentOperationRequest(r.Method, r.URL.Path, body, nil)
	if err != nil {
		attachmentHTTPError(w, http.StatusBadRequest)
		return
	}
	var result []byte
	var ciphertext []byte
	switch route.Operation {
	case permitOperationSourceInit:
		result, _, err = h.store.redeemSourceInit(r.Context(), authority, permit, operation, route, request, authority, authority, now)
	case permitOperationSourceUpload:
		result, _, err = h.store.redeemUpload(r.Context(), permit, operation, route, request, authority, authority, now)
	case permitOperationOffer:
		result, _, err = h.store.redeemOffer(r.Context(), permit, operation, route, request, authority, authority, authority, now)
	case permitOperationAccept:
		result, _, err = h.store.redeemAccept(r.Context(), permit, operation, route, request, authority, authority, authority, now)
	case permitOperationBegin:
		result, _, err = h.store.redeemBegin(r.Context(), permit, operation, route, request, authority, authority, now)
	case permitOperationDownload:
		ciphertext, result, _, err = h.store.redeemDownload(r.Context(), permit, operation, route, request, authority, authority, now)
	case permitOperationComplete:
		result, _, err = h.store.redeemComplete(r.Context(), permit, operation, route, request, authority, authority, now)
	case permitOperationCancel:
		result, _, err = h.store.redeemCancel(r.Context(), permit, operation, route, request, authority, authority, now)
	case permitOperationOutcome:
		result, _, err = h.store.redeemOutcome(r.Context(), permit, operation, route, request, authority, authority, now)
	default:
		attachmentHTTPError(w, http.StatusNotFound)
		return
	}
	if err != nil {
		attachmentHTTPError(w, http.StatusForbidden)
		return
	}
	if route.Operation == permitOperationDownload {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Length", strconv.Itoa(len(ciphertext)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(ciphertext)
		return
	}
	writeAttachmentCBOR(w, http.StatusOK, result)
}

func decodeAttachmentCredentials(r *http.Request) (Permit, OperationRecord, error) {
	p, err := decodeAttachmentHeader(r.Header.Values(attachmentPermitHeader), maxPermitEncodedBytes)
	if err != nil {
		return Permit{}, OperationRecord{}, err
	}
	o, err := decodeAttachmentHeader(r.Header.Values(attachmentOperationHeader), maxOperationEncodedBytes)
	if err != nil {
		return Permit{}, OperationRecord{}, err
	}
	permit, err := DecodePermit(p)
	if err != nil {
		return Permit{}, OperationRecord{}, err
	}
	op, err := DecodeOperation(o)
	return permit, op, err
}
func decodeAttachmentHeader(values []string, maximum int) ([]byte, error) {
	if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > base64.RawURLEncoding.EncodedLen(maximum) {
		return nil, errors.New("invalid v3 attachment credential")
	}
	raw, err := base64.RawURLEncoding.DecodeString(values[0])
	if err != nil || len(raw) == 0 || len(raw) > maximum || base64.RawURLEncoding.EncodeToString(raw) != values[0] {
		return nil, errors.New("invalid v3 attachment credential")
	}
	return raw, nil
}
func readAttachmentHTTPBody(r *http.Request) ([]byte, error) {
	if r.ContentLength > maxAttachmentHTTPBody {
		return nil, errors.New("v3 attachment body too large")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxAttachmentHTTPBody+1))
	if err != nil || len(body) > maxAttachmentHTTPBody {
		return nil, errors.New("v3 attachment body too large")
	}
	return body, nil
}
func writeAttachmentCBOR(w http.ResponseWriter, status int, payload []byte) {
	w.Header().Set("Content-Type", "application/cbor")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}
func attachmentHTTPError(w http.ResponseWriter, status int) {
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
}
