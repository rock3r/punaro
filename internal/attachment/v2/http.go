package v2

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

// AttachmentAuthority is the fresh, root-authorized directory authority used
// to verify every attachment permit, operation signer, manifest, and envelope.
// An implementation must reject a stale, frozen, or non-current snapshot.
type AttachmentAuthority interface {
	DirectoryKeyResolver
	PermitAuthorityResolver
	OperationHolderResolver
}

// AttachmentAuthorityProvider resolves one fresh attachment authority view for
// an incoming request. The handler intentionally does not cache results: a
// stale or unavailable directory is a hard authorization failure.
type AttachmentAuthorityProvider interface {
	ResolveAttachmentAuthority(context.Context, time.Time) (AttachmentAuthority, error)
}

// AttachmentHTTPHandlerOptions configure the strict attachment-v2 relay API.
// The store and authority provider must be private, process-local dependencies.
type AttachmentHTTPHandlerOptions struct {
	Store     *SQLiteTransferStore
	Authority AttachmentAuthorityProvider
	Now       func() time.Time
}

type attachmentHTTPHandler struct {
	store     *SQLiteTransferStore
	authority AttachmentAuthorityProvider
	now       func() time.Time
}

// NewAttachmentHTTPHandler mounts only the fixed v2 attachment schema. It
// deliberately has no compatibility routes and no ambient machine identity:
// each request carries its own short-lived, directory-bound authority.
func NewAttachmentHTTPHandler(options AttachmentHTTPHandlerOptions) (http.Handler, error) {
	if options.Store == nil || options.Authority == nil {
		return nil, errors.New("attachment HTTP handler requires store and authority")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &attachmentHTTPHandler{store: options.Store, authority: options.Authority, now: options.Now}, nil
}

func (h *attachmentHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" || r.URL.Fragment != "" || r.URL.RawPath != "" || r.URL.EscapedPath() != r.URL.Path || r.Header.Get("Content-Encoding") != "" {
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
	if permit.TransferID != route.TransferID || permit.Operation != route.Operation || (route.AttemptGeneration != 0 && permit.AttemptGeneration != route.AttemptGeneration) {
		attachmentHTTPError(w, http.StatusUnauthorized)
		return
	}
	now := h.now().UTC()
	authority, err := h.authority.ResolveAttachmentAuthority(r.Context(), now)
	if err != nil || authority == nil {
		attachmentHTTPError(w, http.StatusForbidden)
		return
	}
	var responseCiphertext []byte
	if route.Operation == PermitOperationDownload {
		// Authenticate the short-lived holder credential before looking up an
		// immutable ciphertext frame, so an unsigned request cannot probe relay
		// storage. The exact route/body commitment is checked again below.
		if VerifyPermit(permit, authority, now) != nil || VerifyOperation(operation, permit, authority, now) != nil {
			attachmentHTTPError(w, http.StatusUnauthorized)
			return
		}
		chunk, found, err := h.store.LoadChunk(route.TransferID, route.ChunkIndex)
		if err != nil {
			attachmentHTTPError(w, http.StatusInternalServerError)
			return
		}
		if !found {
			attachmentHTTPError(w, http.StatusNotFound)
			return
		}
		responseCiphertext = chunk.Ciphertext
	}
	_, request, err := NewAttachmentOperationRequest(r.Method, r.URL.Path, body, responseCiphertext)
	if err != nil {
		attachmentHTTPError(w, http.StatusBadRequest)
		return
	}
	switch route.Operation {
	case PermitOperationOffer:
		record, _, err := h.store.Offer(r.Context(), permit, operation, request, route, body, authority, authority, authority, now)
		if err != nil {
			attachmentHTTPError(w, http.StatusForbidden)
			return
		}
		payload, err := encodeTransferResult(record)
		writeAttachmentCBOR(w, http.StatusOK, payload, err)
	case PermitOperationAccept:
		record, _, err := h.store.Accept(r.Context(), permit, operation, request, route, authority, authority, authority, now)
		if err != nil {
			attachmentHTTPError(w, http.StatusForbidden)
			return
		}
		payload, err := encodeTransferResult(record)
		writeAttachmentCBOR(w, http.StatusOK, payload, err)
	case PermitOperationUpload:
		chunk, _, err := h.store.Upload(r.Context(), permit, operation, request, route, authority, authority, authority, now)
		if err != nil {
			attachmentHTTPError(w, http.StatusForbidden)
			return
		}
		payload, err := encodeChunkResult(route.TransferID, chunk.Index, chunk.CiphertextCommitment)
		writeAttachmentCBOR(w, http.StatusOK, payload, err)
	case PermitOperationDownload:
		chunk, _, err := h.store.Download(r.Context(), permit, operation, request, route, authority, authority, authority, now)
		if err != nil {
			attachmentHTTPError(w, http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Length", decimalLength(len(chunk.Ciphertext)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(chunk.Ciphertext)
	case PermitOperationSignal, PermitOperationComplete:
		record, _, err := h.store.RedeemTransition(r.Context(), permit, operation, request, route, authority, authority, now)
		if err != nil {
			attachmentHTTPError(w, http.StatusForbidden)
			return
		}
		payload, err := encodeTransferResult(record)
		writeAttachmentCBOR(w, http.StatusOK, payload, err)
	default:
		attachmentHTTPError(w, http.StatusNotFound)
	}
}

func decodeAttachmentCredentials(r *http.Request) (Permit, OperationRecord, error) {
	permitRaw, err := decodeAttachmentHeader(r.Header.Values(attachmentPermitHeader), maxPermitEncodedBytes)
	if err != nil {
		return Permit{}, OperationRecord{}, err
	}
	operationRaw, err := decodeAttachmentHeader(r.Header.Values(attachmentOperationHeader), maxOperationEncodedBytes)
	if err != nil {
		return Permit{}, OperationRecord{}, err
	}
	permit, err := DecodePermit(permitRaw)
	if err != nil {
		return Permit{}, OperationRecord{}, err
	}
	operation, err := DecodeOperation(operationRaw)
	if err != nil {
		return Permit{}, OperationRecord{}, err
	}
	return permit, operation, nil
}

func decodeAttachmentHeader(values []string, maximum int) ([]byte, error) {
	if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > base64.RawURLEncoding.EncodedLen(maximum) {
		return nil, errors.New("invalid attachment credential header")
	}
	raw, err := base64.RawURLEncoding.DecodeString(values[0])
	if err != nil || len(raw) == 0 || len(raw) > maximum || base64.RawURLEncoding.EncodeToString(raw) != values[0] {
		return nil, errors.New("invalid attachment credential header")
	}
	return raw, nil
}

func readAttachmentHTTPBody(r *http.Request) ([]byte, error) {
	if r.ContentLength > maxAttachmentHTTPBody {
		return nil, errors.New("attachment body is too large")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxAttachmentHTTPBody+1))
	if err != nil || len(body) > maxAttachmentHTTPBody {
		return nil, errors.New("attachment body is too large")
	}
	return body, nil
}

func writeAttachmentCBOR(w http.ResponseWriter, status int, payload []byte, err error) {
	if err != nil {
		attachmentHTTPError(w, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/cbor")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", decimalLength(len(payload)))
	w.WriteHeader(status)
	// #nosec G705 -- payload is a bounded canonical result generated locally;
	// it is emitted with application/cbor rather than an HTML content type.
	_, _ = w.Write(payload)
}

func attachmentHTTPError(w http.ResponseWriter, status int) {
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
}

func decimalLength(length int) string {
	return strconv.Itoa(length)
}
