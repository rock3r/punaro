package attachment

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// Authenticator obtains a verified device principal from the enclosing relay
// authentication layer. The attachment handler never reads a principal from
// request JSON, headers, or query parameters.
type Authenticator interface {
	Authenticate(context.Context, *http.Request) (Principal, error)
}

// AuthFunc adapts a function into an Authenticator.
type AuthFunc func(context.Context, *http.Request) (Principal, error)

// Authenticate implements Authenticator.
func (f AuthFunc) Authenticate(ctx context.Context, request *http.Request) (Principal, error) {
	return f(ctx, request)
}

// HTTP exposes strict, authenticated attachment control-plane routes. Callers
// must mount it behind the same machine authentication used by the relay.
type HTTP struct {
	service       *Service
	authenticator Authenticator
}

// NewHTTP creates an attachment handler. A nil dependency is deliberately
// unusable, preventing accidental unauthenticated mounting.
func NewHTTP(service *Service, authenticator Authenticator) *HTTP {
	return &HTTP{service: service, authenticator: authenticator}
}

// ServeHTTP serves only known v2 control-plane routes.
func (h *HTTP) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if h.service == nil || h.authenticator == nil {
		writeError(writer, http.StatusServiceUnavailable)
		return
	}
	if request.URL.RawQuery != "" {
		writeError(writer, http.StatusBadRequest)
		return
	}
	principal, err := h.authenticator.Authenticate(request.Context(), request)
	if err != nil || principal.DeviceID == "" {
		writeError(writer, http.StatusUnauthorized)
		return
	}
	segments := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	if request.Method == http.MethodPost && len(segments) == 4 && segments[0] == "v1" && segments[1] == "conversations" && segments[3] == "attachments" {
		h.createOffer(writer, request, principal, segments[2])
		return
	}
	if request.Method == http.MethodPost && len(segments) == 4 && segments[0] == "v1" && segments[1] == "attachment-offers" && segments[3] == "accept" {
		h.acceptOffer(writer, principal, segments[2])
		return
	}
	if request.Method == http.MethodPost && len(segments) == 4 && segments[0] == "v1" && segments[1] == "attachment-offers" && segments[3] == "complete" {
		h.complete(writer, request, principal, segments[2])
		return
	}
	if (request.Method == http.MethodPost || request.Method == http.MethodGet) && len(segments) == 4 && segments[0] == "v1" && segments[1] == "attachment-offers" && segments[3] == "signal" {
		h.signal(writer, request, principal, segments[2])
		return
	}
	if len(segments) == 7 && segments[0] == "v1" && segments[1] == "attachment-offers" && segments[3] == "artifacts" && segments[5] == "chunks" {
		h.chunk(writer, request, principal, segments[2], segments[4], segments[6])
		return
	}
	writeError(writer, http.StatusNotFound)
}

func (h *HTTP) signal(writer http.ResponseWriter, request *http.Request, principal Principal, offerID string) {
	if request.Method == http.MethodGet {
		session, _ := sessionFromRequest(request)
		signals, err := h.service.SignalsFor(principal, offerID, session)
		if err != nil {
			writeError(writer, http.StatusNotFound)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(writer).Encode(signals)
		return
	}
	defer func() { _ = request.Body.Close() }()
	payload, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, maxSignalPayload))
	if err != nil || len(payload) == 0 {
		writeError(writer, http.StatusBadRequest)
		return
	}
	session, _ := sessionFromRequest(request)
	if err := h.service.Signal(principal, offerID, session, payload); err != nil {
		writeError(writer, http.StatusNotFound)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusNoContent)
}

func (h *HTTP) complete(writer http.ResponseWriter, request *http.Request, principal Principal, offerID string) {
	defer func() { _ = request.Body.Close() }()
	decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, 8<<10))
	decoder.DisallowUnknownFields()
	var body struct {
		PlaintextHash string `json:"plaintext_hash"`
	}
	if err := decoder.Decode(&body); err != nil {
		writeError(writer, http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(writer, http.StatusBadRequest)
		return
	}
	decoded, err := base64.RawStdEncoding.DecodeString(body.PlaintextHash)
	if err != nil || len(decoded) != hashSize {
		writeError(writer, http.StatusBadRequest)
		return
	}
	var plaintextHash [hashSize]byte
	copy(plaintextHash[:], decoded)
	session, ok := sessionFromRequest(request)
	if !ok || h.service.Complete(principal, offerID, session, plaintextHash) != nil {
		writeError(writer, http.StatusNotFound)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusNoContent)
}

func (h *HTTP) chunk(writer http.ResponseWriter, request *http.Request, principal Principal, offerID, artifactID, rawIndex string) {
	index, err := strconv.Atoi(rawIndex)
	if err != nil || index < 0 {
		writeError(writer, http.StatusNotFound)
		return
	}
	switch request.Method {
	case http.MethodPut:
		defer func() { _ = request.Body.Close() }()
		ciphertext, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, 256<<10))
		if err != nil || len(ciphertext) == 0 {
			writeError(writer, http.StatusBadRequest)
			return
		}
		frame := Chunk{Index: index, Ciphertext: ciphertext, Hash: hash("punaro/attachment/ciphertext/v2\x00", ciphertext)}
		if err := h.service.PutChunkByOfferID(principal, offerID, artifactID, frame); err != nil {
			writeError(writer, http.StatusNotFound)
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusNoContent)
	case http.MethodGet:
		session, ok := sessionFromRequest(request)
		if !ok {
			writeError(writer, http.StatusNotFound)
			return
		}
		frame, err := h.service.GetChunkByOfferID(principal, offerID, session, artifactID, index)
		if err != nil {
			writeError(writer, http.StatusNotFound)
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Content-Type", "application/octet-stream")
		_, _ = writer.Write(frame.Ciphertext)
	default:
		writeError(writer, http.StatusMethodNotAllowed)
	}
}

func sessionFromRequest(request *http.Request) (Session, bool) {
	generation, err := strconv.ParseUint(request.Header.Get("X-Punaro-Attachment-Generation"), 10, 64)
	token := request.Header.Get("X-Punaro-Attachment-Session")
	if err != nil || token == "" {
		return Session{}, false
	}
	return Session{Token: token, Generation: generation}, true
}

func (h *HTTP) acceptOffer(writer http.ResponseWriter, principal Principal, offerID string) {
	session, err := h.service.AcceptOffer(principal, offerID)
	if err != nil {
		writeError(writer, http.StatusNotFound)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(writer).Encode(struct {
		Generation uint64 `json:"generation"`
		Token      string `json:"token"`
	}{Generation: session.Generation, Token: session.Token})
}

func (h *HTTP) createOffer(writer http.ResponseWriter, request *http.Request, principal Principal, conversation string) {
	defer func() { _ = request.Body.Close() }()
	decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, 8<<10))
	decoder.DisallowUnknownFields()
	var body struct {
		Recipient          string `json:"recipient"`
		TransferID         string `json:"transfer_id"`
		ArtifactID         string `json:"artifact_id"`
		ChunkCount         int    `json:"chunk_count"`
		MaxCiphertextBytes int    `json:"max_ciphertext_bytes"`
		PlaintextHash      string `json:"plaintext_hash"`
	}
	if err := decoder.Decode(&body); err != nil || decoder.More() {
		writeError(writer, http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(writer, http.StatusBadRequest)
		return
	}
	plaintextHash, err := base64.RawStdEncoding.DecodeString(body.PlaintextHash)
	if err != nil || len(plaintextHash) != hashSize {
		writeError(writer, http.StatusBadRequest)
		return
	}
	var spec OfferSpec
	copy(spec.PlaintextHash[:], plaintextHash)
	spec.ArtifactID = body.ArtifactID
	spec.ChunkCount = body.ChunkCount
	spec.MaxCiphertextBytes = body.MaxCiphertextBytes
	if !spec.valid() {
		writeError(writer, http.StatusBadRequest)
		return
	}
	idempotencyKey := request.Header.Get("Idempotency-Key")
	if len(idempotencyKey) == 0 || len(idempotencyKey) > 128 {
		writeError(writer, http.StatusBadRequest)
		return
	}
	offer, err := h.service.CreateOfferWithIdempotency(principal, conversation, body.Recipient, body.TransferID, idempotencyKey, spec)
	if err != nil {
		writeError(writer, http.StatusForbidden)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(writer).Encode(struct {
		OfferID string `json:"offer_id"`
	}{OfferID: offer.ID})
}

func writeError(writer http.ResponseWriter, status int) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
}
