// Package trustedattachmenthttp exposes the bounded authenticated network edge
// for Punaro's trusted-relay attachment lifecycle.
package trustedattachmenthttp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rock3r/punaro/internal/ingress"
	"github.com/rock3r/punaro/internal/postgres"
	"github.com/rock3r/punaro/internal/trustedattachment"
)

const (
	maxMetadataBytes       = 4096
	maxConcurrentRequests  = 32
	shortRequestTimeout    = 5 * time.Second
	downloadRequestTimeout = 10 * time.Minute
	uploadRequestTimeout   = 9 * time.Minute
	uploadClaimLifetime    = 10 * time.Minute
)

type database interface {
	AuthenticateDevice(context.Context, string) (postgres.AuthenticatedDevice, error)
	ReserveAttachment(context.Context, postgres.AttachmentReservationRequest) (postgres.AttachmentReservation, error)
}

type lifecycle interface {
	Upload(context.Context, postgres.AuthenticatedDevice, string, time.Duration, io.Reader) (postgres.AttachmentArtifact, error)
	DownloadPrepared(context.Context, postgres.AttachmentDownloadRequest, trustedattachment.DownloadWriter, func(postgres.AttachmentDownload) error) (postgres.AttachmentDownload, error)
	Delete(context.Context, postgres.AttachmentDeleteRequest) (postgres.AttachmentDeletion, error)
}

type handler struct {
	database  database
	lifecycle lifecycle
	policy    *ingress.Policy
	slots     chan struct{}
	mux       *http.ServeMux
}

// New builds the versioned trusted-attachment routes. The caller remains
// responsible for enabling this separately reviewed surface in configuration.
func New(database database, lifecycle lifecycle, policy *ingress.Policy) http.Handler {
	h := &handler{database: database, lifecycle: lifecycle, policy: policy, slots: make(chan struct{}, maxConcurrentRequests), mux: http.NewServeMux()}
	h.mux.HandleFunc("POST /v1/trusted-attachments", h.reserve)
	h.mux.HandleFunc("PUT /v1/trusted-attachments/{artifact}/content", h.upload)
	h.mux.HandleFunc("GET /v1/trusted-attachments/{artifact}", h.download)
	h.mux.HandleFunc("DELETE /v1/trusted-attachments/{artifact}", h.delete)
	return h
}

func (h *handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if h.database == nil || h.lifecycle == nil || h.policy == nil || !h.policy.AllowsCredential(request) {
		writeError(response, http.StatusForbidden, "credential transport is forbidden")
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		response.Header().Set("Retry-After", "1")
		writeError(response, http.StatusTooManyRequests, "attachment service is busy")
		return
	}
	credential, ok := bearerCredential(request)
	if !ok {
		unauthenticated(response)
		return
	}
	operationCtx, cancel := context.WithTimeout(request.Context(), operationTimeout(request))
	defer cancel()
	device, err := h.database.AuthenticateDevice(operationCtx, credential)
	if err != nil {
		unauthenticated(response)
		return
	}
	h.mux.ServeHTTP(response, request.WithContext(context.WithValue(operationCtx, authenticatedDeviceKey{}, device)))
}

type authenticatedDeviceKey struct{}

func authenticatedDevice(ctx context.Context) (postgres.AuthenticatedDevice, bool) {
	device, ok := ctx.Value(authenticatedDeviceKey{}).(postgres.AuthenticatedDevice)
	return device, ok && device.PrincipalID != "" && device.LookupID != "" && device.Generation > 0
}

func bearerCredential(request *http.Request) (string, bool) {
	if len(request.Header.Values("Authorization")) != 1 {
		return "", false
	}
	value := request.Header.Get("Authorization")
	if !strings.HasPrefix(value, "Bearer ") {
		return "", false
	}
	credential := strings.TrimPrefix(value, "Bearer ")
	return credential, credential != "" && !strings.ContainsAny(credential, " \t\r\n")
}

func operationTimeout(request *http.Request) time.Duration {
	if request.Method == http.MethodPut && strings.HasPrefix(request.URL.Path, "/v1/trusted-attachments/") && strings.HasSuffix(request.URL.Path, "/content") {
		return uploadRequestTimeout
	}
	if request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/v1/trusted-attachments/") {
		return downloadRequestTimeout
	}
	return shortRequestTimeout
}

type reservationInput struct {
	ProjectID       string
	IdempotencyKey  string
	SizeBytes       int64
	SHA256          string
	DisplayName     string
	MediaType       string
	LifetimeSeconds int64
}

func (h *handler) reserve(response http.ResponseWriter, request *http.Request) {
	device, ok := authenticatedDevice(request.Context())
	if !ok {
		unauthenticated(response)
		return
	}
	if !exactMediaType(request, "application/json") || request.ContentLength > maxMetadataBytes {
		writeError(response, http.StatusUnsupportedMediaType, "application/json is required")
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxMetadataBytes+1))
	if err != nil || len(body) > maxMetadataBytes {
		writeError(response, http.StatusRequestEntityTooLarge, "request is too large")
		return
	}
	input, err := decodeReservation(body)
	if err != nil {
		writeError(response, http.StatusBadRequest, "request is malformed")
		return
	}
	var digest [sha256.Size]byte
	decoded, err := hex.DecodeString(input.SHA256)
	if err != nil || len(decoded) != sha256.Size {
		writeError(response, http.StatusBadRequest, "request is malformed")
		return
	}
	copy(digest[:], decoded)
	if input.LifetimeSeconds < 300 || input.LifetimeSeconds > 3600 {
		writeError(response, http.StatusBadRequest, "request is invalid")
		return
	}
	reservationRequest := postgres.AttachmentReservationRequest{PrincipalID: device.PrincipalID, ProjectID: input.ProjectID, IdempotencyKey: input.IdempotencyKey, SizeBytes: input.SizeBytes, SHA256: digest, DisplayName: input.DisplayName, MediaType: input.MediaType, Lifetime: time.Duration(input.LifetimeSeconds) * time.Second}
	if err := reservationRequest.Validate(); err != nil {
		writeError(response, http.StatusBadRequest, "request is invalid")
		return
	}
	reservation, err := h.database.ReserveAttachment(request.Context(), reservationRequest)
	if err != nil {
		writeLifecycleError(response, err)
		return
	}
	writeJSON(response, http.StatusCreated, reservationOutput(reservation))
}

func (h *handler) upload(response http.ResponseWriter, request *http.Request) {
	device, artifactID, ok := h.deviceArtifact(response, request)
	if !ok {
		return
	}
	if !exactMediaType(request, "application/octet-stream") || request.ContentLength < 1 || request.ContentLength > 16<<30 {
		writeError(response, http.StatusBadRequest, "exact application/octet-stream content length is required")
		return
	}
	controller := http.NewResponseController(response)
	if err := controller.SetReadDeadline(time.Now().Add(uploadRequestTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		writeError(response, http.StatusServiceUnavailable, "attachment stream deadline is unavailable")
		return
	}
	if err := controller.SetWriteDeadline(time.Now().Add(downloadRequestTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		writeError(response, http.StatusServiceUnavailable, "attachment stream deadline is unavailable")
		return
	}
	defer func() {
		_ = controller.SetReadDeadline(time.Time{})
		_ = controller.SetWriteDeadline(time.Time{})
	}()
	artifact, err := h.lifecycle.Upload(request.Context(), device, artifactID, uploadClaimLifetime, request.Body)
	if err != nil {
		writeLifecycleError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, artifactOutput(artifact))
}

func (h *handler) download(response http.ResponseWriter, request *http.Request) {
	device, artifactID, ok := h.deviceArtifact(response, request)
	if !ok {
		return
	}
	writer := &responseDownloadWriter{ResponseWriter: response, controller: http.NewResponseController(response)}
	_, err := h.lifecycle.DownloadPrepared(request.Context(), postgres.AttachmentDownloadRequest{PrincipalID: device.PrincipalID, CredentialLookupID: device.LookupID, CredentialGeneration: device.Generation, ArtifactID: artifactID}, writer, func(metadata postgres.AttachmentDownload) error {
		response.Header().Set("Content-Type", metadata.MediaType)
		response.Header().Set("Content-Length", strconv.FormatInt(metadata.SizeBytes, 10))
		response.Header().Set("Content-Disposition", "attachment")
		response.Header().Set("X-Punaro-Artifact-ID", metadata.ArtifactID)
		response.Header().Set("X-Punaro-SHA256", hex.EncodeToString(metadata.SHA256[:]))
		response.Header().Set("X-Punaro-Display-Name", base64.RawURLEncoding.EncodeToString([]byte(metadata.DisplayName)))
		return nil
	})
	if err != nil {
		if writer.wrote {
			return
		}
		for _, name := range []string{"Content-Length", "Content-Disposition", "X-Punaro-Artifact-ID", "X-Punaro-SHA256", "X-Punaro-Display-Name"} {
			response.Header().Del(name)
		}
		writeLifecycleError(response, err)
	}
}

func (h *handler) delete(response http.ResponseWriter, request *http.Request) {
	device, artifactID, ok := h.deviceArtifact(response, request)
	if !ok {
		return
	}
	if len(request.Header.Values("Idempotency-Key")) != 1 || uuid.Validate(request.Header.Get("Idempotency-Key")) != nil || request.Body != nil && request.ContentLength != 0 {
		writeError(response, http.StatusBadRequest, "one idempotency key and no body are required")
		return
	}
	deletion, err := h.lifecycle.Delete(request.Context(), postgres.AttachmentDeleteRequest{PrincipalID: device.PrincipalID, CredentialLookupID: device.LookupID, CredentialGeneration: device.Generation, ArtifactID: artifactID, IdempotencyKey: request.Header.Get("Idempotency-Key")})
	if err != nil {
		writeLifecycleError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, deletionOutput(deletion))
}

func (h *handler) deviceArtifact(response http.ResponseWriter, request *http.Request) (postgres.AuthenticatedDevice, string, bool) {
	device, ok := authenticatedDevice(request.Context())
	artifactID := request.PathValue("artifact")
	if !ok {
		unauthenticated(response)
		return postgres.AuthenticatedDevice{}, "", false
	}
	if uuid.Validate(artifactID) != nil {
		writeError(response, http.StatusNotFound, "attachment not found")
		return postgres.AuthenticatedDevice{}, "", false
	}
	return device, artifactID, true
}

type responseDownloadWriter struct {
	http.ResponseWriter
	controller *http.ResponseController
	wrote      bool
}

func (writer *responseDownloadWriter) Write(value []byte) (int, error) {
	written, err := writer.ResponseWriter.Write(value)
	writer.wrote = writer.wrote || written != 0
	return written, err
}

func (writer *responseDownloadWriter) SetWriteDeadline(deadline time.Time) error {
	return writer.controller.SetWriteDeadline(deadline)
}

func exactMediaType(request *http.Request, expected string) bool {
	if len(request.Header.Values("Content-Type")) != 1 {
		return false
	}
	mediaType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	return err == nil && mediaType == expected && len(parameters) == 0
}

func decodeReservation(body []byte) (reservationInput, error) {
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return reservationInput{}, errors.New("not an object")
	}
	var input reservationInput
	seen := make(map[string]struct{}, 7)
	for decoder.More() {
		token, tokenErr := decoder.Token()
		name, nameOK := token.(string)
		if tokenErr != nil || !nameOK {
			return reservationInput{}, errors.New("invalid field")
		}
		if _, duplicate := seen[name]; duplicate {
			return reservationInput{}, errors.New("duplicate field")
		}
		seen[name] = struct{}{}
		switch name {
		case "project_id":
			err = decoder.Decode(&input.ProjectID)
		case "idempotency_key":
			err = decoder.Decode(&input.IdempotencyKey)
		case "size_bytes":
			err = decoder.Decode(&input.SizeBytes)
		case "sha256":
			err = decoder.Decode(&input.SHA256)
		case "display_name":
			err = decoder.Decode(&input.DisplayName)
		case "media_type":
			err = decoder.Decode(&input.MediaType)
		case "lifetime_seconds":
			err = decoder.Decode(&input.LifetimeSeconds)
		default:
			return reservationInput{}, errors.New("unknown field")
		}
		if err != nil {
			return reservationInput{}, err
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') || len(seen) != 7 || input.ProjectID == "" || input.IdempotencyKey == "" || input.SHA256 == "" || input.DisplayName == "" || input.MediaType == "" {
		return reservationInput{}, errors.New("incomplete object")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return reservationInput{}, errors.New("trailing input")
	}
	return input, nil
}

func reservationOutput(value postgres.AttachmentReservation) map[string]any {
	return map[string]any{"artifact_id": value.ArtifactID, "project_id": value.ProjectID, "size_bytes": value.SizeBytes, "sha256": hex.EncodeToString(value.SHA256[:]), "display_name": value.DisplayName, "media_type": value.MediaType, "state": value.State, "expires_at": value.ExpiresAt}
}

func artifactOutput(value postgres.AttachmentArtifact) map[string]any {
	return map[string]any{"artifact_id": value.ArtifactID, "project_id": value.ProjectID, "size_bytes": value.SizeBytes, "sha256": hex.EncodeToString(value.SHA256[:]), "state": value.State, "ready_at": value.ReadyAt}
}

func deletionOutput(value postgres.AttachmentDeletion) map[string]any {
	return map[string]any{"artifact_id": value.ArtifactID, "project_id": value.ProjectID, "state": value.State, "gc_after": value.GCAfter, "deleted_at": value.DeletedAt}
}

func writeLifecycleError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, postgres.ErrForbidden), errors.Is(err, postgres.ErrAttachmentStale):
		writeError(response, http.StatusNotFound, "attachment not found")
	case errors.Is(err, postgres.ErrIdempotencyConflict):
		writeError(response, http.StatusConflict, "attachment operation conflicts")
	case errors.Is(err, postgres.ErrAttachmentBusy):
		response.Header().Set("Retry-After", "30")
		writeError(response, http.StatusLocked, "attachment operation is busy")
	case errors.Is(err, postgres.ErrAttachmentQuota):
		writeError(response, http.StatusInsufficientStorage, "attachment quota is exhausted")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		writeError(response, http.StatusRequestTimeout, "attachment operation timed out")
	default:
		writeError(response, http.StatusServiceUnavailable, "attachment service is unavailable")
	}
}

func unauthenticated(response http.ResponseWriter) {
	response.Header().Set("WWW-Authenticate", "Bearer")
	writeError(response, http.StatusUnauthorized, "unauthenticated")
}

func writeError(response http.ResponseWriter, status int, message string) {
	writeJSON(response, status, map[string]string{"error": message})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
