package trustedattachmentclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

const maxResponseMetadataBytes = 4096

// Artifact is the exact immutable server declaration returned by Send.
type Artifact struct {
	ArtifactID string
	ProjectID  string
	SizeBytes  int64
	SHA256     [sha256.Size]byte
	State      string
}

// Deletion is the content-free tombstone result returned by Delete.
type Deletion struct {
	ArtifactID string
	ProjectID  string
	State      string
}

// RequestError distinguishes a safe same-operation retry from a terminal
// protocol or authority rejection without exposing response bodies.
type RequestError struct {
	StatusCode int
	Retryable  bool
	operation  string
}

func (err *RequestError) Error() string {
	return "trusted attachment " + err.operation + " failed"
}

// SendRequest binds one local regular file to a stable reservation operation.
type SendRequest struct {
	ProjectID      string
	IdempotencyKey string
	Path           string
	DisplayName    string
	MediaType      string
}

// Client is a bounded native trusted-attachment HTTP client.
type Client struct {
	base         *url.URL
	credential   string
	http         *http.Client
	receiveSlots chan struct{}
}

// New validates one fixed origin and installs a no-redirect policy.
func New(rawBase, credential string, provided *http.Client) (*Client, error) {
	base, err := url.Parse(rawBase)
	if err != nil || base.User != nil || base.Host == "" || base.RawQuery != "" || base.Fragment != "" || (base.Path != "" && base.Path != "/") || !safeClientScheme(base) {
		return nil, errors.New("invalid trusted attachment origin")
	}
	if credential == "" || strings.ContainsAny(credential, " \t\r\n") {
		return nil, errors.New("invalid trusted attachment credential")
	}
	if provided == nil {
		provided = &http.Client{Timeout: 11 * time.Minute, Transport: directTransport()}
	}
	client := *provided
	switch transport := client.Transport.(type) {
	case nil:
		client.Transport = directTransport()
	case *http.Transport:
		clone := transport.Clone()
		clone.Proxy = nil
		client.Transport = clone
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 11 * time.Minute
	}
	base.Path = ""
	return &Client{base: base, credential: credential, http: &client, receiveSlots: make(chan struct{}, maxConcurrentReceivers)}, nil
}

func directTransport() *http.Transport {
	if transport, ok := http.DefaultTransport.(*http.Transport); ok {
		clone := transport.Clone()
		clone.Proxy = nil
		return clone
	}
	return &http.Transport{}
}

func safeClientScheme(base *url.URL) bool {
	if base.Scheme == "https" {
		return true
	}
	if base.Scheme != "http" {
		return false
	}
	ip := net.ParseIP(base.Hostname())
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast())
}

// Send hashes the file, retries the stable reservation, and uploads only when
// the authoritative reservation is not already READY.
func (client *Client) Send(ctx context.Context, request SendRequest) (Artifact, error) {
	if client == nil || uuid.Validate(request.ProjectID) != nil || uuid.Validate(request.IdempotencyKey) != nil || request.Path == "" || request.DisplayName == "" || request.MediaType == "" {
		return Artifact{}, errors.New("invalid trusted attachment send")
	}
	file, err := openRegularSource(request.Path)
	if err != nil {
		return Artifact{}, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || info.Size() < 1 || info.Size() > maxDownloadBytes {
		return Artifact{}, errors.New("attachment source size is invalid")
	}
	hasher := sha256.New()
	written, err := copyDownload(ctx, hasher, file, info.Size()+1)
	if err != nil || written != info.Size() {
		return Artifact{}, errors.New("attachment source cannot be hashed")
	}
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	reservationBody, err := json.Marshal(map[string]any{"project_id": request.ProjectID, "idempotency_key": request.IdempotencyKey, "size_bytes": info.Size(), "sha256": hex.EncodeToString(digest[:]), "display_name": request.DisplayName, "media_type": request.MediaType, "lifetime_seconds": 3600})
	if err != nil {
		return Artifact{}, errors.New("attachment reservation cannot be encoded")
	}
	reservation, err := client.reserve(ctx, reservationBody)
	if err != nil {
		return Artifact{}, err
	}
	if reservation.Artifact.ProjectID != request.ProjectID || reservation.Artifact.SizeBytes != info.Size() || reservation.Artifact.SHA256 != digest || reservation.DisplayName != request.DisplayName || reservation.MediaType != request.MediaType || uuid.Validate(reservation.Artifact.ArtifactID) != nil || (reservation.Artifact.State != "reserved" && reservation.Artifact.State != "ready") {
		return Artifact{}, errors.New("attachment reservation response is inconsistent")
	}
	if reservation.Artifact.State == "ready" {
		return reservation.Artifact, nil
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return Artifact{}, errors.New("attachment source cannot be rewound")
	}
	upload, err := client.upload(ctx, reservation.Artifact.ArtifactID, file, info.Size())
	if err != nil {
		return Artifact{}, err
	}
	if upload.ArtifactID != reservation.Artifact.ArtifactID || upload.ProjectID != request.ProjectID || upload.SizeBytes != info.Size() || upload.SHA256 != digest || upload.State != "ready" {
		return Artifact{}, errors.New("attachment upload response is inconsistent")
	}
	return upload, nil
}

func openRegularSource(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("attachment source must be a regular file")
	}
	file, err := os.Open(path) // #nosec G304 -- explicit user-selected native source.
	if err != nil {
		return nil, errors.New("attachment source is unavailable")
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, errors.New("attachment source changed while opening")
	}
	return file, nil
}

// Receive streams one authenticated download into the configured safe root.
func (client *Client) Receive(ctx context.Context, artifactID, safeRoot string) (string, error) {
	if client == nil || uuid.Validate(artifactID) != nil || safeRoot == "" {
		return "", errors.New("invalid trusted attachment receive")
	}
	select {
	case client.receiveSlots <- struct{}{}:
		defer func() { <-client.receiveSlots }()
	case <-ctx.Done():
		return "", ctx.Err()
	}
	request, err := client.request(ctx, http.MethodGet, "/v1/trusted-attachments/"+artifactID, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Accept", "application/octet-stream")
	response, err := client.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", &RequestError{Retryable: true, operation: "download request"}
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK || response.StatusCode >= 300 && response.StatusCode < 400 {
		return "", responseError("download", response.StatusCode)
	}
	metadata, err := downloadMetadata(response, artifactID)
	if err != nil {
		return "", err
	}
	receiver, err := NewReceiver(safeRoot)
	if err != nil {
		return "", err
	}
	defer func() { _ = receiver.Close() }()
	return receiver.Receive(ctx, metadata, response.Body)
}

// Delete performs one current-authority, operation-bound idempotent tombstone.
func (client *Client) Delete(ctx context.Context, artifactID, idempotencyKey string) (Deletion, error) {
	if client == nil || uuid.Validate(artifactID) != nil || uuid.Validate(idempotencyKey) != nil {
		return Deletion{}, errors.New("invalid trusted attachment delete")
	}
	request, err := client.request(ctx, http.MethodDelete, "/v1/trusted-attachments/"+artifactID, nil)
	if err != nil {
		return Deletion{}, err
	}
	request.Header.Set("Idempotency-Key", idempotencyKey)
	response, err := client.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return Deletion{}, ctx.Err()
		}
		return Deletion{}, &RequestError{Retryable: true, operation: "delete request"}
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK || response.StatusCode >= 300 && response.StatusCode < 400 {
		return Deletion{}, responseError("delete", response.StatusCode)
	}
	if len(response.Header.Values("Content-Type")) != 1 {
		return Deletion{}, errors.New("attachment delete response is malformed")
	}
	responseMediaType, parameters, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaErr != nil || responseMediaType != "application/json" || len(parameters) != 0 {
		return Deletion{}, errors.New("attachment delete response is malformed")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseMetadataBytes+1))
	if err != nil || len(body) > maxResponseMetadataBytes {
		return Deletion{}, errors.New("attachment delete response is too large")
	}
	var encoded struct {
		ArtifactID string    `json:"artifact_id"`
		ProjectID  string    `json:"project_id"`
		State      string    `json:"state"`
		GCAfter    time.Time `json:"gc_after"`
		DeletedAt  time.Time `json:"deleted_at"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&encoded); err != nil || !decoderAtEOF(decoder) || encoded.ArtifactID != artifactID || uuid.Validate(encoded.ProjectID) != nil || (encoded.State != "tombstoned" && encoded.State != "gc_claimed" && encoded.State != "deleted") {
		return Deletion{}, errors.New("attachment delete response is malformed")
	}
	return Deletion{ArtifactID: encoded.ArtifactID, ProjectID: encoded.ProjectID, State: encoded.State}, nil
}

func downloadMetadata(response *http.Response, artifactID string) (DownloadMetadata, error) {
	if response.Header.Get("X-Punaro-Artifact-ID") != artifactID || len(response.Header.Values("X-Punaro-Artifact-ID")) != 1 || len(response.Header.Values("X-Punaro-SHA256")) != 1 || len(response.Header.Values("X-Punaro-Display-Name")) != 1 || len(response.Header.Values("Content-Type")) != 1 || len(response.Header.Values("Content-Length")) != 1 {
		return DownloadMetadata{}, errors.New("attachment download metadata is incomplete")
	}
	size, err := strconv.ParseInt(response.Header.Get("Content-Length"), 10, 64)
	if err != nil || size < 1 || size > maxDownloadBytes || response.ContentLength != -1 && response.ContentLength != size {
		return DownloadMetadata{}, errors.New("attachment download size is invalid")
	}
	digestBytes, err := hex.DecodeString(response.Header.Get("X-Punaro-SHA256"))
	if err != nil || len(digestBytes) != sha256.Size {
		return DownloadMetadata{}, errors.New("attachment download digest is invalid")
	}
	displayName, err := base64.RawURLEncoding.DecodeString(response.Header.Get("X-Punaro-Display-Name"))
	if err != nil || len(displayName) < 1 || len(displayName) > maxDisplayNameBytes || !utf8.Valid(displayName) || utf8.RuneCount(displayName) > maxDisplayNameRunes {
		return DownloadMetadata{}, errors.New("attachment download name is invalid")
	}
	mediaType, parameters, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType == "" || len(parameters) != 0 {
		return DownloadMetadata{}, errors.New("attachment download media type is invalid")
	}
	metadata := DownloadMetadata{ArtifactID: artifactID, SizeBytes: size, DisplayName: string(displayName), MediaType: mediaType}
	copy(metadata.SHA256[:], digestBytes)
	return metadata, nil
}

type reservationResponse struct {
	Artifact    Artifact
	DisplayName string
	MediaType   string
}

func (client *Client) reserve(ctx context.Context, encoded []byte) (reservationResponse, error) {
	body, err := client.doJSONResponse(ctx, http.MethodPost, "/v1/trusted-attachments", bytes.NewReader(encoded), int64(len(encoded)), "application/json", http.StatusCreated, "reservation")
	if err != nil {
		return reservationResponse{}, err
	}
	var response struct {
		ArtifactID  string    `json:"artifact_id"`
		ProjectID   string    `json:"project_id"`
		SizeBytes   int64     `json:"size_bytes"`
		SHA256      string    `json:"sha256"`
		DisplayName string    `json:"display_name"`
		MediaType   string    `json:"media_type"`
		State       string    `json:"state"`
		ExpiresAt   time.Time `json:"expires_at"`
	}
	if err := decodeExactJSON(body, &response); err != nil || response.ExpiresAt.IsZero() || response.DisplayName == "" || response.MediaType == "" {
		return reservationResponse{}, errors.New("attachment reservation response is malformed")
	}
	artifact, err := decodedArtifact(response.ArtifactID, response.ProjectID, response.SizeBytes, response.SHA256, response.State)
	if err != nil {
		return reservationResponse{}, err
	}
	return reservationResponse{Artifact: artifact, DisplayName: response.DisplayName, MediaType: response.MediaType}, nil
}

func (client *Client) upload(ctx context.Context, artifactID string, source io.Reader, size int64) (Artifact, error) {
	body, err := client.doJSONResponse(ctx, http.MethodPut, "/v1/trusted-attachments/"+artifactID+"/content", source, size, "application/octet-stream", http.StatusOK, "upload")
	if err != nil {
		return Artifact{}, err
	}
	var response struct {
		ArtifactID string    `json:"artifact_id"`
		ProjectID  string    `json:"project_id"`
		SizeBytes  int64     `json:"size_bytes"`
		SHA256     string    `json:"sha256"`
		State      string    `json:"state"`
		ReadyAt    time.Time `json:"ready_at"`
	}
	if err := decodeExactJSON(body, &response); err != nil || response.ReadyAt.IsZero() {
		return Artifact{}, errors.New("attachment upload response is malformed")
	}
	return decodedArtifact(response.ArtifactID, response.ProjectID, response.SizeBytes, response.SHA256, response.State)
}

func (client *Client) doJSONResponse(ctx context.Context, method, path string, body io.Reader, contentLength int64, contentType string, expected int, operation string) ([]byte, error) {
	request, err := client.request(ctx, method, path, body)
	if err != nil {
		return nil, err
	}
	request.ContentLength = contentLength
	request.Header.Set("Content-Type", contentType)
	response, err := client.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &RequestError{Retryable: true, operation: operation + " request"}
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != expected || response.StatusCode >= 300 && response.StatusCode < 400 {
		return nil, responseError(operation, response.StatusCode)
	}
	if len(response.Header.Values("Content-Type")) != 1 {
		return nil, errors.New("attachment " + operation + " response media type is invalid")
	}
	responseMediaType, parameters, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaErr != nil || responseMediaType != "application/json" || len(parameters) != 0 {
		return nil, errors.New("attachment " + operation + " response media type is invalid")
	}
	bodyBytes, err := io.ReadAll(io.LimitReader(response.Body, maxResponseMetadataBytes+1))
	if err != nil || len(bodyBytes) > maxResponseMetadataBytes {
		return nil, errors.New("attachment " + operation + " response is too large")
	}
	return bodyBytes, nil
}

func decodeExactJSON(body []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil || !decoderAtEOF(decoder) {
		return errors.New("attachment response is malformed")
	}
	return nil
}

func decodedArtifact(artifactID, projectID string, sizeBytes int64, encodedDigest, state string) (Artifact, error) {
	digest, err := hex.DecodeString(encodedDigest)
	if err != nil || len(digest) != sha256.Size {
		return Artifact{}, errors.New("attachment response digest is malformed")
	}
	artifact := Artifact{ArtifactID: artifactID, ProjectID: projectID, SizeBytes: sizeBytes, State: state}
	copy(artifact.SHA256[:], digest)
	return artifact, nil
}

func decoderAtEOF(decoder *json.Decoder) bool {
	var trailing any
	return errors.Is(decoder.Decode(&trailing), io.EOF)
}

func responseError(operation string, status int) error {
	retryable := status == http.StatusRequestTimeout || status == http.StatusTooEarly || status == http.StatusLocked || status == http.StatusTooManyRequests || status == http.StatusInternalServerError || status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout || status == http.StatusInsufficientStorage
	return &RequestError{StatusCode: status, Retryable: retryable, operation: operation}
}

func (client *Client) request(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	target := *client.base
	target.Path = path
	request, err := http.NewRequestWithContext(ctx, method, target.String(), body)
	if err != nil {
		return nil, errors.New("attachment request cannot be created")
	}
	request.Header.Set("Authorization", "Bearer "+client.credential)
	request.Header.Set("Accept", "application/json")
	return request, nil
}
