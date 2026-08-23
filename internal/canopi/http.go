package canopi

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rock3r/punaro/canopi/protocol"
)

const (
	maxEventBytes = 64 << 10
	maxBatchBytes = 1 << 20
	maxBatchSize  = 100
)

// HandlerConfig supplies the state, authentication, clock, and render policy.
type HandlerConfig struct {
	Store  *Store
	Token  string
	Now    func() time.Time
	Render RenderConfig
}

// Handler exposes authenticated ingestion, snapshot, and render endpoints.
type Handler struct {
	store  *Store
	token  string
	now    func() time.Time
	render RenderConfig

	cacheMu sync.Mutex
	cache   renderCache
}

type renderCache struct {
	revision uint64
	bucket   time.Time
	payload  []byte
	etag     string
}

// NewHandler validates its dependencies and constructs the Canopi HTTP API.
func NewHandler(config HandlerConfig) (*Handler, error) {
	if config.Store == nil {
		return nil, errors.New("canopi store is required")
	}
	if config.Token == "" {
		return nil, errors.New("canopi bearer token is required")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Render == (RenderConfig{}) {
		config.Render = DefaultRenderConfig()
	}
	if err := config.Render.validate(); err != nil {
		return nil, err
	}
	return &Handler{store: config.Store, token: config.Token, now: config.Now, render: config.Render}, nil
}

func (h *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if !h.authorized(request) {
		response.Header().Set("WWW-Authenticate", `Bearer realm="canopi"`)
		http.Error(response, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch {
	case request.Method == http.MethodPost && request.URL.Path == "/v1/events":
		h.ingest(response, request)
	case request.Method == http.MethodPost && request.URL.Path == "/v1/events:batch":
		h.ingestBatch(response, request)
	case request.Method == http.MethodGet && request.URL.Path == "/v1/snapshot":
		h.snapshot(response, request)
	case request.Method == http.MethodGet && request.URL.Path == "/v1/render/800x480.png":
		h.renderPNG(response, request)
	default:
		http.NotFound(response, request)
	}
}

func (h *Handler) authorized(request *http.Request) bool {
	const prefix = "Bearer "
	header := request.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	provided := []byte(strings.TrimSpace(strings.TrimPrefix(header, prefix)))
	expected := []byte(h.token)
	return len(provided) == len(expected) && subtle.ConstantTimeCompare(provided, expected) == 1
}

func (h *Handler) ingest(response http.ResponseWriter, request *http.Request) {
	event, err := protocol.DecodeEvent(request.Body, maxEventBytes)
	if err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	result, err := h.store.Apply(event)
	if err != nil {
		if errors.Is(err, ErrFutureActivity) {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		if errors.Is(err, ErrLiveRecordLimit) {
			writeError(response, http.StatusTooManyRequests, err)
			return
		}
		writeError(response, http.StatusInternalServerError, errors.New("persist event"))
		return
	}
	status := http.StatusOK
	if result.Applied {
		status = http.StatusAccepted
	}
	writeJSON(response, status, result)
}

func (h *Handler) ingestBatch(response http.ResponseWriter, request *http.Request) {
	payload, err := io.ReadAll(io.LimitReader(request.Body, maxBatchBytes+1))
	if err != nil {
		writeError(response, http.StatusBadRequest, errors.New("read batch"))
		return
	}
	if len(payload) > maxBatchBytes {
		writeError(response, http.StatusRequestEntityTooLarge, errors.New("batch body exceeds limit"))
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	var rawEvents []json.RawMessage
	if err := decoder.Decode(&rawEvents); err != nil {
		writeError(response, http.StatusBadRequest, errors.New("invalid batch JSON"))
		return
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeError(response, http.StatusBadRequest, errors.New("invalid batch JSON"))
		return
	}
	if len(rawEvents) > maxBatchSize {
		writeError(response, http.StatusRequestEntityTooLarge, fmt.Errorf("batch exceeds %d events", maxBatchSize))
		return
	}
	events := make([]protocol.Event, 0, len(rawEvents))
	for _, raw := range rawEvents {
		event, err := protocol.DecodeEvent(bytes.NewReader(raw), maxEventBytes)
		if err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		events = append(events, event)
	}
	results := make([]ApplyResult, 0, len(events))
	for _, event := range events {
		result, err := h.store.Apply(event)
		if err != nil {
			if errors.Is(err, ErrFutureActivity) {
				writeError(response, http.StatusBadRequest, err)
				return
			}
			if errors.Is(err, ErrLiveRecordLimit) {
				writeError(response, http.StatusTooManyRequests, err)
				return
			}
			writeError(response, http.StatusInternalServerError, errors.New("persist batch"))
			return
		}
		results = append(results, result)
	}
	writeJSON(response, http.StatusAccepted, map[string]any{"results": results})
}

func (h *Handler) snapshot(response http.ResponseWriter, request *http.Request) {
	now := h.now().Truncate(h.render.RelativeTimeBucket)
	snapshot := h.store.Snapshot(now)
	payload, err := json.Marshal(snapshot)
	if err != nil {
		writeError(response, http.StatusInternalServerError, errors.New("encode snapshot"))
		return
	}
	etag := payloadETag(payload)
	if request.Header.Get("If-None-Match") == etag {
		response.WriteHeader(http.StatusNotModified)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "private, max-age=0, must-revalidate")
	response.Header().Set("ETag", etag)
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(payload)
}

func (h *Handler) renderPNG(response http.ResponseWriter, request *http.Request) {
	now := h.now().Truncate(h.render.RelativeTimeBucket)
	snapshot := h.store.Snapshot(now)
	payload, etag, err := h.cachedRender(snapshot, now)
	if err != nil {
		writeError(response, http.StatusInternalServerError, errors.New("render dashboard"))
		return
	}
	if request.Header.Get("If-None-Match") == etag {
		response.Header().Set("ETag", etag)
		response.WriteHeader(http.StatusNotModified)
		return
	}
	response.Header().Set("Content-Type", "image/png")
	response.Header().Set("Cache-Control", "private, max-age=0, must-revalidate")
	response.Header().Set("ETag", etag)
	response.Header().Set("Content-Length", fmt.Sprintf("%d", len(payload)))
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(payload)
}

func (h *Handler) cachedRender(snapshot Snapshot, bucket time.Time) ([]byte, string, error) {
	h.cacheMu.Lock()
	defer h.cacheMu.Unlock()
	if h.cache.payload != nil && h.cache.revision == snapshot.Revision && h.cache.bucket.Equal(bucket) {
		return h.cache.payload, h.cache.etag, nil
	}
	payload, err := Render(snapshot.Agents, h.render, bucket)
	if err != nil {
		return nil, "", err
	}
	h.cache = renderCache{revision: snapshot.Revision, bucket: bucket, payload: payload, etag: payloadETag(payload)}
	return h.cache.payload, h.cache.etag, nil
}

func payloadETag(payload []byte) string {
	digest := sha256.Sum256(payload)
	return `"` + hex.EncodeToString(digest[:]) + `"`
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeError(response http.ResponseWriter, status int, err error) {
	writeJSON(response, status, map[string]string{"error": err.Error()})
}
