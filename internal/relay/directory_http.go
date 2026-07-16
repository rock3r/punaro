package relay

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"
)

const maxDirectorySnapshotResponseBytes = 2 << 20

var errDirectoryUnavailable = errors.New("directory snapshot unavailable")

// DirectorySnapshotSource serves one complete, canonical signed directory
// snapshot. It must fail instead of returning a cached expired view.
type DirectorySnapshotSource interface {
	CurrentDirectorySnapshot() ([]byte, error)
}

type directoryHTTPHandler struct {
	auth   *Authenticator
	source DirectorySnapshotSource
	now    func() time.Time
}

// NewDirectoryHandler returns the machine-authenticated attachment-directory
// endpoint. Cloudflare Access remains an outer admission layer in punarod;
// this handler independently protects directory metadata with enrolled-machine
// request signatures and durable replay prevention.
func NewDirectoryHandler(auth *Authenticator, source DirectorySnapshotSource, now func() time.Time) (http.Handler, error) {
	if auth == nil || source == nil {
		return nil, errors.New("directory handler requires authenticator and source")
	}
	if now == nil {
		now = time.Now
	}
	return &directoryHTTPHandler{auth: auth, source: source, now: now}, nil
}

func (h *directoryHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.Path != "/v2/directory" {
		writeError(w, http.StatusNotFound, "route not found")
		return
	}
	if r.URL.RawQuery != "" || r.URL.RawPath != "" || r.URL.EscapedPath() != r.URL.Path || r.ContentLength > 0 {
		writeError(w, http.StatusBadRequest, "invalid directory request")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1))
	if err != nil || len(body) != 0 {
		writeError(w, http.StatusBadRequest, "invalid directory request")
		return
	}
	if _, err := h.auth.AuthenticateHTTP(r, body, h.now().UTC()); err != nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	raw, err := h.source.CurrentDirectorySnapshot()
	if err != nil || len(raw) == 0 || len(raw) > maxDirectorySnapshotResponseBytes {
		writeError(w, http.StatusServiceUnavailable, "directory unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/cbor")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
	w.WriteHeader(http.StatusOK)
	// #nosec G705 -- source is a validated canonical CBOR snapshot, never an
	// HTTP request body, and has a non-rendering content type.
	_, _ = w.Write(raw)
}
