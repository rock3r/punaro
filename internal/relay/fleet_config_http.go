package relay

import (
	"net/http"
	"strings"
)

func (h *handler) fleetDesired(w http.ResponseWriter, r *http.Request, machineID string) {
	if h.fleet == nil {
		writeError(w, http.StatusNotFound, "route not found")
		return
	}
	desired, err := h.fleet.FleetDesired(r.Context())
	if err != nil {
		writeError(w, http.StatusForbidden, "fleet-config access is not authorized")
		return
	}
	_ = machineID
	writeJSON(w, http.StatusOK, map[string]any{
		"generation":    desired.Generation,
		"digest":        desired.Digest,
		"source_commit": desired.SourceCommit,
		"skill_count":   desired.SkillCount,
		"total_bytes":   desired.TotalBytes,
	})
}

func (h *handler) fleetRelease(w http.ResponseWriter, r *http.Request, digest, machineID string) {
	if h.fleet == nil || !fleetDigestPattern.MatchString(digest) {
		writeError(w, http.StatusNotFound, "route not found")
		return
	}
	archive, err := h.fleet.FleetRelease(r.Context(), digest)
	if err != nil || len(archive) == 0 {
		writeError(w, http.StatusForbidden, "fleet-config access is not authorized")
		return
	}
	_ = machineID
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	// #nosec G705 -- digest-pinned USTAR archive is emitted as octet-stream, never HTML.
	_, _ = w.Write(archive)
}

func (h *handler) fleetStatus(w http.ResponseWriter, r *http.Request, body []byte, machineID, idempotencyKey string) {
	if h.fleet == nil {
		writeError(w, http.StatusNotFound, "route not found")
		return
	}
	if idempotencyKey == "" {
		writeError(w, http.StatusBadRequest, "idempotency key is required")
		return
	}
	var request struct {
		Generation        int64  `json:"generation"`
		AppliedDigest     string `json:"applied_digest"`
		State             string `json:"state"`
		Activation        string `json:"activation"`
		TrailerState      string `json:"trailer_state"`
		AliasState        string `json:"alias_state"`
		ProjectMatchState string `json:"project_match_state"`
		ReportGeneration  int64  `json:"report_generation"`
	}
	if err := decodeJSON(body, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid fleet-config status")
		return
	}
	report := FleetStatusReport{
		Generation:        request.Generation,
		AppliedDigest:     request.AppliedDigest,
		State:             request.State,
		Activation:        request.Activation,
		TrailerState:      request.TrailerState,
		AliasState:        request.AliasState,
		ProjectMatchState: request.ProjectMatchState,
		ReportGeneration:  request.ReportGeneration,
		IdempotencyKey:    idempotencyKey,
	}
	report.RequestHash = fleetStatusRequestHash(machineID, report)
	if !validFleetStatus(report) {
		writeError(w, http.StatusBadRequest, "invalid fleet-config status")
		return
	}
	if err := h.fleet.PutFleetStatus(r.Context(), machineID, report); err != nil {
		if strings.Contains(err.Error(), "stale") {
			writeError(w, http.StatusConflict, "fleet-config status generation is stale")
			return
		}
		if strings.Contains(err.Error(), "idempotency") {
			writeError(w, http.StatusConflict, "idempotency key conflicts with an earlier operation")
			return
		}
		writeError(w, http.StatusForbidden, "fleet-config access is not authorized")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "recorded"})
}
