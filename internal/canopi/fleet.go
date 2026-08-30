package canopi

import "encoding/json"

// FleetConvergenceEvent is a content-free dashboard hook for fleet-config.
type FleetConvergenceEvent struct {
	Kind       string `json:"kind"`
	Generation int64  `json:"generation"`
	Digest     string `json:"digest"`
	State      string `json:"state"`
}

// EncodeFleetConvergence encodes one bounded convergence event.
func EncodeFleetConvergence(generation int64, digest, state string) ([]byte, error) {
	return json.Marshal(FleetConvergenceEvent{Kind: "fleet_config", Generation: generation, Digest: digest, State: state})
}
