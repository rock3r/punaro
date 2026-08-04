// Package clientidentity defines the non-secret, per-device identity record
// shared by Punaro's native clients.
package clientidentity

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/rock3r/punaro/internal/relay"
)

// Version is the current compatible client identity state schema.
const Version = 1

var (
	// ErrInvalidState reports malformed, unsafe, or unsupported state data.
	ErrInvalidState = errors.New("client identity state is invalid")
	// ErrStateMismatch reports state belonging to another local client.
	ErrStateMismatch = errors.New("client identity state does not match this client")
)

// State is deliberately non-secret. Credential values and private keys belong
// to platform-protected storage, never this portable record.
type State struct {
	Version         int
	Origin          string
	ClientBinding   string
	LegacyMachineID string
}

// Parse accepts exactly the current schema version and rejects ambiguous JSON
// before any client uses its local routing or migration relationship.
func Parse(raw []byte) (State, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return State{}, ErrInvalidState
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		name, err := decoder.Token()
		if err != nil {
			return State{}, ErrInvalidState
		}
		key, ok := name.(string)
		if !ok || (key != "version" && key != "origin" && key != "client_binding" && key != "legacy_machine_id") {
			return State{}, ErrInvalidState
		}
		if _, duplicate := fields[key]; duplicate {
			return State{}, ErrInvalidState
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return State{}, ErrInvalidState
		}
		fields[key] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') || decoder.Decode(&struct{}{}) != io.EOF {
		return State{}, ErrInvalidState
	}
	if len(fields) < 3 || fields["version"] == nil || fields["origin"] == nil || fields["client_binding"] == nil {
		return State{}, ErrInvalidState
	}
	var state State
	if json.Unmarshal(fields["version"], &state.Version) != nil || json.Unmarshal(fields["origin"], &state.Origin) != nil || json.Unmarshal(fields["client_binding"], &state.ClientBinding) != nil {
		return State{}, ErrInvalidState
	}
	if rawMachine, present := fields["legacy_machine_id"]; present {
		var machine string
		if json.Unmarshal(rawMachine, &machine) != nil || !validLegacyMachineID(machine) {
			return State{}, ErrInvalidState
		}
		state.LegacyMachineID = machine
	}
	if err := state.validate(); err != nil {
		return State{}, ErrInvalidState
	}
	return state, nil
}

// Encode renders the only accepted non-secret record shape deterministically.
func (s State) Encode() ([]byte, error) {
	if err := s.validate(); err != nil {
		return nil, ErrInvalidState
	}
	return json.Marshal(struct {
		Version         int    `json:"version"`
		Origin          string `json:"origin"`
		ClientBinding   string `json:"client_binding"`
		LegacyMachineID string `json:"legacy_machine_id,omitempty"`
	}{Version: s.Version, Origin: s.Origin, ClientBinding: s.ClientBinding, LegacyMachineID: s.LegacyMachineID})
}

// Match proves the supplied non-secret local configuration is for exactly this
// identity. It deliberately exposes no stored values in mismatch errors.
func (s State) Match(origin, clientBinding, legacyMachineID string) error {
	canonicalOrigin, ok := canonicalOrigin(origin)
	if s.validate() != nil || !ok || !validBinding(clientBinding) || (legacyMachineID != "" && !validLegacyMachineID(legacyMachineID)) || s.Origin != canonicalOrigin || s.ClientBinding != clientBinding || (s.LegacyMachineID != "" && s.LegacyMachineID != legacyMachineID) {
		return ErrStateMismatch
	}
	return nil
}

func (s State) validate() error {
	if s.Version != Version || !validOrigin(s.Origin) || !validBinding(s.ClientBinding) || (s.LegacyMachineID != "" && !validLegacyMachineID(s.LegacyMachineID)) {
		return ErrInvalidState
	}
	return nil
}

func validOrigin(raw string) bool {
	canonical, ok := canonicalOrigin(raw)
	return ok && canonical == raw
}

func canonicalOrigin(raw string) (string, bool) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || strings.HasSuffix(parsed.Host, ":") || parsed.User != nil || parsed.Opaque != "" || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", false
	}
	if strings.HasPrefix(parsed.Host, "[") && !validIPv6Hostname(parsed.Hostname()) {
		return "", false
	}
	hostname := canonicalHostname(parsed.Hostname())
	if port := parsed.Port(); port != "" {
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil || value == 0 {
			return "", false
		}
		if value == 443 {
			parsed.Host = canonicalHost(hostname)
		} else {
			parsed.Host = net.JoinHostPort(hostname, strconv.FormatUint(value, 10))
		}
	} else {
		parsed.Host = canonicalHost(hostname)
	}
	parsed.Path = ""
	parsed.ForceQuery = false
	return parsed.String(), true
}

func canonicalHost(hostname string) string {
	if strings.Contains(hostname, ":") {
		return "[" + hostname + "]"
	}
	return hostname
}

func canonicalHostname(hostname string) string {
	address, zone, hasZone := strings.Cut(hostname, "%")
	if canonical, ok := canonicalIPv6(address); ok {
		if hasZone {
			return canonical + "%" + zone
		}
		return canonical
	}
	return strings.ToLower(hostname)
}

func validIPv6Hostname(hostname string) bool {
	address, zone, hasZone := strings.Cut(hostname, "%")
	if hasZone && zone == "" {
		return false
	}
	_, ok := canonicalIPv6(address)
	return ok
}

func canonicalIPv6(address string) (string, bool) {
	parsed := net.ParseIP(address)
	if parsed == nil || !strings.Contains(address, ":") {
		return "", false
	}
	if ipv4 := parsed.To4(); ipv4 != nil {
		return "::ffff:" + ipv4.String(), true
	}
	return parsed.String(), true
}

func validBinding(raw string) bool {
	parsed, err := uuid.Parse(raw)
	return err == nil && parsed != uuid.Nil && parsed.String() == raw
}

func validLegacyMachineID(raw string) bool {
	return relay.ValidMachineID(raw)
}
