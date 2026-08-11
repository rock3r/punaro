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
	"github.com/rock3r/punaro/internal/clienttransport"
	"github.com/rock3r/punaro/internal/relay"
	"golang.org/x/net/idna"
)

// Version is the current compatible client identity state schema.
const Version = 1

// LANVersion adds the explicit client-side plaintext acknowledgement and
// pinned CIDR required for a trusted-LAN origin. Version one remains the
// canonical HTTPS identity shape.
const LANVersion = 2

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
	AllowLANHTTP    bool
	TrustedLANCIDR  string
}

// Parse accepts only the defined HTTPS and trusted-LAN schema versions and
// rejects ambiguous JSON before any client uses its local routing or migration
// relationship.
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
		if !ok || (key != "version" && key != "origin" && key != "client_binding" && key != "legacy_machine_id" && key != "allow_lan_http" && key != "trusted_lan_cidr") {
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
	if rawAllow, present := fields["allow_lan_http"]; present {
		if json.Unmarshal(rawAllow, &state.AllowLANHTTP) != nil {
			return State{}, ErrInvalidState
		}
	}
	if rawCIDR, present := fields["trusted_lan_cidr"]; present {
		if json.Unmarshal(rawCIDR, &state.TrustedLANCIDR) != nil {
			return State{}, ErrInvalidState
		}
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
		AllowLANHTTP    bool   `json:"allow_lan_http,omitempty"`
		TrustedLANCIDR  string `json:"trusted_lan_cidr,omitempty"`
	}{Version: s.Version, Origin: s.Origin, ClientBinding: s.ClientBinding, LegacyMachineID: s.LegacyMachineID, AllowLANHTTP: s.AllowLANHTTP, TrustedLANCIDR: s.TrustedLANCIDR})
}

// Match proves the supplied non-secret local configuration is for exactly this
// identity. It deliberately exposes no stored values in mismatch errors.
func (s State) Match(origin, clientBinding, legacyMachineID string) error {
	canonicalOrigin, ok := canonicalOriginForPolicy(origin, s.TransportPolicy())
	if s.validate() != nil || !ok || !validBinding(clientBinding) || (legacyMachineID != "" && !validLegacyMachineID(legacyMachineID)) || s.Origin != canonicalOrigin || s.ClientBinding != clientBinding || (s.LegacyMachineID != "" && s.LegacyMachineID != legacyMachineID) {
		return ErrStateMismatch
	}
	return nil
}

// MatchLegacyAdapter verifies the transition state for an adapter that still
// authenticates with its legacy machine identity. Fresh post-enrollment
// clients use Match and have no legacy machine relationship to prove.
func (s State) MatchLegacyAdapter(origin, clientBinding, machineID string) error {
	if s.LegacyMachineID == "" {
		return ErrStateMismatch
	}
	return s.Match(origin, clientBinding, machineID)
}

func (s State) validate() error {
	if !validBinding(s.ClientBinding) || (s.LegacyMachineID != "" && !validLegacyMachineID(s.LegacyMachineID)) {
		return ErrInvalidState
	}
	switch s.Version {
	case Version:
		if s.AllowLANHTTP || s.TrustedLANCIDR != "" || !validOrigin(s.Origin) {
			return ErrInvalidState
		}
	case LANVersion:
		if !s.AllowLANHTTP || s.TrustedLANCIDR == "" {
			return ErrInvalidState
		}
		canonical, ok := canonicalOriginForPolicy(s.Origin, s.TransportPolicy())
		if !ok || canonical != s.Origin {
			return ErrInvalidState
		}
	default:
		return ErrInvalidState
	}
	return nil
}

// TransportPolicy returns the non-secret LAN transport boundary bound into
// this identity. HTTPS version-one identities return the zero policy.
func (s State) TransportPolicy() clienttransport.Policy {
	return clienttransport.Policy{AllowLANHTTP: s.AllowLANHTTP, TrustedLANCIDR: s.TrustedLANCIDR}
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
	hostname, ok := canonicalHostname(parsed.Hostname())
	if !ok {
		return "", false
	}
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

// CanonicalOrigin validates and canonicalizes the one fixed HTTPS authority a
// native client is allowed to contact. Callers must persist the returned value
// before accepting credentials or network input.
func CanonicalOrigin(raw string) (string, bool) { return canonicalOrigin(raw) }

// CanonicalOriginWithPolicy validates the explicit trusted-LAN HTTP exception
// used only by version-two identity records.
func CanonicalOriginWithPolicy(raw string, policy clienttransport.Policy) (string, bool) {
	return canonicalOriginForPolicy(raw, policy)
}

func canonicalOriginForPolicy(raw string, policy clienttransport.Policy) (string, bool) {
	if !policy.AllowLANHTTP && policy.TrustedLANCIDR == "" {
		return canonicalOrigin(raw)
	}
	parsed, err := clienttransport.ValidateOrigin(raw, policy)
	if err != nil {
		return "", false
	}
	return parsed.String(), true
}

func canonicalHost(hostname string) string {
	if strings.Contains(hostname, ":") {
		return "[" + hostname + "]"
	}
	return hostname
}

func canonicalHostname(hostname string) (string, bool) {
	address, zone, hasZone := strings.Cut(hostname, "%")
	if canonical, ok := canonicalIPv6(address); ok {
		if hasZone {
			return canonical + "%" + zone, true
		}
		return canonical, true
	}
	canonical, err := idna.Lookup.ToASCII(hostname)
	if err != nil || !validDNSName(canonical) {
		return "", false
	}
	return strings.ToLower(canonical), true
}

func validDNSName(hostname string) bool {
	if len(hostname) == 0 || len(hostname) > 253 {
		return false
	}
	labels := strings.Split(hostname, ".")
	if labels[len(labels)-1] == "" {
		labels = labels[:len(labels)-1]
	}
	if len(labels) == 0 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
	}
	return true
}

func validIPv6Hostname(hostname string) bool {
	address, zone, hasZone := strings.Cut(hostname, "%")
	if hasZone && !validIPv6Zone(zone) {
		return false
	}
	_, ok := canonicalIPv6(address)
	return ok
}

func validIPv6Zone(zone string) bool {
	return zone != "" && !strings.ContainsAny(zone, "[]")
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
