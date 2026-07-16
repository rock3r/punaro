package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const maxRequestAge = 5 * time.Minute

// Machine is the non-secret enrollment record for one adapter installation.
// Its matching private key remains only on that machine.
type Machine struct {
	ID               string
	PublicKey        ed25519.PublicKey
	EndpointPrefixes []string
	// Endpoints contains exact mailbox addresses owned by this machine. Unlike
	// EndpointPrefixes, an entry here never authorizes a similarly named
	// endpoint. This is for a narrowly delegated external session that cannot
	// safely be placed under the machine's namespace.
	Endpoints []string
	// AttachmentDeviceID binds this enrolled transport identity to one
	// directory device for attachment permit issuance. It is optional for the
	// text relay, but permit routes require it and never infer it from a name.
	AttachmentDeviceID [16]byte
}

// AttachmentDeviceID returns the explicit attachment device bound to a
// machine enrollment. A missing binding is never treated as a wildcard.
func (a *Authenticator) AttachmentDeviceID(machineID string) ([16]byte, bool) {
	if a == nil {
		return [16]byte{}, false
	}
	machine, found := a.machines[machineID]
	if !found || machine.AttachmentDeviceID == [16]byte{} {
		return [16]byte{}, false
	}
	return machine.AttachmentDeviceID, true
}

// SignedRequest is the complete application-level authentication envelope.
// HTTP code builds it from headers and the exact bounded request body.
type SignedRequest struct {
	MachineID string
	Method    string
	Path      string
	Body      []byte
	Timestamp time.Time
	Nonce     string
	Signature []byte
}

// Authenticator verifies enrolled Ed25519 device signatures and persists
// nonces in the relay database so a daemon restart cannot reopen a replay
// window.
type Authenticator struct {
	store    *Store
	machines map[string]Machine
}

// NewAuthenticator accepts a complete explicit enrollment set. Enrollment is
// configuration-controlled, not message-controlled; duplicate IDs and unsafe
// endpoint rules fail startup rather than picking an arbitrary credential.
func NewAuthenticator(store *Store, machines []Machine) (*Authenticator, error) {
	if store == nil || len(machines) == 0 {
		return nil, fmt.Errorf("relay authenticator requires enrolled machines")
	}
	configured := make(map[string]Machine, len(machines))
	attachmentDevices := make(map[[16]byte]string, len(machines))
	for _, machine := range machines {
		if strings.TrimSpace(machine.ID) == "" || len(machine.PublicKey) != ed25519.PublicKeySize || (len(machine.EndpointPrefixes) == 0 && len(machine.Endpoints) == 0) {
			return nil, fmt.Errorf("invalid machine enrollment")
		}
		if _, exists := configured[machine.ID]; exists {
			return nil, fmt.Errorf("duplicate machine enrollment %q", machine.ID)
		}
		if machine.AttachmentDeviceID != [16]byte{} {
			if prior, exists := attachmentDevices[machine.AttachmentDeviceID]; exists {
				return nil, fmt.Errorf("attachment device is bound to both machines %q and %q", prior, machine.ID)
			}
			attachmentDevices[machine.AttachmentDeviceID] = machine.ID
		}
		for _, prefix := range machine.EndpointPrefixes {
			if !validEndpointPrefix(prefix) {
				return nil, fmt.Errorf("invalid endpoint prefix for machine %q", machine.ID)
			}
		}
		exact := make(map[string]struct{}, len(machine.Endpoints))
		for _, endpoint := range machine.Endpoints {
			if endpoint == "" || strings.TrimSpace(endpoint) != endpoint {
				return nil, fmt.Errorf("invalid exact endpoint for machine %q", machine.ID)
			}
			if _, duplicate := exact[endpoint]; duplicate {
				return nil, fmt.Errorf("duplicate exact endpoint for machine %q", machine.ID)
			}
			exact[endpoint] = struct{}{}
		}
		machine.PublicKey = append(ed25519.PublicKey(nil), machine.PublicKey...)
		machine.EndpointPrefixes = append([]string(nil), machine.EndpointPrefixes...)
		machine.Endpoints = append([]string(nil), machine.Endpoints...)
		configured[machine.ID] = machine
	}
	for leftID, left := range configured {
		for rightID, right := range configured {
			if leftID >= rightID {
				continue
			}
			for _, leftPrefix := range left.EndpointPrefixes {
				for _, rightPrefix := range right.EndpointPrefixes {
					if strings.HasPrefix(leftPrefix, rightPrefix) || strings.HasPrefix(rightPrefix, leftPrefix) {
						return nil, fmt.Errorf("overlapping endpoint namespaces for machines %q and %q", leftID, rightID)
					}
				}
			}
			for _, endpoint := range left.Endpoints {
				if machineOwnsEndpoint(right, endpoint) {
					return nil, fmt.Errorf("exact endpoint %q is owned by both machines %q and %q", endpoint, leftID, rightID)
				}
			}
			for _, endpoint := range right.Endpoints {
				if machineOwnsEndpoint(left, endpoint) {
					return nil, fmt.Errorf("exact endpoint %q is owned by both machines %q and %q", endpoint, leftID, rightID)
				}
			}
		}
	}
	return &Authenticator{store: store, machines: configured}, nil
}

// validEndpointPrefix requires a complete mailbox path segment. Without the
// trailing slash, a raw prefix comparison could let `agent/a` claim
// `agent/abuse`; prefixes are authority boundaries, not friendly labels.
func validEndpointPrefix(prefix string) bool {
	return prefix == strings.TrimSpace(prefix) && prefix != "/" && strings.HasSuffix(prefix, "/") && !strings.Contains(prefix, "//")
}

// CanonicalRequest returns the stable, unambiguous byte sequence signed by a
// machine key. Query strings are intentionally excluded from the API surface;
// handlers reject them before authentication so they cannot become unsigned
// authorization input.
func CanonicalRequest(request SignedRequest) []byte {
	bodyHash := sha256.Sum256(request.Body)
	return []byte(strings.Join([]string{
		"punaro-request-v1",
		request.MachineID,
		strings.ToUpper(request.Method),
		request.Path,
		fmt.Sprintf("%x", bodyHash),
		fmt.Sprintf("%d", request.Timestamp.UTC().UnixMilli()),
		request.Nonce,
	}, "\n"))
}

// Verify rejects unknown machines, stale signatures, path/body tampering, and
// replays. Errors intentionally use one authorization result at the boundary.
func (a *Authenticator) Verify(request SignedRequest, now time.Time) error {
	machine, found := a.machines[request.MachineID]
	if !found || !validSignedRequest(request, now) || !ed25519.Verify(machine.PublicKey, CanonicalRequest(request), request.Signature) {
		return ErrForbidden
	}
	tx, err := a.store.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("begin request replay transaction: %w", err)
	}
	defer rollback(tx)
	if _, err := tx.ExecContext(context.Background(), "DELETE FROM request_nonces WHERE expires_at <= ?", now.UnixMilli()); err != nil {
		return fmt.Errorf("prune request nonces: %w", err)
	}
	_, err = tx.ExecContext(context.Background(), "INSERT INTO request_nonces(machine_id, nonce, expires_at) VALUES (?, ?, ?)", request.MachineID, request.Nonce, request.Timestamp.UTC().Add(maxRequestAge).UnixMilli())
	if err != nil {
		return ErrForbidden
	}
	return tx.Commit()
}

// AuthenticateHTTP authenticates a request over its exact already-bounded
// body. Route handlers remain responsible for rejecting unsigned URL features
// (query strings and alternate escaped paths) before calling this method.
func (a *Authenticator) AuthenticateHTTP(request *http.Request, body []byte, now time.Time) (string, error) {
	if a == nil || request == nil {
		return "", ErrForbidden
	}
	timestamp, err := time.Parse(time.RFC3339Nano, request.Header.Get("X-Punaro-Timestamp"))
	if err != nil {
		return "", ErrForbidden
	}
	signatureText := request.Header.Get("X-Punaro-Signature")
	signature, err := base64.RawURLEncoding.DecodeString(signatureText)
	if err != nil || base64.RawURLEncoding.EncodeToString(signature) != signatureText {
		return "", ErrForbidden
	}
	signed := SignedRequest{MachineID: request.Header.Get("X-Punaro-Machine"), Method: request.Method, Path: request.URL.Path, Body: body, Timestamp: timestamp, Nonce: request.Header.Get("X-Punaro-Nonce"), Signature: signature}
	if err := a.Verify(signed, now.UTC()); err != nil {
		return "", err
	}
	return signed.MachineID, nil
}

// AllowsEndpoint checks a configured endpoint namespace. It is used before an
// adapter can advertise or act as an endpoint, keeping friendly labels out of
// the authorization decision.
func (a *Authenticator) AllowsEndpoint(machineID, endpoint string) bool {
	machine, found := a.machines[machineID]
	if !found {
		return false
	}
	for _, exact := range machine.Endpoints {
		if endpoint == exact {
			return true
		}
	}
	for _, prefix := range machine.EndpointPrefixes {
		if strings.HasPrefix(endpoint, prefix) {
			return true
		}
	}
	return false
}

func machineOwnsEndpoint(machine Machine, endpoint string) bool {
	for _, exact := range machine.Endpoints {
		if endpoint == exact {
			return true
		}
	}
	for _, prefix := range machine.EndpointPrefixes {
		if strings.HasPrefix(endpoint, prefix) {
			return true
		}
	}
	return false
}

func validSignedRequest(request SignedRequest, now time.Time) bool {
	if strings.TrimSpace(request.Method) == "" || !strings.HasPrefix(request.Path, "/") || strings.ContainsAny(request.Path, "?#") || len(request.Nonce) == 0 || len(request.Nonce) > 128 || len(request.Signature) != ed25519.SignatureSize {
		return false
	}
	if request.Timestamp.IsZero() {
		return false
	}
	age := now.Sub(request.Timestamp)
	return age <= maxRequestAge && age >= -maxRequestAge
}

// EqualCanonicalRequest is useful to test signing implementations without
// exposing body data in logs. It avoids callers comparing mutable buffers.
func EqualCanonicalRequest(left, right SignedRequest) bool {
	return bytes.Equal(CanonicalRequest(left), CanonicalRequest(right))
}
