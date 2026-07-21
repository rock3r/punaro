package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
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
	store                NonceStore
	machines             map[string]Machine
	transition           TransitionAuthority
	transitionMachineIDs map[[sha256.Size]byte]string
}

// TransitionAuthority is the dormant bridge between the durable PostgreSQL
// migration inventory and the existing configured relay enrollment. For an
// Ed25519 request credential is empty and legacyKey is the verified configured
// key. For a device request credential is the opaque bearer and legacyKey is
// nil. A successful result is always the exact registered legacy public key;
// callers never accept a friendly label or principal ID as relay authority.
type TransitionAuthority interface {
	AuthorizeTransition(context.Context, string, ed25519.PublicKey) (TransitionAuthorization, error)
}

// TransitionAuthorization binds one successful request to its exact legacy
// key and a non-secret current-session fence. Current must recheck the durable
// gate or device generation without retaining bearer material.
type TransitionAuthorization struct {
	LegacyPublicKey ed25519.PublicKey
	Current         func(context.Context) error
}

// MachineSession is the authenticated relay identity plus an optional durable
// revalidation fence for long-lived transports.
type MachineSession struct {
	MachineID string
	current   func(context.Context) error
}

// Current fails closed when the durable transition authority is no longer
// current. Ordinary signed-request mode has no external transition fence.
func (s MachineSession) Current(ctx context.Context) error {
	if s.MachineID == "" {
		return ErrForbidden
	}
	if s.current == nil {
		return nil
	}
	if err := s.current(ctx); err != nil {
		return ErrForbidden
	}
	return nil
}

// NewAuthenticator accepts a complete explicit enrollment set. Enrollment is
// configuration-controlled, not message-controlled; duplicate IDs and unsafe
// endpoint rules fail startup rather than picking an arbitrary credential.
func NewAuthenticator(store NonceStore, machines []Machine) (*Authenticator, error) {
	return newAuthenticator(store, machines, nil)
}

// NewTransitionAuthenticator enables the explicitly selected, dormant
// Ed25519-to-device transition path. Static machine enrollments remain the sole
// endpoint authority; PostgreSQL only proves whether the legacy key or its
// exactly linked replacement credential may select that enrollment.
func NewTransitionAuthenticator(store NonceStore, machines []Machine, transition TransitionAuthority) (*Authenticator, error) {
	if transition == nil {
		return nil, fmt.Errorf("relay transition authenticator requires durable authority")
	}
	return newAuthenticator(store, machines, transition)
}

func newAuthenticator(store NonceStore, machines []Machine, transition TransitionAuthority) (*Authenticator, error) {
	if store == nil || len(machines) == 0 {
		return nil, fmt.Errorf("relay authenticator requires enrolled machines")
	}
	configured := make(map[string]Machine, len(machines))
	attachmentDevices := make(map[[16]byte]string, len(machines))
	for _, machine := range machines {
		if !ValidMachineID(machine.ID) || len(machine.PublicKey) != ed25519.PublicKeySize || (len(machine.EndpointPrefixes) == 0 && len(machine.Endpoints) == 0) {
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
			if !ValidEndpoint(endpoint) {
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
	transitionMachineIDs := make(map[[sha256.Size]byte]string, len(configured))
	if transition != nil {
		for machineID, machine := range configured {
			digest := sha256.Sum256(machine.PublicKey)
			if _, duplicate := transitionMachineIDs[digest]; duplicate {
				return nil, fmt.Errorf("ambiguous public key for transition enrollment")
			}
			transitionMachineIDs[digest] = machineID
		}
	}
	return &Authenticator{store: store, machines: configured, transition: transition, transitionMachineIDs: transitionMachineIDs}, nil
}

// validEndpointPrefix requires a complete mailbox path segment. Without the
// trailing slash, a raw prefix comparison could let `agent/a` claim
// `agent/abuse`; prefixes are authority boundaries, not friendly labels.
func validEndpointPrefix(prefix string) bool {
	return ValidEndpoint(prefix) && prefix != "/" && strings.HasSuffix(prefix, "/") && !strings.Contains(prefix, "//")
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
	machine, err := a.verifySignature(request, now)
	if err != nil {
		return ErrForbidden
	}
	return a.consumeNonce(machine.ID, request, now)
}

func (a *Authenticator) verifySignature(request SignedRequest, now time.Time) (Machine, error) {
	machine, found := a.machines[request.MachineID]
	if !found || !ValidRequestToken(request.Nonce) || !validSignedRequest(request, now) || !ed25519.Verify(machine.PublicKey, CanonicalRequest(request), request.Signature) {
		return Machine{}, ErrForbidden
	}
	return machine, nil
}

func (a *Authenticator) consumeNonce(machineID string, request SignedRequest, now time.Time) error {
	if err := a.store.ConsumeRequestNonce(machineID, request.Nonce, now, request.Timestamp.UTC().Add(maxRequestAge)); err != nil {
		if errors.Is(err, ErrMaintenance) {
			return ErrMaintenance
		}
		return ErrForbidden
	}
	return nil
}

// AuthenticateHTTP authenticates a request over its exact already-bounded
// body. Route handlers remain responsible for rejecting unsigned URL features
// (query strings and alternate escaped paths) before calling this method.
func (a *Authenticator) AuthenticateHTTP(request *http.Request, body []byte, now time.Time) (string, error) {
	session, err := a.AuthenticateHTTPSession(request, body, now)
	return session.MachineID, err
}

// AuthenticateHTTPSession authenticates one request and retains only the
// non-secret durable fence needed to revalidate a long-lived transport.
func (a *Authenticator) AuthenticateHTTPSession(request *http.Request, body []byte, now time.Time) (MachineSession, error) {
	if a == nil || request == nil {
		return MachineSession{}, ErrForbidden
	}
	if authorization := request.Header.Get("Authorization"); authorization != "" {
		return a.authenticateTransitionDevice(request, authorization)
	}
	timestamp, err := time.Parse(time.RFC3339Nano, request.Header.Get("X-Punaro-Timestamp"))
	if err != nil {
		return MachineSession{}, ErrForbidden
	}
	signatureText := request.Header.Get("X-Punaro-Signature")
	signature, err := base64.RawURLEncoding.DecodeString(signatureText)
	if err != nil || base64.RawURLEncoding.EncodeToString(signature) != signatureText {
		return MachineSession{}, ErrForbidden
	}
	signed := SignedRequest{MachineID: request.Header.Get("X-Punaro-Machine"), Method: request.Method, Path: request.URL.Path, Body: body, Timestamp: timestamp, Nonce: request.Header.Get("X-Punaro-Nonce"), Signature: signature}
	if a.transition == nil {
		if err := a.Verify(signed, now.UTC()); err != nil {
			return MachineSession{}, err
		}
		return MachineSession{MachineID: signed.MachineID}, nil
	}
	machine, err := a.verifySignature(signed, now.UTC())
	if err != nil {
		return MachineSession{}, err
	}
	authorization, err := a.transition.AuthorizeTransition(request.Context(), "", machine.PublicKey)
	if err != nil || authorization.Current == nil || !bytes.Equal(authorization.LegacyPublicKey, machine.PublicKey) {
		return MachineSession{}, ErrForbidden
	}
	if err := a.consumeNonce(machine.ID, signed, now.UTC()); err != nil {
		return MachineSession{}, err
	}
	return MachineSession{MachineID: signed.MachineID, current: authorization.Current}, nil
}

func (a *Authenticator) authenticateTransitionDevice(request *http.Request, authorization string) (MachineSession, error) {
	if a.transition == nil || len(request.Header.Values("Authorization")) != 1 || !strings.HasPrefix(authorization, "Bearer ") || strings.Count(authorization, " ") != 1 || request.Header.Get("X-Punaro-Machine") != "" || request.Header.Get("X-Punaro-Signature") != "" || request.Header.Get("X-Punaro-Timestamp") != "" || request.Header.Get("X-Punaro-Nonce") != "" {
		return MachineSession{}, ErrForbidden
	}
	credential := strings.TrimPrefix(authorization, "Bearer ")
	if credential == "" {
		return MachineSession{}, ErrForbidden
	}
	transition, err := a.transition.AuthorizeTransition(request.Context(), credential, nil)
	if err != nil || transition.Current == nil || len(transition.LegacyPublicKey) != ed25519.PublicKeySize {
		return MachineSession{}, ErrForbidden
	}
	machineID, found := a.transitionMachineIDs[sha256.Sum256(transition.LegacyPublicKey)]
	if !found || !bytes.Equal(a.machines[machineID].PublicKey, transition.LegacyPublicKey) {
		return MachineSession{}, ErrForbidden
	}
	return MachineSession{MachineID: machineID, current: transition.Current}, nil
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
