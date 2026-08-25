package postgres

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	maxEnrollmentProjects = 100
	minEnrollmentTTL      = time.Minute
	maxEnrollmentTTL      = 24 * time.Hour
)

// GrantSpec is one principal-independent grant displayed before enrollment.
type GrantSpec struct {
	Scope      GrantScope `json:"scope"`
	ProjectID  string     `json:"project_id,omitempty"`
	Capability Capability `json:"capability"`
}

var trustedAgentProjectCapabilities = [...]Capability{
	CapabilityProjectDiscover,
	CapabilityProjectRead,
	CapabilityProjectWrite,
	CapabilityProjectAttachUnclaimed,
	CapabilityConversationSend,
	CapabilityConversationReceive,
	CapabilityMemorySearch,
	CapabilityMemoryRead,
	CapabilityMemoryPropose,
	CapabilityMemoryWrite,
	CapabilityAttachmentUpload,
	CapabilityAttachmentDownload,
}

// TrustedAgentGrantPreview returns the exact stable expansion shown to an
// operator before a pending enrollment is created.
func TrustedAgentGrantPreview(projectIDs []string, allProjects bool) ([]GrantSpec, error) {
	if allProjects == (len(projectIDs) > 0) {
		return nil, errors.New("select projects or all projects")
	}
	seen := make(map[string]struct{}, len(projectIDs))
	for _, projectID := range projectIDs {
		if !validOpaqueID(projectID) {
			return nil, errors.New("invalid enrollment project")
		}
		if _, exists := seen[projectID]; exists {
			return nil, errors.New("duplicate enrollment project")
		}
		seen[projectID] = struct{}{}
	}
	projectIDs = slices.Clone(projectIDs)
	slices.Sort(projectIDs)
	grants := make([]GrantSpec, 0, 1+len(trustedAgentProjectCapabilities)*max(1, len(projectIDs)))
	grants = append(grants, GrantSpec{Scope: ScopeInstallation, Capability: CapabilityProjectCreate})
	if allProjects {
		for _, capability := range trustedAgentProjectCapabilities {
			grants = append(grants, GrantSpec{Scope: ScopeAllProjects, Capability: capability})
		}
		return grants, nil
	}
	for _, projectID := range projectIDs {
		for _, capability := range trustedAgentProjectCapabilities {
			grants = append(grants, GrantSpec{Scope: ScopeProject, ProjectID: projectID, Capability: capability})
		}
	}
	return grants, nil
}

// PreviewTrustedAgentEnrollment returns the exact grant list and a stable hash
// that must be confirmed when the host-local enrollment is created.
func PreviewTrustedAgentEnrollment(projectIDs []string, allProjects bool) ([]GrantSpec, string, error) {
	grants, err := TrustedAgentGrantPreview(projectIDs, allProjects)
	if err != nil {
		return nil, "", err
	}
	return previewEnrollment(grants)
}

// PreviewServiceEnrollment returns an explicitly empty capability expansion
// for service identities that authenticate health checks but need no API
// authority of their own.
func PreviewServiceEnrollment() ([]GrantSpec, string, error) {
	return previewEnrollment([]GrantSpec{})
}

func previewEnrollment(grants []GrantSpec) ([]GrantSpec, string, error) {
	body, err := json.Marshal(grants)
	if err != nil {
		return nil, "", errors.New("enrollment preview cannot be encoded")
	}
	digest := sha256.Sum256(body)
	return grants, hex.EncodeToString(digest[:]), nil
}

// EnrollmentRequest is a bounded host-local request to create one pending client.
type EnrollmentRequest struct {
	ClientBinding     string
	MachineID         string
	Label             string
	ProjectIDs        []string
	AllProjects       bool
	ServiceOnly       bool
	LegacyPrincipalID string
	TTL               time.Duration
	CredentialTTL     time.Duration
	ExpiresAt         time.Time
}

// Validate rejects ambiguous grants, friendly client bindings, and unsafe lifetimes.
func (r EnrollmentRequest) Validate() error {
	if !validOpaqueID(r.ClientBinding) || !validLifecycleMachineID(r.MachineID) || !validDisplayName(r.Label) || len(r.ProjectIDs) > maxEnrollmentProjects || r.TTL < minEnrollmentTTL || r.TTL > maxEnrollmentTTL || r.CredentialTTL != 0 || !r.ExpiresAt.IsZero() || (r.LegacyPrincipalID != "" && !validOpaqueID(r.LegacyPrincipalID)) {
		return errors.New("invalid enrollment request")
	}
	if r.ServiceOnly {
		if len(r.ProjectIDs) != 0 || r.AllProjects || r.LegacyPrincipalID != "" {
			return errors.New("invalid enrollment request")
		}
		return nil
	}
	_, err := TrustedAgentGrantPreview(r.ProjectIDs, r.AllProjects)
	return err
}

func validLifecycleMachineID(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	first := value[0]
	switch {
	case first >= 'a' && first <= 'z':
	case first >= '0' && first <= '9':
	default:
		return false
	}
	for index, character := range []byte(value) {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			continue
		}
		if index > 0 && index < len(value)-1 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
}

func newDeviceCredential() (encoded, lookupID string, digest [sha256.Size]byte, err error) {
	lookup, err := uuid.NewRandom()
	if err != nil {
		return "", "", digest, errors.New("credential entropy is unavailable")
	}
	lookupID = lookup.String()
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		return "", "", digest, errors.New("credential entropy is unavailable")
	}
	digest = sha256.Sum256(secret)
	encoded = lookupID + "." + base64.RawURLEncoding.EncodeToString(secret)
	return encoded, lookupID, digest, nil
}

func parseDeviceCredential(encoded string) (string, []byte, error) {
	lookupID, secretText, found := strings.Cut(encoded, ".")
	if !found || !validOpaqueID(lookupID) || strings.Contains(secretText, "=") {
		return "", nil, errors.New("invalid device credential")
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(secretText)
	if err != nil || len(secret) != 32 || base64.RawURLEncoding.EncodeToString(secret) != secretText {
		return "", nil, errors.New("invalid device credential")
	}
	return lookupID, secret, nil
}
