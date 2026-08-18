package relay

import (
	"encoding/base64"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var canonicalRoleSlug = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func validBoundedText(value string, maxCharacters, maxBytes int) bool {
	if value == "" || !utf8.ValidString(value) || strings.TrimSpace(value) != value || len(value) > maxBytes || utf8.RuneCountInString(value) > maxCharacters {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

// ValidMachineID reports whether an enrolled machine identifier has portable
// SQLite/PostgreSQL representation.
func ValidMachineID(value string) bool { return validBoundedText(value, 128, 512) }

// ValidEndpoint reports whether a mailbox address has portable durable bounds.
func ValidEndpoint(value string) bool { return validBoundedText(value, 512, 2048) }

// ValidRole reports whether a durable conversation-role identity has portable
// storage bounds. Roles and session endpoints deliberately occupy separate
// namespaces in the relay model even when their textual labels are similar.
func ValidRole(value string) bool { return validBoundedText(value, 512, 2048) }

// CanonicalRoleHandle reports whether role has the immutable machine-qualified
// form role/<machine>/<slug> without checking which machine owns it.
func CanonicalRoleHandle(role string) bool {
	if !ValidRole(role) {
		return false
	}
	rest, ok := strings.CutPrefix(role, "role/")
	if !ok {
		return false
	}
	machine, slug, ok := strings.Cut(rest, "/")
	return ok && !strings.Contains(slug, "/") && ValidMachineID(machine) && canonicalRoleSlug.MatchString(slug)
}

// CanonicalRoleForMachine reports whether role is the immutable machine-qualified
// handle role/<machine>/<slug> for the authenticated owner.
func CanonicalRoleForMachine(role, machineID string) bool {
	if !ValidMachineID(machineID) || !CanonicalRoleHandle(role) {
		return false
	}
	rest, _ := strings.CutPrefix(role, "role/")
	machine, _, _ := strings.Cut(rest, "/")
	return machine == machineID
}

// OrderedDirectRolePair returns the lexicographic unordered pair for two distinct
// canonical roles. Equal or non-canonical handles are rejected.
func OrderedDirectRolePair(left, right string) (string, string, bool) {
	if !CanonicalRoleHandle(left) || !CanonicalRoleHandle(right) || left == right {
		return "", "", false
	}
	if left < right {
		return left, right, true
	}
	return right, left, true
}

// DirectMessageRequestHash binds a direct-send idempotency key to source role,
// target role, and body. Conversation ID is assigned after this hash.
func DirectMessageRequestHash(fromRole, toRole, body string) string {
	return stableHash(fromRole, toRole, body)
}

// CanonicalRoleSlug returns the immutable trailing slug of a canonical handle.
func CanonicalRoleSlug(role string) (string, bool) {
	if !CanonicalRoleHandle(role) {
		return "", false
	}
	rest, _ := strings.CutPrefix(role, "role/")
	_, slug, _ := strings.Cut(rest, "/")
	return slug, true
}

// ValidRoleSlug reports whether value is a canonical role slug, not a display name.
func ValidRoleSlug(value string) bool {
	return canonicalRoleSlug.MatchString(value)
}

// EncodeRoleListCursor hides the last canonical role behind an opaque page token.
func EncodeRoleListCursor(role string) string {
	if !CanonicalRoleHandle(role) {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString([]byte(role))
}

// DecodeRoleListCursor reports the last canonical role of an opaque page token.
func DecodeRoleListCursor(cursor string) (string, bool) {
	if cursor == "" {
		return "", true
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return "", false
	}
	role := string(raw)
	if !CanonicalRoleHandle(role) {
		return "", false
	}
	return role, true
}

// NormalizeRoleDisplayName trims an optional portable display name. Empty after
// trim means the role has no display name. It is never authorization.
func NormalizeRoleDisplayName(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", true
	}
	if !validBoundedText(trimmed, 128, 128) {
		return "", false
	}
	return trimmed, true
}

// RegisterRoleRequestHash binds a registration idempotency key to the normalized request.
func RegisterRoleRequestHash(role, displayName string, directAddressable bool) string {
	addressable := "0"
	if directAddressable {
		addressable = "1"
	}
	return stableHash(role, displayName, addressable)
}

// ValidRequestToken bounds nonces, idempotency keys, and consumer identities.
func ValidRequestToken(value string) bool { return validBoundedText(value, 128, 512) }

// ValidMessageBody reports whether a message has a portable SQLite/PostgreSQL
// text representation within the durable relay limit.
func ValidMessageBody(value string) bool {
	return len(value) <= maxMessageBodyBytes && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}

// AppendRequestHash binds a message idempotency key to its immutable request.
func AppendRequestHash(input AppendInput) string { return appendHash(input) }

// CreateConversationRequestHash binds a conversation idempotency key to the
// normalized creator and membership set.
func CreateConversationRequestHash(creatorEndpoint string, members []Member, projectID ...string) string {
	digest := createConversationHash(creatorEndpoint, members)
	if len(projectID) == 0 || projectID[0] == "" {
		return digest
	}
	return stableHash(digest, projectID[0])
}

// Backend is the complete durable mail boundary shared by the SQLite parity
// store and the selectable PostgreSQL implementation. HTTP authentication and
// authorization remain outside this interface; every method still rechecks
// the durable ownership needed for its own operation.
type Backend interface {
	NonceStore
	AdvertiseEndpoints(machineID string, endpoints []string, now time.Time, ttl time.Duration) error
	AssertEndpointOwnership(machineID, endpoint string, now time.Time) error
	CreateConversationIdempotent(CreateConversationInput) (Conversation, error)
	AuthorizeSender(conversationID, machineID, endpoint string, now time.Time) error
	AppendMessage(AppendInput) (Message, bool, error)
	LeaseDeliveries(machineID, consumerID, endpoint, conversationID string, now time.Time, ttl time.Duration, limit int) (DeliveryLeasePage, error)
	AckDelivery(machineID, endpoint, deliveryID, token string, generation int64, now time.Time) error
	RecipientCursor(machineID, endpoint, conversationID string, now time.Time) (int64, error)
	RecipientMachines(messageID string, now time.Time) ([]string, error)
	ConversationsForMachine(machineID string, now time.Time) ([]Conversation, error)
}

// InvocationBackend is intentionally separate from Backend while PostgreSQL
// mail cutover parity is staged. Selected backends without it fail closed
// rather than treating a normal message or notification as process control.
type InvocationBackend interface {
	RequestInvocation(InvokeInput) (Invocation, bool, error)
	LeaseInvocations(machineID, consumerID string, now time.Time, ttl time.Duration, limit int) ([]Invocation, error)
	ReportInvocation(machineID, invocationID, token string, generation int64, accepted bool, now time.Time) error
	RejectInvocation(machineID, invocationID, token string, generation int64, now time.Time) error
}

// ControlBackend is deliberately separate from message delivery: only
// backends that implement this explicit membership-control surface may mutate
// a running conversation.
type ControlBackend interface {
	ApplyControl(ControlInput) (ControlEvent, bool, error)
	ControlAudit(conversationID, machineID, actorEndpoint string, now time.Time) ([]ControlEvent, error)
}

// PrincipalEndpointBackend atomically binds advertised endpoint ownership to
// the stable authenticated principal used by trusted attachment snapshots.
// Legacy backends remain mail-only and need not implement it.
type PrincipalEndpointBackend interface {
	AdvertiseEndpointsForPrincipal(machineID string, authority PrincipalAuthority, endpoints []string, now time.Time, ttl time.Duration) error
}

// RoleBindingBackend is implemented by stores that persist durable role
// identities. Binding always proves the caller owns the currently attached
// session; the binding itself has a bounded renewable lease.
type RoleBindingBackend interface {
	BindRoleToSession(machineID, role, sessionEndpoint string, now time.Time, ttl time.Duration) error
}

// RoleProfileBackend persists opt-in addressable role identity. Profile state
// is distinct from transient session bindings and from legacy conversation roles.
type RoleProfileBackend interface {
	RegisterRoleProfile(RegisterRoleInput) (RoleProfile, bool, error)
	RoleProfile(role string) (RoleProfile, error)
	ListAddressableRoles(RoleListInput) (RoleListPage, error)
	ResolveAddressableRole(RoleResolveInput) (RoleResolveResult, error)
}

// DirectMessageBackend creates or reuses one conversation for an unordered
// opted-in role pair and appends a targeted message in the same transaction.
type DirectMessageBackend interface {
	SendDirectMessage(DirectMessageInput) (Message, bool, error)
}

// PrincipalAuthority is the non-secret, generation-fenced result of device
// credential authentication. It is never populated from request JSON.
type PrincipalAuthority struct {
	PrincipalID          string
	CredentialLookupID   string
	CredentialGeneration int64
}

// NonceStore atomically consumes one signed-request nonce until its expiry.
// It is intentionally smaller than Backend so attachment-only handlers can
// share authentication without receiving mail mutation authority.
type NonceStore interface {
	ConsumeRequestNonce(machineID, nonce string, now, expiresAt time.Time) error
}

var _ Backend = (*Store)(nil)
var _ RoleProfileBackend = (*Store)(nil)
var _ DirectMessageBackend = (*Store)(nil)
