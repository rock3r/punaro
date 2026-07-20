package relay

import (
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

func validBoundedText(value string, maxCharacters, maxBytes int) bool {
	if value == "" || strings.TrimSpace(value) != value || len(value) > maxBytes || utf8.RuneCountInString(value) > maxCharacters {
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

// ValidRequestToken bounds nonces, idempotency keys, and consumer identities.
func ValidRequestToken(value string) bool { return validBoundedText(value, 128, 512) }

// AppendRequestHash binds a message idempotency key to its immutable request.
func AppendRequestHash(input AppendInput) string { return appendHash(input) }

// CreateConversationRequestHash binds a conversation idempotency key to the
// normalized creator and membership set.
func CreateConversationRequestHash(creatorEndpoint string, members []Member) string {
	return createConversationHash(creatorEndpoint, members)
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
	LeaseDeliveries(machineID, consumerID, endpoint, conversationID string, now time.Time, ttl time.Duration, limit int) ([]Delivery, error)
	AckDelivery(machineID, endpoint, deliveryID, token string, generation int64, now time.Time) error
	RecipientCursor(machineID, endpoint, conversationID string, now time.Time) (int64, error)
	RecipientMachines(messageID string, now time.Time) ([]string, error)
	ConversationsForMachine(machineID string, now time.Time) ([]Conversation, error)
}

// NonceStore atomically consumes one signed-request nonce until its expiry.
// It is intentionally smaller than Backend so attachment-only handlers can
// share authentication without receiving mail mutation authority.
type NonceStore interface {
	ConsumeRequestNonce(machineID, nonce string, now, expiresAt time.Time) error
}

var _ Backend = (*Store)(nil)
