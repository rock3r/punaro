package attachment

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	// ErrUnauthorized deliberately does not disclose offer existence.
	ErrUnauthorized = errors.New("attachment operation is not authorized")
)

// Offer is an immutable recipient-bound attachment offer.
type Offer struct {
	ID         string
	TransferID string
	Recipient  string
	Spec       OfferSpec
}

// OfferSpec is the sender-signed, recipient-bound fallback declaration. It
// limits the only artifact a relay will retain for this offer and binds the
// recipient's completion acknowledgement to one plaintext commitment.
type OfferSpec struct {
	ArtifactID         string
	ChunkCount         int
	MaxCiphertextBytes int
	PlaintextHash      [hashSize]byte
}

// Session is a fenced capability for an accepted recipient offer.
type Session struct {
	Token      string
	Generation uint64
	ExpiresAt  time.Time
}

type offerState struct {
	offer   Offer
	session Session
}

// OfferStore is an in-memory reference implementation of recipient-bound,
// fenced offer state. Production persistence must preserve the same atomicity.
type OfferStore struct {
	mu          sync.Mutex
	offers      map[string]*offerState
	idempotency map[string]Offer
	now         func() time.Time
	leaseTTL    time.Duration
}

// NewOfferStore creates an empty offer store.
func NewOfferStore() *OfferStore {
	return newOfferStore(time.Now, defaultSessionLease)
}

const defaultSessionLease = 10 * time.Minute

func newOfferStore(now func() time.Time, leaseTTL time.Duration) *OfferStore {
	if now == nil {
		now = time.Now
	}
	if leaseTTL <= 0 {
		leaseTTL = defaultSessionLease
	}
	return &OfferStore{offers: make(map[string]*offerState), idempotency: make(map[string]Offer), now: now, leaseTTL: leaseTTL}
}

// CreateWithContext atomically deduplicates a sender/conversation request key
// and stores the authorization context alongside the offer in memory.
func (s *OfferStore) CreateWithContext(transferID, recipient, sender, conversation, idempotencyKey string, spec OfferSpec) (Offer, error) {
	if transferID == "" || recipient == "" || sender == "" || conversation == "" || idempotencyKey == "" || !spec.valid() {
		return Offer{}, ErrUnauthorized
	}
	id := sender + "\x00" + conversation + "\x00" + idempotencyKey
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.idempotency[id]; ok {
		if existing.TransferID != transferID || existing.Recipient != recipient || existing.Spec != spec {
			return Offer{}, ErrUnauthorized
		}
		return existing, nil
	}
	offerID, err := randomOpaqueID()
	if err != nil {
		return Offer{}, err
	}
	offer := Offer{ID: offerID, TransferID: transferID, Recipient: recipient, Spec: spec}
	s.offers[offerID] = &offerState{offer: offer}
	s.idempotency[id] = offer
	return offer, nil
}

func (s OfferSpec) valid() bool {
	if s.ChunkCount < 1 || s.ChunkCount > maxArtifactChunks || s.MaxCiphertextBytes < 1 || s.MaxCiphertextBytes > maxArtifactCiphertextBytes {
		return false
	}
	if len(s.ArtifactID) == 0 || len(s.ArtifactID) > 64 {
		return false
	}
	for _, character := range s.ArtifactID {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '-' && character != '_' {
			return false
		}
	}
	return true
}

// Create creates a recipient-bound offer with an opaque relay-generated ID.
func (s *OfferStore) Create(transferID, recipient string) (Offer, error) {
	if transferID == "" || recipient == "" {
		return Offer{}, fmt.Errorf("transfer ID and recipient are required")
	}
	id, err := randomOpaqueID()
	if err != nil {
		return Offer{}, err
	}
	offer := Offer{ID: id, TransferID: transferID, Recipient: recipient}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.offers[id] = &offerState{offer: offer}
	return offer, nil
}

// Accept atomically fences any earlier session and returns the only current one.
func (s *OfferStore) Accept(offerID, recipient string) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.offers[offerID]
	if !ok || state.offer.Recipient != recipient {
		return Session{}, ErrUnauthorized
	}
	token, err := randomOpaqueID()
	if err != nil {
		return Session{}, err
	}
	state.session = Session{Token: token, Generation: state.session.Generation + 1, ExpiresAt: s.now().Add(s.leaseTTL)}
	return state.session, nil
}

// Authorize verifies the recipient and current fencing session without leaking
// whether the failure was an unknown offer, wrong recipient, or stale session.
func (s *OfferStore) Authorize(offerID, recipient, token string, generation uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.offers[offerID]
	if !ok || state.offer.Recipient != recipient || generation != state.session.Generation || token == "" || !state.session.ExpiresAt.After(s.now()) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(state.session.Token)) == 1
}

func randomOpaqueID() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate opaque ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}
