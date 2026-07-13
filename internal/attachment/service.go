package attachment

import "sync"

const (
	maxSignalPayload           = 32 << 10
	maxSignalEntries           = 32
	maxSignalBytes             = 512 << 10
	maxArtifactChunkBytes      = 256 << 10
	maxArtifactChunks          = 4096
	maxArtifactCiphertextBytes = 64 << 20
	maxRelayOffers             = 1024
	maxRelayCiphertextBytes    = 1 << 30
	maxRelaySignalBytes        = 128 << 20
)

// Action is a server-side attachment authorization operation.
type Action uint8

const (
	// ActionCreate authorizes a sender to create a recipient-bound offer.
	ActionCreate Action = iota + 1
	// ActionUpload authorizes only the original sender to upload ciphertext.
	ActionUpload
	// ActionDownload authorizes only the offered recipient with a current lease.
	ActionDownload
	// ActionSignal authorizes bounded WebRTC/TURN signaling for an offer.
	ActionSignal
)

// Principal is the authenticated machine/device identity. It is deliberately
// supplied by the authentication layer, never decoded from an attachment body.
type Principal struct {
	DeviceID string
}

// Policy evaluates explicit conversation membership and action rights.
type Policy interface {
	Allowed(sender, conversation, recipient string, action Action) bool
}

// PolicyFunc adapts a function into a Policy.
type PolicyFunc func(sender, conversation, recipient string, action Action) bool

// Allowed implements Policy.
func (f PolicyFunc) Allowed(sender, conversation, recipient string, action Action) bool {
	return f(sender, conversation, recipient, action)
}

type serviceOffer struct {
	offer        Offer
	sender       string
	conversation string
}

// Signal is a bounded opaque WebRTC/TURN control-plane record. Payloads are
// never interpreted, logged, or included in normal mailbox messages.
type Signal struct {
	Sequence uint64
	From     string
	Payload  []byte
}

// OfferRepository provides the recipient-bound fencing state required by the
// service. Both memory and SQLite implementations preserve this contract.
type OfferRepository interface {
	Create(transferID, recipient string) (Offer, error)
	Accept(offerID, recipient string) (Session, error)
	Authorize(offerID, recipient, token string, generation uint64) bool
}

// OfferContextRepository persists authorization context needed to resume an
// offer after a relay restart.
type OfferContextRepository interface {
	SaveContext(offer Offer, sender, conversation string) error
	LoadContext(offerID string) (Offer, string, string, bool, error)
}

// IdempotentOfferRepository commits a creation request, its authorization
// context, and its deduplication key as one durable operation.
type IdempotentOfferRepository interface {
	CreateWithContext(transferID, recipient, sender, conversation, idempotencyKey string, spec OfferSpec) (Offer, error)
}

// BlobRepository persists immutable encrypted frames.
type BlobRepository interface {
	Put(key BlobKey, frame Chunk, maxBytes int) error
	Get(key BlobKey, index int) (Chunk, bool)
	HasAll(key BlobKey, count int) bool
}

// CompletionRepository persists verified recipient completion records.
type CompletionRepository interface {
	RecordCompletion(offerID, recipient string, plaintextHash [hashSize]byte) error
	HasCompletion(offerID, recipient string) bool
}

// FencedCompletionRepository atomically checks the current recipient lease and
// complete declared artifact before recording a completion.
type FencedCompletionRepository interface {
	RecordFencedCompletion(offer Offer, recipient string, session Session, plaintextHash [hashSize]byte) error
}

// SignalRepository persists ordered opaque direct/TURN signaling records.
type SignalRepository interface {
	AppendSignal(offerID, sender string, payload []byte) error
	ListSignals(offerID string) ([]Signal, error)
}

// Service applies authenticated membership policy before any attachment state
// mutation or ciphertext retrieval. It is transport-neutral so the HTTP adapter
// cannot accidentally replace server-side authorization with request fields.
type Service struct {
	policy Policy
	offers OfferRepository
	blobs  BlobRepository

	mu        sync.RWMutex
	metadata  map[string]serviceOffer
	completed map[string][hashSize]byte
	signals   map[string][]Signal
}

// NewService creates a transport-neutral attachment authorization service.
func NewService(policy Policy) *Service {
	return NewServiceWithOfferRepository(policy, NewOfferStore())
}

// NewServiceWithOfferRepository injects durable fencing state into the service.
func NewServiceWithOfferRepository(policy Policy, offers OfferRepository) *Service {
	blobs := BlobRepository(NewBlobStore())
	if durableBlobs, ok := offers.(BlobRepository); ok {
		blobs = durableBlobs
	}
	return NewServiceWithRepositories(policy, offers, blobs)
}

// NewServiceWithRepositories injects durable offer and blob implementations.
func NewServiceWithRepositories(policy Policy, offers OfferRepository, blobs BlobRepository) *Service {
	return &Service{policy: policy, offers: offers, blobs: blobs, metadata: make(map[string]serviceOffer), completed: make(map[string][hashSize]byte), signals: make(map[string][]Signal)}
}

// CreateOffer authorizes the sender against the recipient snapshot before the
// opaque offer ID exists.
func (s *Service) CreateOffer(sender Principal, conversation, recipient, transferID string) (Offer, error) {
	if sender.DeviceID == "" || s.policy == nil || !s.policy.Allowed(sender.DeviceID, conversation, recipient, ActionCreate) {
		return Offer{}, ErrUnauthorized
	}
	offer, err := s.offers.Create(transferID, recipient)
	if err != nil {
		return Offer{}, err
	}
	offer.Spec = defaultOfferSpec()
	meta := serviceOffer{offer: offer, sender: sender.DeviceID, conversation: conversation}
	if persistent, ok := s.offers.(OfferContextRepository); ok {
		if err := persistent.SaveContext(offer, sender.DeviceID, conversation); err != nil {
			return Offer{}, err
		}
	}
	s.mu.Lock()
	s.metadata[offer.ID] = meta
	s.mu.Unlock()
	return offer, nil
}

func defaultOfferSpec() OfferSpec {
	return OfferSpec{ArtifactID: "artifact", ChunkCount: maxArtifactChunks, MaxCiphertextBytes: maxArtifactCiphertextBytes}
}

// CreateOfferWithIdempotency is the relay-facing offer constructor. A retry of
// the same authenticated request returns the original recipient-bound offer;
// it never produces a second offer or a partially persisted context.
func (s *Service) CreateOfferWithIdempotency(sender Principal, conversation, recipient, transferID, idempotencyKey string, spec OfferSpec) (Offer, error) {
	if sender.DeviceID == "" || s.policy == nil || !spec.valid() || !s.policy.Allowed(sender.DeviceID, conversation, recipient, ActionCreate) {
		return Offer{}, ErrUnauthorized
	}
	creator, ok := s.offers.(IdempotentOfferRepository)
	if !ok {
		return Offer{}, ErrUnauthorized
	}
	offer, err := creator.CreateWithContext(transferID, recipient, sender.DeviceID, conversation, idempotencyKey, spec)
	if err != nil {
		return Offer{}, err
	}
	s.mu.Lock()
	s.metadata[offer.ID] = serviceOffer{offer: offer, sender: sender.DeviceID, conversation: conversation}
	s.mu.Unlock()
	return offer, nil
}

// AcceptOffer fences previous recipient sessions after identity and membership
// checks. It returns no offer-existence detail on failure.
func (s *Service) AcceptOffer(recipient Principal, offerID string) (Session, error) {
	meta, ok := s.lookup(offerID)
	if !ok || recipient.DeviceID != meta.offer.Recipient || !s.policy.Allowed(meta.sender, meta.conversation, recipient.DeviceID, ActionDownload) {
		return Session{}, ErrUnauthorized
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.offers.Accept(offerID, recipient.DeviceID)
}

// PutChunk admits ciphertext only from the original sender under an immutable
// recipient-specific artifact key.
func (s *Service) PutChunk(sender Principal, offer Offer, artifactID string, frame Chunk) error {
	meta, ok := s.lookup(offer.ID)
	if !ok || sender.DeviceID != meta.sender || offer != meta.offer || artifactID != meta.offer.Spec.ArtifactID || frame.Index < 0 || frame.Index >= meta.offer.Spec.ChunkCount || len(frame.Ciphertext) == 0 || len(frame.Ciphertext) > maxArtifactChunkBytes || !s.policy.Allowed(sender.DeviceID, meta.conversation, meta.offer.Recipient, ActionUpload) {
		return ErrUnauthorized
	}
	return s.blobs.Put(BlobKey{TransferID: meta.offer.TransferID, Recipient: meta.offer.Recipient, ArtifactID: artifactID}, frame, meta.offer.Spec.MaxCiphertextBytes)
}

// PutChunkByOfferID is the HTTP-facing equivalent of PutChunk. It preserves
// opaque failure behavior by resolving the offer only inside the service.
func (s *Service) PutChunkByOfferID(sender Principal, offerID, artifactID string, frame Chunk) error {
	meta, ok := s.lookup(offerID)
	if !ok {
		return ErrUnauthorized
	}
	return s.PutChunk(sender, meta.offer, artifactID, frame)
}

// GetChunk releases ciphertext only to the offered recipient presenting the
// current fencing session. It returns ErrUnauthorized for absent blobs too.
func (s *Service) GetChunk(recipient Principal, offer Offer, session Session, artifactID string, index int) (Chunk, error) {
	meta, ok := s.lookup(offer.ID)
	if !ok || offer != meta.offer || recipient.DeviceID != meta.offer.Recipient || !s.policy.Allowed(meta.sender, meta.conversation, recipient.DeviceID, ActionDownload) || !s.offers.Authorize(offer.ID, recipient.DeviceID, session.Token, session.Generation) {
		return Chunk{}, ErrUnauthorized
	}
	if artifactID != meta.offer.Spec.ArtifactID || index < 0 || index >= meta.offer.Spec.ChunkCount {
		return Chunk{}, ErrUnauthorized
	}
	frame, found := s.blobs.Get(BlobKey{TransferID: meta.offer.TransferID, Recipient: meta.offer.Recipient, ArtifactID: artifactID}, index)
	if !found {
		return Chunk{}, ErrUnauthorized
	}
	return frame, nil
}

// GetChunkByOfferID is the HTTP-facing equivalent of GetChunk.
func (s *Service) GetChunkByOfferID(recipient Principal, offerID string, session Session, artifactID string, index int) (Chunk, error) {
	meta, ok := s.lookup(offerID)
	if !ok {
		return Chunk{}, ErrUnauthorized
	}
	return s.GetChunk(recipient, meta.offer, session, artifactID, index)
}

// Complete records a recipient's verified plaintext hash only when it presents
// the current fencing session. Connection state alone is never completion.
func (s *Service) Complete(recipient Principal, offerID string, session Session, plaintextHash [hashSize]byte) error {
	meta, ok := s.lookup(offerID)
	if !ok || recipient.DeviceID != meta.offer.Recipient || plaintextHash != meta.offer.Spec.PlaintextHash || !s.policy.Allowed(meta.sender, meta.conversation, recipient.DeviceID, ActionDownload) {
		return ErrUnauthorized
	}
	if persistent, ok := s.offers.(FencedCompletionRepository); ok {
		return persistent.RecordFencedCompletion(meta.offer, recipient.DeviceID, session, plaintextHash)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.offers.Authorize(offerID, recipient.DeviceID, session.Token, session.Generation) || !s.blobs.HasAll(BlobKey{TransferID: meta.offer.TransferID, Recipient: meta.offer.Recipient, ArtifactID: meta.offer.Spec.ArtifactID}, meta.offer.Spec.ChunkCount) {
		return ErrUnauthorized
	}
	if existing, completed := s.completed[offerID]; completed && existing != plaintextHash {
		return ErrUnauthorized
	}
	if persistent, ok := s.offers.(CompletionRepository); ok {
		if err := persistent.RecordCompletion(offerID, recipient.DeviceID, plaintextHash); err != nil {
			return err
		}
	}
	s.completed[offerID] = plaintextHash
	return nil
}

// Completed reports whether a recipient completion was durably accepted by the
// configured completion implementation. The in-memory implementation is used
// only for tests until a durable repository is injected.
func (s *Service) Completed(offerID string) bool {
	s.mu.RLock()
	_, completed := s.completed[offerID]
	s.mu.RUnlock()
	if completed {
		return true
	}
	persistent, ok := s.offers.(CompletionRepository)
	if !ok {
		return false
	}
	meta, found := s.lookup(offerID)
	return found && persistent.HasCompletion(offerID, meta.offer.Recipient)
}

// Signal records bounded opaque signaling from either the original sender or
// the current recipient lease holder.
func (s *Service) Signal(principal Principal, offerID string, session Session, payload []byte) error {
	if len(payload) == 0 || len(payload) > maxSignalPayload {
		return ErrUnauthorized
	}
	meta, ok := s.lookup(offerID)
	if !ok || !s.policy.Allowed(meta.sender, meta.conversation, meta.offer.Recipient, ActionSignal) {
		return ErrUnauthorized
	}
	sender := principal.DeviceID == meta.sender
	recipient := principal.DeviceID == meta.offer.Recipient && s.offers.Authorize(offerID, principal.DeviceID, session.Token, session.Generation)
	if !sender && !recipient {
		return ErrUnauthorized
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.signals[offerID]) >= maxSignalEntries || signalBytes(s.signals[offerID])+len(payload) > maxSignalBytes {
		return ErrUnauthorized
	}
	if persistent, ok := s.offers.(SignalRepository); ok {
		if err := persistent.AppendSignal(offerID, principal.DeviceID, payload); err != nil {
			return err
		}
	}
	sequence := uint64(len(s.signals[offerID])) + 1
	s.signals[offerID] = append(s.signals[offerID], Signal{Sequence: sequence, From: principal.DeviceID, Payload: append([]byte(nil), payload...)})
	return nil
}

func signalBytes(signals []Signal) int {
	total := 0
	for _, signal := range signals {
		total += len(signal.Payload)
	}
	return total
}

// Signals returns defensive copies of the ordered opaque signaling records.
func (s *Service) Signals(offerID string) []Signal {
	if persistent, ok := s.offers.(SignalRepository); ok {
		signals, err := persistent.ListSignals(offerID)
		if err == nil {
			return signals
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	stored := s.signals[offerID]
	result := make([]Signal, len(stored))
	for index, signal := range stored {
		result[index] = Signal{Sequence: signal.Sequence, From: signal.From, Payload: append([]byte(nil), signal.Payload...)}
	}
	return result
}

// SignalsFor returns signaling only to the original sender or current recipient
// lease holder.
func (s *Service) SignalsFor(principal Principal, offerID string, session Session) ([]Signal, error) {
	meta, ok := s.lookup(offerID)
	if !ok || !s.policy.Allowed(meta.sender, meta.conversation, meta.offer.Recipient, ActionSignal) {
		return nil, ErrUnauthorized
	}
	sender := principal.DeviceID == meta.sender
	recipient := principal.DeviceID == meta.offer.Recipient && s.offers.Authorize(offerID, principal.DeviceID, session.Token, session.Generation)
	if !sender && !recipient {
		return nil, ErrUnauthorized
	}
	return s.Signals(offerID), nil
}

func (s *Service) lookup(offerID string) (serviceOffer, bool) {
	s.mu.RLock()
	meta, ok := s.metadata[offerID]
	s.mu.RUnlock()
	if ok {
		return meta, true
	}
	persistent, ok := s.offers.(OfferContextRepository)
	if !ok {
		return serviceOffer{}, false
	}
	offer, sender, conversation, found, err := persistent.LoadContext(offerID)
	if err != nil || !found {
		return serviceOffer{}, false
	}
	meta = serviceOffer{offer: offer, sender: sender, conversation: conversation}
	s.mu.Lock()
	s.metadata[offerID] = meta
	s.mu.Unlock()
	return meta, true
}
