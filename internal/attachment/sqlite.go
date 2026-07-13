package attachment

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite" // SQLite driver registration for the durable attachment store.
)

// SQLiteOfferStore persists recipient-bound offers and fencing sessions in the
// relay's local SQLite database. It is safe to reopen after a process restart.
type SQLiteOfferStore struct {
	db       *sql.DB
	writeMu  sync.Mutex
	now      func() time.Time
	leaseTTL time.Duration
}

// OpenSQLiteOfferStore opens and migrates the durable offer store at path.
func OpenSQLiteOfferStore(path string) (*SQLiteOfferStore, error) {
	return openSQLiteOfferStore(path, time.Now, defaultSessionLease)
}

func openSQLiteOfferStore(path string, now func() time.Time, leaseTTL time.Duration) (*SQLiteOfferStore, error) {
	if now == nil {
		now = time.Now
	}
	if leaseTTL <= 0 {
		leaseTTL = defaultSessionLease
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open attachment sqlite database: %w", err)
	}
	store := &SQLiteOfferStore{db: db, now: now, leaseTTL: leaseTTL}
	if _, err := db.ExecContext(context.Background(), `PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS attachment_offers (
 id TEXT PRIMARY KEY, transfer_id TEXT NOT NULL, recipient TEXT NOT NULL,
 sender TEXT NOT NULL DEFAULT '', conversation TEXT NOT NULL DEFAULT '',
 session_token TEXT NOT NULL DEFAULT '', generation INTEGER NOT NULL DEFAULT 0,
 session_expires_at INTEGER NOT NULL DEFAULT 0,
 artifact_id TEXT NOT NULL DEFAULT '', chunk_count INTEGER NOT NULL DEFAULT 0,
 max_ciphertext_bytes INTEGER NOT NULL DEFAULT 0, plaintext_hash BLOB NOT NULL DEFAULT X'',
 UNIQUE (transfer_id, recipient)
);
CREATE TABLE IF NOT EXISTS attachment_chunks (
 transfer_id TEXT NOT NULL, recipient TEXT NOT NULL, artifact_id TEXT NOT NULL,
 chunk_index INTEGER NOT NULL, ciphertext BLOB NOT NULL, ciphertext_hash BLOB NOT NULL,
 PRIMARY KEY (transfer_id, recipient, artifact_id, chunk_index)
);
CREATE TABLE IF NOT EXISTS attachment_completions (
 offer_id TEXT NOT NULL, recipient TEXT NOT NULL, plaintext_hash BLOB NOT NULL,
 PRIMARY KEY (offer_id, recipient)
);
CREATE TABLE IF NOT EXISTS attachment_signals (
 offer_id TEXT NOT NULL, sequence INTEGER NOT NULL, sender TEXT NOT NULL, payload BLOB NOT NULL,
 PRIMARY KEY (offer_id, sequence)
);
CREATE TABLE IF NOT EXISTS attachment_request_nonces (
 device TEXT NOT NULL, nonce TEXT NOT NULL, expires_at INTEGER NOT NULL,
 PRIMARY KEY (device, nonce)
);
CREATE TABLE IF NOT EXISTS attachment_create_idempotency (
 sender TEXT NOT NULL, conversation TEXT NOT NULL, request_key TEXT NOT NULL,
 offer_id TEXT NOT NULL, transfer_id TEXT NOT NULL, recipient TEXT NOT NULL,
 PRIMARY KEY (sender, conversation, request_key)
);`); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			return nil, fmt.Errorf("migrate attachment sqlite database: %w", errors.Join(err, closeErr))
		}
		return nil, fmt.Errorf("migrate attachment sqlite database: %w", err)
	}
	return store, nil
}

// CreateWithContext atomically creates or returns an offer keyed by the
// sender's idempotency request key, preventing duplicate offers after retries.
func (s *SQLiteOfferStore) CreateWithContext(transferID, recipient, sender, conversation, idempotencyKey string, spec OfferSpec) (Offer, error) {
	if transferID == "" || recipient == "" || sender == "" || conversation == "" || idempotencyKey == "" || !spec.valid() {
		return Offer{}, ErrUnauthorized
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return Offer{}, fmt.Errorf("begin attachment offer create: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var existing Offer
	var plaintextHash []byte
	err = tx.QueryRowContext(context.Background(), `SELECT o.id, o.transfer_id, o.recipient, o.artifact_id, o.chunk_count, o.max_ciphertext_bytes, o.plaintext_hash
FROM attachment_create_idempotency AS i JOIN attachment_offers AS o ON o.id = i.offer_id
WHERE i.sender = ? AND i.conversation = ? AND i.request_key = ?`, sender, conversation, idempotencyKey).Scan(&existing.ID, &existing.TransferID, &existing.Recipient, &existing.Spec.ArtifactID, &existing.Spec.ChunkCount, &existing.Spec.MaxCiphertextBytes, &plaintextHash)
	if err == nil {
		if len(plaintextHash) != hashSize {
			return Offer{}, ErrUnauthorized
		}
		copy(existing.Spec.PlaintextHash[:], plaintextHash)
		if existing.TransferID != transferID || existing.Recipient != recipient || existing.Spec != spec {
			return Offer{}, ErrUnauthorized
		}
		if err := tx.Commit(); err != nil {
			return Offer{}, fmt.Errorf("commit attachment offer retry: %w", err)
		}
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Offer{}, fmt.Errorf("read attachment offer retry: %w", err)
	}
	var offers int
	if err := tx.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM attachment_offers`).Scan(&offers); err != nil {
		return Offer{}, fmt.Errorf("read attachment offer budget: %w", err)
	}
	if offers >= maxRelayOffers {
		return Offer{}, ErrUnauthorized
	}
	id, err := randomOpaqueID()
	if err != nil {
		return Offer{}, err
	}
	offer := Offer{ID: id, TransferID: transferID, Recipient: recipient, Spec: spec}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO attachment_offers (id, transfer_id, recipient, sender, conversation, artifact_id, chunk_count, max_ciphertext_bytes, plaintext_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, offer.ID, offer.TransferID, offer.Recipient, sender, conversation, spec.ArtifactID, spec.ChunkCount, spec.MaxCiphertextBytes, spec.PlaintextHash[:]); err != nil {
		return Offer{}, fmt.Errorf("persist attachment offer: %w", err)
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO attachment_create_idempotency (sender, conversation, request_key, offer_id, transfer_id, recipient) VALUES (?, ?, ?, ?, ?, ?)`, sender, conversation, idempotencyKey, offer.ID, offer.TransferID, offer.Recipient); err != nil {
		return Offer{}, fmt.Errorf("persist attachment offer idempotency: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Offer{}, fmt.Errorf("commit attachment offer: %w", err)
	}
	return offer, nil
}

// ConsumeNonce durably rejects a device nonce that has already been used in
// its validity window. SQLite's primary key makes the decision atomic across
// authenticator reconstruction in the same relay database.
func (s *SQLiteOfferStore) ConsumeNonce(device, nonce string, now, expiry time.Time) bool {
	if device == "" || nonce == "" {
		return false
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return false
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(context.Background(), `DELETE FROM attachment_request_nonces WHERE expires_at <= ?`, now.Unix()); err != nil {
		return false
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO attachment_request_nonces (device, nonce, expires_at) VALUES (?, ?, ?)`, device, nonce, expiry.Unix()); err != nil {
		return false
	}
	return tx.Commit() == nil
}

// Close closes the durable database handle.
func (s *SQLiteOfferStore) Close() error {
	return s.db.Close()
}

// Create persists a recipient-bound offer.
func (s *SQLiteOfferStore) Create(transferID, recipient string) (Offer, error) {
	if transferID == "" || recipient == "" {
		return Offer{}, fmt.Errorf("transfer ID and recipient are required")
	}
	id, err := randomOpaqueID()
	if err != nil {
		return Offer{}, err
	}
	offer := Offer{ID: id, TransferID: transferID, Recipient: recipient, Spec: defaultOfferSpec()}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if _, err := s.db.ExecContext(context.Background(), `INSERT INTO attachment_offers (id, transfer_id, recipient, artifact_id, chunk_count, max_ciphertext_bytes, plaintext_hash) VALUES (?, ?, ?, ?, ?, ?, ?)`, offer.ID, offer.TransferID, offer.Recipient, offer.Spec.ArtifactID, offer.Spec.ChunkCount, offer.Spec.MaxCiphertextBytes, offer.Spec.PlaintextHash[:]); err != nil {
		return Offer{}, fmt.Errorf("persist attachment offer: %w", err)
	}
	return offer, nil
}

// SaveContext persists the sender and conversation authorization binding.
func (s *SQLiteOfferStore) SaveContext(offer Offer, sender, conversation string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	result, err := s.db.ExecContext(context.Background(), `UPDATE attachment_offers SET sender = ?, conversation = ? WHERE id = ? AND transfer_id = ? AND recipient = ?`, sender, conversation, offer.ID, offer.TransferID, offer.Recipient)
	if err != nil {
		return fmt.Errorf("persist attachment offer context: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return ErrUnauthorized
	}
	return nil
}

// LoadContext recovers a persisted offer and its authorization context.
func (s *SQLiteOfferStore) LoadContext(offerID string) (Offer, string, string, bool, error) {
	var offer Offer
	var sender, conversation string
	var plaintextHash []byte
	err := s.db.QueryRowContext(context.Background(), `SELECT id, transfer_id, recipient, sender, conversation, artifact_id, chunk_count, max_ciphertext_bytes, plaintext_hash FROM attachment_offers WHERE id = ?`, offerID).Scan(&offer.ID, &offer.TransferID, &offer.Recipient, &sender, &conversation, &offer.Spec.ArtifactID, &offer.Spec.ChunkCount, &offer.Spec.MaxCiphertextBytes, &plaintextHash)
	if err == sql.ErrNoRows {
		return Offer{}, "", "", false, nil
	}
	if err != nil {
		return Offer{}, "", "", false, fmt.Errorf("load attachment offer context: %w", err)
	}
	if sender == "" || conversation == "" || len(plaintextHash) != hashSize || !offer.Spec.valid() {
		return Offer{}, "", "", false, nil
	}
	copy(offer.Spec.PlaintextHash[:], plaintextHash)
	return offer, sender, conversation, true, nil
}

// Put atomically accepts an encrypted frame once, or accepts an identical retry.
func (s *SQLiteOfferStore) Put(key BlobKey, frame Chunk, maxBytes int) error {
	if key.TransferID == "" || key.Recipient == "" || key.ArtifactID == "" || frame.Index < 0 {
		return fmt.Errorf("invalid blob key or frame index")
	}
	computed := hash("punaro/attachment/ciphertext/v2\x00", frame.Ciphertext)
	if subtle.ConstantTimeCompare(computed[:], frame.Hash[:]) != 1 {
		return fmt.Errorf("chunk %d hash mismatch", frame.Index)
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("begin attachment chunk store: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var existingCiphertext, existingHash []byte
	err = tx.QueryRowContext(context.Background(), `SELECT ciphertext, ciphertext_hash FROM attachment_chunks WHERE transfer_id = ? AND recipient = ? AND artifact_id = ? AND chunk_index = ?`, key.TransferID, key.Recipient, key.ArtifactID, frame.Index).Scan(&existingCiphertext, &existingHash)
	if err == nil {
		if subtle.ConstantTimeCompare(existingCiphertext, frame.Ciphertext) == 1 && subtle.ConstantTimeCompare(existingHash, frame.Hash[:]) == 1 {
			return tx.Commit()
		}
		return errImmutableChunk
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read attachment chunk: %w", err)
	}
	var storedBytes int
	if err := tx.QueryRowContext(context.Background(), `SELECT COALESCE(SUM(length(ciphertext)), 0) FROM attachment_chunks WHERE transfer_id = ? AND recipient = ? AND artifact_id = ?`, key.TransferID, key.Recipient, key.ArtifactID).Scan(&storedBytes); err != nil {
		return fmt.Errorf("read attachment chunk budget: %w", err)
	}
	if maxBytes < 1 || storedBytes+len(frame.Ciphertext) > maxBytes {
		return ErrUnauthorized
	}
	var relayBytes int
	if err := tx.QueryRowContext(context.Background(), `SELECT COALESCE(SUM(length(ciphertext)), 0) FROM attachment_chunks`).Scan(&relayBytes); err != nil {
		return fmt.Errorf("read relay ciphertext budget: %w", err)
	}
	if relayBytes+len(frame.Ciphertext) > maxRelayCiphertextBytes {
		return ErrUnauthorized
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO attachment_chunks (transfer_id, recipient, artifact_id, chunk_index, ciphertext, ciphertext_hash) VALUES (?, ?, ?, ?, ?, ?)`, key.TransferID, key.Recipient, key.ArtifactID, frame.Index, frame.Ciphertext, frame.Hash[:]); err != nil {
		return fmt.Errorf("persist attachment chunk: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit attachment chunk: %w", err)
	}
	return nil
}

// HasAll reports whether every declared immutable frame is present.
func (s *SQLiteOfferStore) HasAll(key BlobKey, count int) bool {
	if count < 1 {
		return false
	}
	var stored int
	err := s.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM attachment_chunks WHERE transfer_id = ? AND recipient = ? AND artifact_id = ?`, key.TransferID, key.Recipient, key.ArtifactID).Scan(&stored)
	return err == nil && stored == count
}

// Get loads a validated immutable ciphertext frame.
func (s *SQLiteOfferStore) Get(key BlobKey, index int) (Chunk, bool) {
	if index < 0 {
		return Chunk{}, false
	}
	var frame Chunk
	var hashBytes []byte
	err := s.db.QueryRowContext(context.Background(), `SELECT ciphertext, ciphertext_hash FROM attachment_chunks WHERE transfer_id = ? AND recipient = ? AND artifact_id = ? AND chunk_index = ?`, key.TransferID, key.Recipient, key.ArtifactID, index).Scan(&frame.Ciphertext, &hashBytes)
	if err != nil || len(hashBytes) != hashSize {
		return Chunk{}, false
	}
	frame.Index = index
	copy(frame.Hash[:], hashBytes)
	computed := hash("punaro/attachment/ciphertext/v2\x00", frame.Ciphertext)
	if subtle.ConstantTimeCompare(computed[:], frame.Hash[:]) != 1 {
		return Chunk{}, false
	}
	return frame, true
}

// RecordCompletion stores a verified plaintext result once. An identical retry
// succeeds; a different hash for the same recipient/offer is rejected.
func (s *SQLiteOfferStore) RecordCompletion(offerID, recipient string, plaintextHash [hashSize]byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("begin attachment completion: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var existing []byte
	err = tx.QueryRowContext(context.Background(), `SELECT plaintext_hash FROM attachment_completions WHERE offer_id = ? AND recipient = ?`, offerID, recipient).Scan(&existing)
	if err == nil {
		if subtle.ConstantTimeCompare(existing, plaintextHash[:]) == 1 {
			return tx.Commit()
		}
		return ErrUnauthorized
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read attachment completion: %w", err)
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO attachment_completions (offer_id, recipient, plaintext_hash) VALUES (?, ?, ?)`, offerID, recipient, plaintextHash[:]); err != nil {
		return fmt.Errorf("persist attachment completion: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit attachment completion: %w", err)
	}
	return nil
}

// RecordFencedCompletion atomically verifies the durable current lease and
// declared artifact before committing completion. A concurrent accept cannot
// fence the session between authorization and the completion insert.
func (s *SQLiteOfferStore) RecordFencedCompletion(offer Offer, recipient string, session Session, plaintextHash [hashSize]byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("begin fenced attachment completion: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var actualRecipient, token, artifactID string
	var generation uint64
	var expiry int64
	var chunkCount, maxBytes int
	var expectedHash []byte
	err = tx.QueryRowContext(context.Background(), `SELECT recipient, session_token, generation, session_expires_at, artifact_id, chunk_count, max_ciphertext_bytes, plaintext_hash
FROM attachment_offers WHERE id = ?`, offer.ID).Scan(&actualRecipient, &token, &generation, &expiry, &artifactID, &chunkCount, &maxBytes, &expectedHash)
	if err != nil || actualRecipient != recipient || session.Token == "" || generation != session.Generation || !time.Unix(expiry, 0).After(s.now()) || artifactID != offer.Spec.ArtifactID || chunkCount != offer.Spec.ChunkCount || maxBytes != offer.Spec.MaxCiphertextBytes || len(expectedHash) != hashSize || subtle.ConstantTimeCompare([]byte(token), []byte(session.Token)) != 1 || subtle.ConstantTimeCompare(expectedHash, plaintextHash[:]) != 1 {
		return ErrUnauthorized
	}
	var frames int
	if err := tx.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM attachment_chunks WHERE transfer_id = ? AND recipient = ? AND artifact_id = ?`, offer.TransferID, recipient, artifactID).Scan(&frames); err != nil || frames != chunkCount {
		return ErrUnauthorized
	}
	var existing []byte
	err = tx.QueryRowContext(context.Background(), `SELECT plaintext_hash FROM attachment_completions WHERE offer_id = ? AND recipient = ?`, offer.ID, recipient).Scan(&existing)
	if err == nil {
		if subtle.ConstantTimeCompare(existing, plaintextHash[:]) != 1 {
			return ErrUnauthorized
		}
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read fenced attachment completion: %w", err)
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO attachment_completions (offer_id, recipient, plaintext_hash) VALUES (?, ?, ?)`, offer.ID, recipient, plaintextHash[:]); err != nil {
		return fmt.Errorf("persist fenced attachment completion: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit fenced attachment completion: %w", err)
	}
	return nil
}

// HasCompletion reports whether the recipient has a durable completion record.
func (s *SQLiteOfferStore) HasCompletion(offerID, recipient string) bool {
	var found int
	err := s.db.QueryRowContext(context.Background(), `SELECT 1 FROM attachment_completions WHERE offer_id = ? AND recipient = ?`, offerID, recipient).Scan(&found)
	return err == nil && found == 1
}

// AppendSignal persists a bounded opaque signaling record in offer order.
func (s *SQLiteOfferStore) AppendSignal(offerID, sender string, payload []byte) error {
	if len(payload) == 0 || len(payload) > maxSignalPayload {
		return ErrUnauthorized
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("begin attachment signal: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var sequence uint64
	if err := tx.QueryRowContext(context.Background(), `SELECT COALESCE(MAX(sequence), 0) FROM attachment_signals WHERE offer_id = ?`, offerID).Scan(&sequence); err != nil {
		return fmt.Errorf("read attachment signal sequence: %w", err)
	}
	var count, bytes int
	if err := tx.QueryRowContext(context.Background(), `SELECT COUNT(*), COALESCE(SUM(length(payload)), 0) FROM attachment_signals WHERE offer_id = ?`, offerID).Scan(&count, &bytes); err != nil {
		return fmt.Errorf("read attachment signal budget: %w", err)
	}
	if count >= maxSignalEntries || bytes+len(payload) > maxSignalBytes {
		return ErrUnauthorized
	}
	var relayBytes int
	if err := tx.QueryRowContext(context.Background(), `SELECT COALESCE(SUM(length(payload)), 0) FROM attachment_signals`).Scan(&relayBytes); err != nil {
		return fmt.Errorf("read relay signaling budget: %w", err)
	}
	if relayBytes+len(payload) > maxRelaySignalBytes {
		return ErrUnauthorized
	}
	sequence++
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO attachment_signals (offer_id, sequence, sender, payload) VALUES (?, ?, ?, ?)`, offerID, sequence, sender, payload); err != nil {
		return fmt.Errorf("persist attachment signal: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit attachment signal: %w", err)
	}
	return nil
}

// ListSignals loads ordered opaque records for an offer.
func (s *SQLiteOfferStore) ListSignals(offerID string) ([]Signal, error) {
	rows, err := s.db.QueryContext(context.Background(), `SELECT sequence, sender, payload FROM attachment_signals WHERE offer_id = ? ORDER BY sequence`, offerID)
	if err != nil {
		return nil, fmt.Errorf("list attachment signals: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var signals []Signal
	for rows.Next() {
		var signal Signal
		if err := rows.Scan(&signal.Sequence, &signal.From, &signal.Payload); err != nil {
			return nil, fmt.Errorf("scan attachment signal: %w", err)
		}
		signal.Payload = append([]byte(nil), signal.Payload...)
		signals = append(signals, signal)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate attachment signals: %w", err)
	}
	return signals, nil
}

// Accept atomically rotates the recipient session token and fencing generation.
func (s *SQLiteOfferStore) Accept(offerID, recipient string) (Session, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return Session{}, fmt.Errorf("begin attachment accept: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var actualRecipient string
	var generation uint64
	if err := tx.QueryRowContext(context.Background(), `SELECT recipient, generation FROM attachment_offers WHERE id = ?`, offerID).Scan(&actualRecipient, &generation); err != nil || actualRecipient != recipient {
		return Session{}, ErrUnauthorized
	}
	token, err := randomOpaqueID()
	if err != nil {
		return Session{}, err
	}
	session := Session{Token: token, Generation: generation + 1, ExpiresAt: s.now().Add(s.leaseTTL)}
	result, err := tx.ExecContext(context.Background(), `UPDATE attachment_offers SET session_token = ?, generation = ?, session_expires_at = ? WHERE id = ? AND recipient = ? AND generation = ?`, session.Token, session.Generation, session.ExpiresAt.Unix(), offerID, recipient, generation)
	if err != nil {
		return Session{}, fmt.Errorf("persist attachment session: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return Session{}, ErrUnauthorized
	}
	if err := tx.Commit(); err != nil {
		return Session{}, fmt.Errorf("commit attachment accept: %w", err)
	}
	return session, nil
}

// Authorize verifies the current durable recipient session.
func (s *SQLiteOfferStore) Authorize(offerID, recipient, token string, generation uint64) bool {
	var actualRecipient, actualToken string
	var actualGeneration uint64
	var expiry int64
	err := s.db.QueryRowContext(context.Background(), `SELECT recipient, session_token, generation, session_expires_at FROM attachment_offers WHERE id = ?`, offerID).Scan(&actualRecipient, &actualToken, &actualGeneration, &expiry)
	return err == nil && actualRecipient == recipient && actualGeneration == generation && token != "" && time.Unix(expiry, 0).After(s.now()) && subtle.ConstantTimeCompare([]byte(token), []byte(actualToken)) == 1
}
