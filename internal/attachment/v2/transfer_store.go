package v2

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// SQLiteTransferStore persists non-secret transfer lifecycle state in the same
// SQLite database as the permit ledger. Its signed transition method makes the
// state mutation and durable idempotency result one transaction.
type SQLiteTransferStore struct{ ledger *SQLitePermitLedger }

// OpenSQLiteTransferStore initializes transfer state on an existing private
// permit ledger. The ledger owns the database lifecycle.
func OpenSQLiteTransferStore(ledger *SQLitePermitLedger) (*SQLiteTransferStore, error) {
	if ledger == nil || ledger.db == nil {
		return nil, errors.New("transfer store requires permit ledger")
	}
	if _, err := ledger.db.ExecContext(context.Background(), `CREATE TABLE IF NOT EXISTS attachment_transfers (
		transfer_id BLOB PRIMARY KEY, manifest_commitment BLOB NOT NULL, status BLOB NOT NULL,
		attempt_generation BLOB NOT NULL, expires_at BLOB NOT NULL
	)`); err != nil {
		return nil, err
	}
	if _, err := ledger.db.ExecContext(context.Background(), `CREATE TABLE IF NOT EXISTS attachment_offers (
		transfer_id BLOB PRIMARY KEY, manifest BLOB NOT NULL, envelope BLOB NOT NULL
	)`); err != nil {
		return nil, err
	}
	if _, err := ledger.db.ExecContext(context.Background(), `CREATE TABLE IF NOT EXISTS attachment_chunks (
		transfer_id BLOB NOT NULL, chunk_index BLOB NOT NULL, ciphertext BLOB NOT NULL,
		ciphertext_commitment BLOB NOT NULL, PRIMARY KEY(transfer_id, chunk_index)
	)`); err != nil {
		return nil, err
	}
	return &SQLiteTransferStore{ledger: ledger}, nil
}

// CreateSourceReady durably records a source artifact that has already been
// verified and persisted by the source-ready artifact store. Exact retries are
// allowed; replacement of any immutable binding is forbidden.
func (s *SQLiteTransferStore) CreateSourceReady(ctx context.Context, record TransferRecord) error {
	if s == nil || s.ledger == nil || record.Status != TransferSourceReady || validateTransferRecord(record) != nil {
		return errors.New("invalid source-ready transfer")
	}
	tx, err := s.ledger.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	existing, found, err := loadTransferTx(ctx, tx, record.TransferID)
	if err != nil {
		return err
	}
	if found {
		if existing != record {
			return errors.New("transfer replacement is forbidden")
		}
		return nil
	}
	if err := insertTransferTx(ctx, tx, record); err != nil {
		return err
	}
	return tx.Commit()
}

// Load returns one exact transfer record.
func (s *SQLiteTransferStore) Load(transferID [16]byte) (TransferRecord, bool, error) {
	if s == nil || s.ledger == nil || isZero16(transferID) {
		return TransferRecord{}, false, errors.New("invalid transfer lookup")
	}
	return loadTransferDB(context.Background(), s.ledger.db, transferID)
}

// LoadOffer returns the exact immutable manifest and recipient envelope for a
// transfer. It does not authenticate them; each operation must still perform
// fresh directory verification before relying on the returned records.
func (s *SQLiteTransferStore) LoadOffer(transferID [16]byte) (Manifest, Envelope, bool, error) {
	if s == nil || s.ledger == nil || isZero16(transferID) {
		return Manifest{}, Envelope{}, false, errors.New("invalid offer lookup")
	}
	var manifestRaw, envelopeRaw []byte
	err := s.ledger.db.QueryRowContext(context.Background(), "SELECT manifest, envelope FROM attachment_offers WHERE transfer_id = ?", transferID[:]).Scan(&manifestRaw, &envelopeRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return Manifest{}, Envelope{}, false, nil
	}
	if err != nil {
		return Manifest{}, Envelope{}, false, err
	}
	manifest, err := DecodeManifest(manifestRaw)
	if err != nil {
		return Manifest{}, Envelope{}, false, errors.New("invalid stored offer")
	}
	envelope, err := DecodeEnvelope(envelopeRaw)
	if err != nil {
		return Manifest{}, Envelope{}, false, errors.New("invalid stored offer")
	}
	return manifest, envelope, true, nil
}

// LoadChunk returns one immutable ciphertext chunk. Callers must authorize the
// download before using it and construct the response-bound operation request
// from this exact byte slice.
func (s *SQLiteTransferStore) LoadChunk(transferID [16]byte, index uint64) (EncryptedChunk, bool, error) {
	if s == nil || s.ledger == nil || isZero16(transferID) {
		return EncryptedChunk{}, false, errors.New("invalid chunk lookup")
	}
	var ciphertext, commitment []byte
	err := s.ledger.db.QueryRowContext(context.Background(), "SELECT ciphertext, ciphertext_commitment FROM attachment_chunks WHERE transfer_id = ? AND chunk_index = ?", transferID[:], uint64Bytes(index)).Scan(&ciphertext, &commitment)
	if errors.Is(err, sql.ErrNoRows) {
		return EncryptedChunk{}, false, nil
	}
	if err != nil || len(commitment) != 32 || len(ciphertext) == 0 || ciphertextCommitment(ciphertext) != [32]byte(commitment) {
		return EncryptedChunk{}, false, errors.New("invalid stored attachment chunk")
	}
	var hash [32]byte
	copy(hash[:], commitment)
	return EncryptedChunk{Index: index, Ciphertext: append([]byte(nil), ciphertext...), CiphertextCommitment: hash}, true, nil
}

// RedeemTransition atomically verifies and redeems an exact permit operation,
// then records the route's corresponding lifecycle transition. Route transfer,
// operation, and attempt bindings are checked against the permit before any
// directory, signature, or database work. An identical retry returns its
// original transfer result without another transition.
func (s *SQLiteTransferStore) RedeemTransition(ctx context.Context, permit Permit, operation OperationRecord, request OperationRequest, route AttachmentRoute, issuers PermitAuthorityResolver, holders OperationHolderResolver, now time.Time) (TransferRecord, bool, error) {
	if s == nil || s.ledger == nil || route.Action == 0 || permit.TransferID != route.TransferID || permit.Operation != route.Operation || permit.Operation != permitOperationForAction(route.Action) || (route.AttemptGeneration != 0 && permit.AttemptGeneration != route.AttemptGeneration) {
		return TransferRecord{}, false, errors.New("invalid permit transition")
	}
	raw, replayed, err := s.ledger.Redeem(ctx, permit, operation, request, issuers, holders, now, func(ctx context.Context, tx *sql.Tx) ([]byte, error) {
		record, found, err := loadTransferTx(ctx, tx, permit.TransferID)
		if err != nil || !found {
			return nil, errors.New("unknown transfer")
		}
		next, err := record.Transition(route.Action, now)
		if err != nil {
			return nil, err
		}
		if err := updateTransferTx(ctx, tx, record, next); err != nil {
			return nil, err
		}
		return encodeTransferResult(next)
	})
	if err != nil {
		return TransferRecord{}, false, err
	}
	record, err := decodeTransferResult(raw)
	if err != nil {
		return TransferRecord{}, false, err
	}
	return record, replayed, nil
}

func permitOperationForAction(action TransferAction) uint64 {
	switch action {
	case TransferActionOffer:
		return PermitOperationOffer
	case TransferActionAccept:
		return PermitOperationAccept
	case TransferActionBegin:
		return PermitOperationSignal
	case TransferActionComplete:
		return PermitOperationComplete
	default:
		return 0
	}
}

type transferResultWire struct {
	Version            uint64   `cbor:"1,keyasint"`
	TransferID         [16]byte `cbor:"2,keyasint"`
	ManifestCommitment [32]byte `cbor:"3,keyasint"`
	Status             uint64   `cbor:"4,keyasint"`
	AttemptGeneration  uint64   `cbor:"5,keyasint"`
	ExpiresAt          uint64   `cbor:"6,keyasint"`
}

func encodeTransferResult(record TransferRecord) ([]byte, error) {
	if validateTransferRecord(record) != nil {
		return nil, errors.New("invalid transfer result")
	}
	return canonicalEncoding.Marshal(transferResultWire{Version: protocolVersion, TransferID: record.TransferID, ManifestCommitment: record.ManifestCommitment, Status: uint64(record.Status), AttemptGeneration: record.AttemptGeneration, ExpiresAt: record.ExpiresAt})
}

func decodeTransferResult(raw []byte) (TransferRecord, error) {
	if len(raw) == 0 || len(raw) > maxOperationResultBytes {
		return TransferRecord{}, errors.New("invalid transfer result")
	}
	var wire transferResultWire
	if err := strictDecoding.Unmarshal(raw, &wire); err != nil || wire.Version != protocolVersion {
		return TransferRecord{}, errors.New("invalid transfer result")
	}
	record := TransferRecord{TransferID: wire.TransferID, ManifestCommitment: wire.ManifestCommitment, Status: TransferStatus(wire.Status), AttemptGeneration: wire.AttemptGeneration, ExpiresAt: wire.ExpiresAt}
	canonical, err := encodeTransferResult(record)
	if err != nil || string(raw) != string(canonical) {
		return TransferRecord{}, errors.New("invalid transfer result")
	}
	return record, nil
}

func loadTransferDB(ctx context.Context, db *sql.DB, transferID [16]byte) (TransferRecord, bool, error) {
	var manifest, status, attempt, expires []byte
	err := db.QueryRowContext(ctx, "SELECT manifest_commitment, status, attempt_generation, expires_at FROM attachment_transfers WHERE transfer_id = ?", transferID[:]).Scan(&manifest, &status, &attempt, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return TransferRecord{}, false, nil
	}
	if err != nil {
		return TransferRecord{}, false, err
	}
	return decodeTransferRecord(transferID, manifest, status, attempt, expires)
}

func loadTransferTx(ctx context.Context, tx *sql.Tx, transferID [16]byte) (TransferRecord, bool, error) {
	var manifest, status, attempt, expires []byte
	err := tx.QueryRowContext(ctx, "SELECT manifest_commitment, status, attempt_generation, expires_at FROM attachment_transfers WHERE transfer_id = ?", transferID[:]).Scan(&manifest, &status, &attempt, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return TransferRecord{}, false, nil
	}
	if err != nil {
		return TransferRecord{}, false, err
	}
	return decodeTransferRecord(transferID, manifest, status, attempt, expires)
}

func decodeTransferRecord(transferID [16]byte, manifest, status, attempt, expires []byte) (TransferRecord, bool, error) {
	if len(manifest) != 32 || len(status) != 8 || len(attempt) != 8 || len(expires) != 8 {
		return TransferRecord{}, false, errors.New("invalid stored transfer")
	}
	record := TransferRecord{TransferID: transferID, Status: TransferStatus(uint64FromBytes(status)), AttemptGeneration: uint64FromBytes(attempt), ExpiresAt: uint64FromBytes(expires)}
	copy(record.ManifestCommitment[:], manifest)
	if validateTransferRecord(record) != nil {
		return TransferRecord{}, false, errors.New("invalid stored transfer")
	}
	return record, true, nil
}

func insertTransferTx(ctx context.Context, tx *sql.Tx, record TransferRecord) error {
	_, err := tx.ExecContext(ctx, "INSERT INTO attachment_transfers(transfer_id, manifest_commitment, status, attempt_generation, expires_at) VALUES (?, ?, ?, ?, ?)", record.TransferID[:], record.ManifestCommitment[:], uint64Bytes(uint64(record.Status)), uint64Bytes(record.AttemptGeneration), uint64Bytes(record.ExpiresAt))
	return err
}

func updateTransferTx(ctx context.Context, tx *sql.Tx, previous, next TransferRecord) error {
	result, err := tx.ExecContext(ctx, "UPDATE attachment_transfers SET status = ?, attempt_generation = ? WHERE transfer_id = ? AND manifest_commitment = ? AND expires_at = ? AND status = ? AND attempt_generation = ?", uint64Bytes(uint64(next.Status)), uint64Bytes(next.AttemptGeneration), previous.TransferID[:], previous.ManifestCommitment[:], uint64Bytes(previous.ExpiresAt), uint64Bytes(uint64(previous.Status)), uint64Bytes(previous.AttemptGeneration))
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil || updated != 1 {
		return errors.New("transfer update fencing failed")
	}
	return nil
}
