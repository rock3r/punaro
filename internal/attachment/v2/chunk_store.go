package v2

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"time"
)

// expectedCiphertextChunkLength derives the exact ChaCha20-Poly1305 ciphertext
// frame length for one manifest chunk without decrypting it.
func expectedCiphertextChunkLength(manifest Manifest, index uint64) (uint64, error) {
	if validateManifest(manifest) != nil || index >= manifest.ChunkCount {
		return 0, errors.New("invalid manifest chunk")
	}
	plainLength := manifest.ChunkSize
	if index == manifest.ChunkCount-1 {
		plainLength = manifest.PlaintextSize - manifest.ChunkSize*(manifest.ChunkCount-1)
	}
	return plainLength + 16, nil
}

type chunkResultWire struct {
	Version    uint64   `cbor:"1,keyasint"`
	TransferID [16]byte `cbor:"2,keyasint"`
	Index      uint64   `cbor:"3,keyasint"`
	Commitment [32]byte `cbor:"4,keyasint"`
}

// Upload verifies and immutably stores one exactly sized ciphertext chunk in
// the same transaction as the sender's signed upload redemption.
func (s *SQLiteTransferStore) Upload(ctx context.Context, permit Permit, operation OperationRecord, request OperationRequest, route AttachmentRoute, issuers PermitAuthorityResolver, holders OperationHolderResolver, directory DirectoryKeyResolver, now time.Time) (EncryptedChunk, bool, error) {
	if s == nil || s.ledger == nil || route.Operation != PermitOperationUpload || route.Action != 0 || route.TransferID != permit.TransferID || permit.Operation != PermitOperationUpload || permit.HolderRole != PermitHolderSender {
		return EncryptedChunk{}, false, errors.New("invalid attachment upload")
	}
	manifest, _, found, err := s.LoadOffer(permit.TransferID)
	if err != nil || !found {
		return EncryptedChunk{}, false, errors.New("unknown attachment offer")
	}
	if _, err := verifyManifestFromDirectoryAt(manifest, directory, now); err != nil || !offerPermitBinding(permit, manifest) {
		return EncryptedChunk{}, false, errors.New("invalid attachment upload authority")
	}
	expectedLength, err := expectedCiphertextChunkLength(manifest, route.ChunkIndex)
	if err != nil || uint64(len(request.body)) != expectedLength {
		return EncryptedChunk{}, false, errors.New("invalid attachment chunk length")
	}
	commitment := ciphertextCommitment(request.body)
	raw, replayed, err := s.ledger.Redeem(ctx, permit, operation, request, issuers, holders, now, func(ctx context.Context, tx *sql.Tx) ([]byte, error) {
		record, found, err := loadTransferTx(ctx, tx, permit.TransferID)
		if err != nil || !found || (record.Status != TransferOffered && record.Status != TransferAccepted && record.Status != TransferTransferring) {
			return nil, errors.New("transfer does not accept chunks")
		}
		var existingCiphertext, existingCommitment []byte
		err = tx.QueryRowContext(ctx, "SELECT ciphertext, ciphertext_commitment FROM attachment_chunks WHERE transfer_id = ? AND chunk_index = ?", permit.TransferID[:], uint64Bytes(route.ChunkIndex)).Scan(&existingCiphertext, &existingCommitment)
		switch {
		case err == nil:
			if !bytes.Equal(existingCiphertext, request.body) || !bytes.Equal(existingCommitment, commitment[:]) {
				return nil, errors.New("attachment chunk replacement is forbidden")
			}
		case errors.Is(err, sql.ErrNoRows):
			if _, err := tx.ExecContext(ctx, "INSERT INTO attachment_chunks(transfer_id, chunk_index, ciphertext, ciphertext_commitment) VALUES (?, ?, ?, ?)", permit.TransferID[:], uint64Bytes(route.ChunkIndex), request.body, commitment[:]); err != nil {
				return nil, err
			}
		default:
			return nil, err
		}
		return encodeChunkResult(permit.TransferID, route.ChunkIndex, commitment)
	})
	if err != nil {
		return EncryptedChunk{}, false, err
	}
	chunk, err := decodeChunkResult(raw)
	if err != nil {
		return EncryptedChunk{}, false, err
	}
	return chunk, replayed, nil
}

func encodeChunkResult(transferID [16]byte, index uint64, commitment [32]byte) ([]byte, error) {
	return canonicalEncoding.Marshal(chunkResultWire{Version: protocolVersion, TransferID: transferID, Index: index, Commitment: commitment})
}

func decodeChunkResult(raw []byte) (EncryptedChunk, error) {
	if len(raw) == 0 || len(raw) > maxOperationResultBytes {
		return EncryptedChunk{}, errors.New("invalid chunk result")
	}
	var wire chunkResultWire
	if err := strictDecoding.Unmarshal(raw, &wire); err != nil || wire.Version != protocolVersion || isZero16(wire.TransferID) || isZero32(wire.Commitment) {
		return EncryptedChunk{}, errors.New("invalid chunk result")
	}
	canonical, err := encodeChunkResult(wire.TransferID, wire.Index, wire.Commitment)
	if err != nil || !bytes.Equal(raw, canonical) {
		return EncryptedChunk{}, errors.New("invalid chunk result")
	}
	return EncryptedChunk{Index: wire.Index, CiphertextCommitment: wire.Commitment}, nil
}
