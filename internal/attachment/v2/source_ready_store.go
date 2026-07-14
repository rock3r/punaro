package v2

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// SQLiteSourceReadyStore persists a complete immutable source artifact before
// it may be offered or accepted.
type SQLiteSourceReadyStore struct{ db *sql.DB }

// OpenSQLiteSourceReadyStore opens a private source-ready artifact store.
func OpenSQLiteSourceReadyStore(path string) (*SQLiteSourceReadyStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("source-ready store path is required")
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("source-ready parent must be private and non-symlinked")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	for _, statement := range []string{
		"PRAGMA journal_mode = WAL", "PRAGMA busy_timeout = 5000",
		`CREATE TABLE IF NOT EXISTS source_ready (manifest_commitment BLOB PRIMARY KEY, manifest BLOB NOT NULL, envelope BLOB NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS source_ready_chunks (manifest_commitment BLOB NOT NULL, chunk_index BLOB NOT NULL, ciphertext BLOB NOT NULL, ciphertext_commitment BLOB NOT NULL, PRIMARY KEY(manifest_commitment, chunk_index))`,
	} {
		if _, err := db.ExecContext(context.Background(), statement); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &SQLiteSourceReadyStore{db: db}, nil
}

// Close closes the source-ready store.
func (s *SQLiteSourceReadyStore) Close() error { return s.db.Close() }

// CommitSourceReady verifies a fresh manifest/envelope binding and atomically
// persists all immutable chunks. An exact retry succeeds without replacement.
func (s *SQLiteSourceReadyStore) CommitSourceReady(artifact SourceArtifact, envelope Envelope, directory DirectoryKeyResolver) error {
	if s == nil || directory == nil || len(artifact.Chunks) == 0 || uint64(len(artifact.Chunks)) != artifact.Manifest.ChunkCount {
		return errors.New("invalid source-ready artifact")
	}
	verified, err := verifyManifestFromDirectory(artifact.Manifest, directory)
	if err != nil || verified.commitment != artifact.ManifestCommitment || !verifyEnvelope(envelope, verified) {
		return errors.New("invalid source-ready authority")
	}
	manifestRaw, err := EncodeManifest(artifact.Manifest)
	if err != nil {
		return err
	}
	envelopeRaw, err := EncodeEnvelope(envelope)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var existingManifest, existingEnvelope []byte
	err = tx.QueryRowContext(context.Background(), "SELECT manifest, envelope FROM source_ready WHERE manifest_commitment = ?", artifact.ManifestCommitment[:]).Scan(&existingManifest, &existingEnvelope)
	if err == nil {
		if !bytes.Equal(existingManifest, manifestRaw) || !bytes.Equal(existingEnvelope, envelopeRaw) {
			return errors.New("source-ready artifact replacement is forbidden")
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if _, err := tx.ExecContext(context.Background(), "INSERT INTO source_ready(manifest_commitment, manifest, envelope) VALUES (?, ?, ?)", artifact.ManifestCommitment[:], manifestRaw, envelopeRaw); err != nil {
		return err
	}
	for index := uint64(0); index < artifact.Manifest.ChunkCount; index++ {
		chunk := artifact.Chunks[index]
		if chunk.Index != index || ciphertextCommitment(chunk.Ciphertext) != chunk.CiphertextCommitment {
			return errors.New("invalid source-ready chunk")
		}
		if _, err := tx.ExecContext(context.Background(), "INSERT INTO source_ready_chunks(manifest_commitment, chunk_index, ciphertext, ciphertext_commitment) VALUES (?, ?, ?, ?)", artifact.ManifestCommitment[:], uint64Bytes(chunk.Index), chunk.Ciphertext, chunk.CiphertextCommitment[:]); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LoadSourceReady reads one immutable complete artifact for a later offer.
func (s *SQLiteSourceReadyStore) LoadSourceReady(commitment [32]byte) (SourceArtifact, Envelope, bool, error) {
	if s == nil || isZero32(commitment) {
		return SourceArtifact{}, Envelope{}, false, errors.New("invalid source-ready commitment")
	}
	var manifestRaw, envelopeRaw []byte
	err := s.db.QueryRowContext(context.Background(), "SELECT manifest, envelope FROM source_ready WHERE manifest_commitment = ?", commitment[:]).Scan(&manifestRaw, &envelopeRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return SourceArtifact{}, Envelope{}, false, nil
	}
	if err != nil {
		return SourceArtifact{}, Envelope{}, false, err
	}
	manifest, err := DecodeManifest(manifestRaw)
	if err != nil {
		return SourceArtifact{}, Envelope{}, false, err
	}
	envelope, err := DecodeEnvelope(envelopeRaw)
	if err != nil {
		return SourceArtifact{}, Envelope{}, false, err
	}
	rows, err := s.db.QueryContext(context.Background(), "SELECT chunk_index, ciphertext, ciphertext_commitment FROM source_ready_chunks WHERE manifest_commitment = ? ORDER BY chunk_index", commitment[:])
	if err != nil {
		return SourceArtifact{}, Envelope{}, false, err
	}
	defer func() { _ = rows.Close() }()
	artifact := SourceArtifact{Manifest: manifest, ManifestCommitment: commitment}
	for rows.Next() {
		var indexRaw, ciphertext, hashRaw []byte
		if err := rows.Scan(&indexRaw, &ciphertext, &hashRaw); err != nil {
			return SourceArtifact{}, Envelope{}, false, err
		}
		if len(hashRaw) != 32 {
			return SourceArtifact{}, Envelope{}, false, errors.New("invalid stored source chunk")
		}
		var hash [32]byte
		copy(hash[:], hashRaw)
		artifact.Chunks = append(artifact.Chunks, EncryptedChunk{Index: uint64FromBytes(indexRaw), Ciphertext: ciphertext, CiphertextCommitment: hash})
	}
	if err := rows.Err(); err != nil {
		return SourceArtifact{}, Envelope{}, false, err
	}
	if uint64(len(artifact.Chunks)) != manifest.ChunkCount {
		return SourceArtifact{}, Envelope{}, false, errors.New("incomplete source-ready artifact")
	}
	return artifact, envelope, true, nil
}
