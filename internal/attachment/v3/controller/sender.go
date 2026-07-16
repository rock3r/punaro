package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"time"

	attachmentv2 "github.com/rock3r/punaro/internal/attachment/v2"
	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
	"github.com/zeebo/blake3"
)

// SenderIdentity is the pinned local source device. It is configured by the
// privileged worker, never inferred from a relay request.
type SenderIdentity struct {
	DeviceID   [16]byte
	Generation uint64
}

func (s SenderIdentity) valid() bool { return s.DeviceID != [16]byte{} && s.Generation != 0 }

// SenderStageOptions configures local sender staging and file-key protection.
type SenderStageOptions struct {
	Journal         *Journal
	ArtifactStore   *attachmentv3.ArtifactStore
	BindingResolver TransferBindingResolver
	Sender          SenderIdentity
	SigningKey      ed25519.PrivateKey
	// FileKeyProtector is backed by an OS-bound, non-exportable host secret
	// (Keychain, TPM, or equivalent). It must AEAD-authenticate the supplied
	// associated data; plaintext file keys are never written to the journal.
	FileKeyProtector SenderFileKeyProtector
	Now              func() time.Time
	NewID            func() ([16]byte, error)
	ChunkSize        uint64
}

// SenderFileKeyProtector isolates wrapping-key ownership from the controller.
// Its implementation belongs to the machine credential provider, not a
// mailbox adapter nor the SQLite journal. The associated data is fixed by the
// controller to the transfer identity and manifest commitment.
type SenderFileKeyProtector interface {
	SealSenderFileKey(context.Context, [32]byte, []byte) ([]byte, error)
	OpenSenderFileKey(context.Context, []byte, []byte) ([32]byte, error)
}

// SenderStager creates the encrypted, restart-safe source half of a v3
// transfer. It persists only ciphertext, signed metadata and the local file
// key in the private controller journal; plaintext never enters journal state.
type SenderStager struct{ options SenderStageOptions }

// NewSenderStager constructs a sender stager with a sender-bound journal and
// host-protected file-key boundary.
func NewSenderStager(options SenderStageOptions) (*SenderStager, error) {
	if options.Journal == nil || options.Journal.db == nil || !options.Journal.sender.valid() || options.Journal.sender != options.Sender || options.ArtifactStore == nil || options.BindingResolver == nil || !options.Sender.valid() || len(options.SigningKey) != ed25519.PrivateKeySize || options.FileKeyProtector == nil || options.NewID == nil || options.ChunkSize == 0 || options.ChunkSize > 256<<10 {
		return nil, errors.New("invalid sender staging worker")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &SenderStager{options: options}, nil
}

// Stage fresh-verifies the exact configured mapping before creating a new
// transfer. stageID is caller-durable and mandatory: reusing it after any
// crash resumes the same sealed material and transfer identity, while a new
// stageID creates a new source. It reserves cryptographic tuples only after
// the complete signed manifest and wrapped file key are durable.
func (s *SenderStager) Stage(ctx context.Context, stageID [16]byte, relayConversationID string, plaintext []byte) (attachmentv3.Manifest, error) {
	if s == nil || stageID == [16]byte{} || len(plaintext) > 64<<20 {
		return attachmentv3.Manifest{}, errors.New("invalid sender staging request")
	}
	now := s.options.Now().UTC()
	// Reaping is entirely local: it must keep bounded staging capacity usable
	// even while the directory or relay is unavailable. Tombstones make a
	// reaped caller-visible stage ID permanently non-reusable.
	if _, err := s.options.Journal.ReapExpiredSenderStages(now, maxPendingSenderStages); err != nil {
		return attachmentv3.Manifest{}, fmt.Errorf("reap expired sender stages: %w", err)
	}
	if retired, err := s.options.Journal.senderStageTombstoned(stageID); err != nil || retired {
		return attachmentv3.Manifest{}, errors.New("sender stage ID is no longer reusable")
	}
	mapping, found, err := s.options.Journal.mapping(relayConversationID)
	if err != nil || !found || mapping.SenderDeviceID != s.options.Sender.DeviceID || mapping.SenderGeneration != s.options.Sender.Generation {
		return attachmentv3.Manifest{}, errors.New("sender staging mapping is unavailable")
	}
	binding, err := s.options.BindingResolver.ResolveTransferBinding(ctx, mapping.ConversationID, mapping.SenderDeviceID, mapping.SenderGeneration, mapping.RecipientDeviceID, mapping.RecipientGeneration, mapping.MembershipCommitment, now)
	if err != nil || !exactTransferBinding(mapping, binding, now) {
		return attachmentv3.Manifest{}, errors.New("fresh sender staging binding is unavailable")
	}
	public := s.options.SigningKey.Public().(ed25519.PublicKey)
	if binding.Sender.SigningKeyID == [32]byte{} || len(public) != ed25519.PublicKeySize || !bytes.Equal(public, binding.Sender.SigningPublicKey[:]) {
		return attachmentv3.Manifest{}, errors.New("fresh sender signing identity is unavailable")
	}
	intent, found, err := s.options.Journal.senderStageIntent(stageID)
	if err != nil {
		return attachmentv3.Manifest{}, err
	}
	if !found {
		transferID, err := s.options.NewID()
		if err != nil || transferID == [16]byte{} {
			return attachmentv3.Manifest{}, errors.New("generate sender transfer identity")
		}
		material, err := newSourceArtifactMaterial()
		if err != nil {
			return attachmentv3.Manifest{}, err
		}
		manifest := attachmentv3.Manifest{Audience: binding.Permit.Audience, TransferID: transferID, ConversationID: mapping.ConversationID, SenderDeviceID: mapping.SenderDeviceID, SenderGeneration: mapping.SenderGeneration, RecipientDeviceID: mapping.RecipientDeviceID, RecipientGeneration: mapping.RecipientGeneration, DirectoryHead: binding.Permit.DirectoryHead, MembershipCommitment: mapping.MembershipCommitment, RevocationEpoch: binding.Permit.RevocationEpoch, IssuedAt: uint64(now.Unix()), ExpiresAt: binding.Permit.ExpiresAt, ChunkSize: s.options.ChunkSize, SignerKeyID: binding.Sender.SigningKeyID} // #nosec G115 -- the surrounding v3 validation bounds this conversion and fails closed.
		prepared, commitment, err := attachmentv3.PrepareSourceManifest(plaintext, manifest, s.options.SigningKey, material)
		if err != nil {
			return attachmentv3.Manifest{}, err
		}
		rawManifest, err := attachmentv3.EncodeManifest(prepared)
		if err != nil {
			return attachmentv3.Manifest{}, err
		}
		wrappedKey, err := s.options.FileKeyProtector.SealSenderFileKey(ctx, material.FileKey, senderKeyAAD(prepared.TransferID, commitment))
		if err != nil || len(wrappedKey) == 0 || bytes.Equal(wrappedKey, material.FileKey[:]) {
			return attachmentv3.Manifest{}, errors.New("wrap sender file key")
		}
		intent, err = s.options.Journal.ensureSenderStageIntent(senderStageIntent{stageID: stageID, transferID: transferID, relayConversationID: mapping.RelayConversationID, manifest: rawManifest, manifestCommitment: commitment, wrappedFileKey: wrappedKey, createdAt: now.Unix()})
		if err != nil {
			return attachmentv3.Manifest{}, err
		}
	}
	if intent.relayConversationID != mapping.RelayConversationID {
		return attachmentv3.Manifest{}, errors.New("changed sender stage mapping")
	}
	manifest, err := attachmentv3.DecodeManifest(intent.manifest)
	if err != nil || manifest.TransferID != intent.transferID || blake3.Sum256(intent.manifest) != intent.manifestCommitment || !exactStagedManifest(manifest, mapping, binding, now) {
		return attachmentv3.Manifest{}, errors.New("invalid durable sender stage intent")
	}
	fileKey, err := s.options.FileKeyProtector.OpenSenderFileKey(ctx, intent.wrappedFileKey, senderKeyAAD(manifest.TransferID, intent.manifestCommitment))
	if err != nil || fileKey == [32]byte{} {
		return attachmentv3.Manifest{}, errors.New("open sender file key")
	}
	artifact, err := attachmentv3.EncryptPreparedSourceArtifact(plaintext, manifest, intent.manifestCommitment, fileKey, s.options.ArtifactStore)
	if err != nil {
		return attachmentv3.Manifest{}, err
	}
	if err := s.persistStaged(mapping, intent.manifest, artifact, intent.wrappedFileKey); err != nil {
		return attachmentv3.Manifest{}, err
	}
	return artifact.Manifest, nil
}

func exactStagedManifest(manifest attachmentv3.Manifest, mapping Mapping, binding attachmentv2.DirectoryTransferBinding, now time.Time) bool {
	return now.Unix() >= 0 && manifest.Audience == binding.Permit.Audience && manifest.ConversationID == mapping.ConversationID && manifest.SenderDeviceID == mapping.SenderDeviceID && manifest.SenderGeneration == mapping.SenderGeneration && manifest.RecipientDeviceID == mapping.RecipientDeviceID && manifest.RecipientGeneration == mapping.RecipientGeneration && manifest.DirectoryHead == binding.Permit.DirectoryHead && manifest.MembershipCommitment == mapping.MembershipCommitment && manifest.RevocationEpoch == binding.Permit.RevocationEpoch && manifest.SignerKeyID == binding.Sender.SigningKeyID && manifest.ExpiresAt > uint64(now.Unix()) && manifest.ExpiresAt <= binding.Permit.ExpiresAt // #nosec G115 -- the surrounding v3 validation bounds this conversion and fails closed.
}

func newSourceArtifactMaterial() (attachmentv3.SourceArtifactMaterial, error) {
	var material attachmentv3.SourceArtifactMaterial
	if _, err := rand.Read(material.FileKey[:]); err != nil {
		return attachmentv3.SourceArtifactMaterial{}, err
	}
	if _, err := rand.Read(material.ContentSalt[:]); err != nil {
		return attachmentv3.SourceArtifactMaterial{}, err
	}
	return material, nil
}

func senderKeyAAD(transferID [16]byte, commitment [32]byte) []byte {
	aad := make([]byte, 0, len("punaro/sender-file-key/v3\x00")+len(transferID)+len(commitment))
	aad = append(aad, "punaro/sender-file-key/v3\x00"...)
	aad = append(aad, transferID[:]...)
	return append(aad, commitment[:]...)
}

type senderStageIntent struct {
	stageID             [16]byte
	transferID          [16]byte
	relayConversationID string
	manifest            []byte
	manifestCommitment  [32]byte
	wrappedFileKey      []byte
	createdAt           int64
}

func (j *Journal) senderStageIntent(stageID [16]byte) (senderStageIntent, bool, error) {
	var intent senderStageIntent
	var stage, transfer, commitment []byte
	err := j.db.QueryRowContext(context.Background(), `SELECT stage_id,transfer_id,relay_conversation_id,manifest,manifest_commitment,wrapped_file_key,created_at FROM controller_sender_stage_intents WHERE stage_id=?`, stageID[:]).Scan(&stage, &transfer, &intent.relayConversationID, &intent.manifest, &commitment, &intent.wrappedFileKey, &intent.createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return intent, false, nil
	}
	if err != nil || len(stage) != 16 || !bytes.Equal(stage, stageID[:]) || len(transfer) != 16 || len(intent.manifest) == 0 || len(commitment) != 32 || len(intent.wrappedFileKey) == 0 || intent.createdAt < 0 {
		return intent, false, errors.New("invalid durable sender stage intent")
	}
	copy(intent.stageID[:], stage)
	copy(intent.transferID[:], transfer)
	copy(intent.manifestCommitment[:], commitment)
	return intent, true, nil
}

func (j *Journal) ensureSenderStageIntent(intent senderStageIntent) (senderStageIntent, error) {
	if j == nil || j.db == nil || intent.stageID == [16]byte{} || intent.transferID == [16]byte{} || !validRelayIdentifier(intent.relayConversationID) || len(intent.manifest) == 0 || intent.manifestCommitment == [32]byte{} || len(intent.wrappedFileKey) == 0 || intent.createdAt < 0 {
		return senderStageIntent{}, errors.New("invalid sender stage intent")
	}
	result, err := j.db.ExecContext(context.Background(), `INSERT INTO controller_sender_stage_intents(stage_id,transfer_id,relay_conversation_id,manifest,manifest_commitment,wrapped_file_key,created_at)
		SELECT ?,?,?,?,?,?,? WHERE (SELECT COUNT(*) FROM controller_sender_stage_intents) < ?
		ON CONFLICT(stage_id) DO NOTHING`, intent.stageID[:], intent.transferID[:], intent.relayConversationID, intent.manifest, intent.manifestCommitment[:], intent.wrappedFileKey, intent.createdAt, maxPendingSenderStages)
	if err != nil {
		return senderStageIntent{}, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return senderStageIntent{}, err
	}
	stored, found, err := j.senderStageIntent(intent.stageID)
	if err != nil || !found || (inserted == 1 && (stored.transferID != intent.transferID || stored.relayConversationID != intent.relayConversationID || !bytes.Equal(stored.manifest, intent.manifest) || stored.manifestCommitment != intent.manifestCommitment || !bytes.Equal(stored.wrappedFileKey, intent.wrappedFileKey))) {
		return senderStageIntent{}, errors.New("changed durable sender stage intent")
	}
	return stored, nil
}

// ReapExpiredSenderStages bounds abandoned locally staged ciphertext. It only
// removes stages whose signed manifest has expired; it never releases the
// ArtifactStore's cryptographic reservations, because those must remain
// permanently unique even after an abandoned transfer is forgotten.
func (j *Journal) ReapExpiredSenderStages(now time.Time, limit int) (int, error) {
	if j == nil || j.db == nil || now.UTC().Unix() < 0 || limit <= 0 || limit > maxPendingSenderStages {
		return 0, errors.New("invalid sender stage reaper")
	}
	tx, err := j.db.BeginTx(context.Background(), nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(context.Background(), `SELECT intent.stage_id,intent.transfer_id,intent.manifest FROM controller_sender_stage_intents AS intent WHERE NOT EXISTS (SELECT 1 FROM controller_sender_offer_holds AS held WHERE held.transfer_id=intent.transfer_id) ORDER BY intent.created_at,intent.stage_id`)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()
	type expiredStage struct{ stage, transfer []byte }
	expired := make([]expiredStage, 0, limit)
	for rows.Next() {
		var stage, transfer, raw []byte
		if err := rows.Scan(&stage, &transfer, &raw); err != nil {
			return 0, err
		}
		manifest, err := attachmentv3.DecodeManifest(raw)
		if err != nil || len(stage) != 16 || len(transfer) != 16 || manifest.TransferID == [16]byte{} {
			return 0, errors.New("invalid durable sender stage intent")
		}
		if manifest.ExpiresAt <= uint64(now.UTC().Unix()) && len(expired) < limit { // #nosec G115 -- the surrounding v3 validation bounds this conversion and fails closed.
			expired = append(expired, expiredStage{stage: stage, transfer: transfer})
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	var retained int
	if err := tx.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM controller_sender_stage_tombstones`).Scan(&retained); err != nil || retained+len(expired) > maxRetainedSenderStageTombstones {
		return 0, errors.New("sender stage identity retention exhausted")
	}
	for _, item := range expired {
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO controller_sender_stage_tombstones(stage_id,expired_at) VALUES (?,?)`, item.stage, now.UTC().Unix()); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(context.Background(), `DELETE FROM controller_sender_chunks WHERE transfer_id=?`, item.transfer); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(context.Background(), `DELETE FROM controller_sender_operations WHERE transfer_id=?`, item.transfer); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(context.Background(), `DELETE FROM controller_sender_transfers WHERE transfer_id=?`, item.transfer); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(context.Background(), `DELETE FROM controller_sender_stage_intents WHERE stage_id=?`, item.stage); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(expired), nil
}

func (j *Journal) senderStageTombstoned(stageID [16]byte) (bool, error) {
	if j == nil || j.db == nil || stageID == [16]byte{} {
		return false, errors.New("invalid sender stage identity")
	}
	var stored []byte
	err := j.db.QueryRowContext(context.Background(), `SELECT stage_id FROM controller_sender_stage_tombstones WHERE stage_id=?`, stageID[:]).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil || len(stored) != len(stageID) || !bytes.Equal(stored, stageID[:]) {
		return false, errors.New("invalid sender stage identity")
	}
	return true, nil
}

func (j *Journal) holdSenderOffer(transferID [16]byte) error {
	if j == nil || j.db == nil || transferID == [16]byte{} {
		return errors.New("invalid sender offer hold")
	}
	result, err := j.db.ExecContext(context.Background(), `INSERT INTO controller_sender_offer_holds(transfer_id) VALUES (?) ON CONFLICT(transfer_id) DO NOTHING`, transferID[:])
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil || changed > 1 {
		return errors.New("invalid sender offer hold")
	}
	return nil
}

func (j *Journal) releaseSenderOfferHold(transferID [16]byte) error {
	if j == nil || j.db == nil || transferID == [16]byte{} {
		return errors.New("invalid sender offer hold")
	}
	_, err := j.db.ExecContext(context.Background(), `DELETE FROM controller_sender_offer_holds WHERE transfer_id=?`, transferID[:])
	return err
}

func (s *SenderStager) persistStaged(mapping Mapping, raw []byte, artifact attachmentv3.SourceArtifact, wrappedKey []byte) error {
	tx, err := s.options.Journal.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(context.Background(), `INSERT INTO controller_sender_transfers(transfer_id, relay_conversation_id, manifest, manifest_commitment, wrapped_file_key) VALUES (?, ?, ?, ?, ?) ON CONFLICT(transfer_id) DO NOTHING`, artifact.Manifest.TransferID[:], mapping.RelayConversationID, raw, artifact.ManifestCommitment[:], wrappedKey)
	if err != nil {
		return errors.New("persist sender transfer intent")
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted == 0 {
		var relay string
		var stored, commitment, key []byte
		err := tx.QueryRowContext(context.Background(), `SELECT relay_conversation_id,manifest,manifest_commitment,wrapped_file_key FROM controller_sender_transfers WHERE transfer_id=?`, artifact.Manifest.TransferID[:]).Scan(&relay, &stored, &commitment, &key)
		if err != nil || relay != mapping.RelayConversationID || !bytes.Equal(stored, raw) || !bytes.Equal(commitment, artifact.ManifestCommitment[:]) || !bytes.Equal(key, wrappedKey) {
			return errors.New("changed durable sender transfer")
		}
		rows, err := tx.QueryContext(context.Background(), `SELECT chunk_index,ciphertext,ciphertext_commitment FROM controller_sender_chunks WHERE transfer_id=? ORDER BY chunk_index`, artifact.Manifest.TransferID[:])
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		index := 0
		for rows.Next() {
			var chunkIndex uint64
			var ciphertext, chunkCommitment []byte
			if err := rows.Scan(&chunkIndex, &ciphertext, &chunkCommitment); err != nil || index >= len(artifact.Chunks) || chunkIndex != artifact.Chunks[index].Index || !bytes.Equal(ciphertext, artifact.Chunks[index].Ciphertext) || !bytes.Equal(chunkCommitment, artifact.Chunks[index].CiphertextCommitment[:]) {
				return errors.New("changed durable sender ciphertext")
			}
			index++
		}
		if err := rows.Err(); err != nil || index != len(artifact.Chunks) {
			return errors.New("incomplete durable sender ciphertext")
		}
		return tx.Commit()
	}
	for _, chunk := range artifact.Chunks {
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO controller_sender_chunks(transfer_id, chunk_index, ciphertext, ciphertext_commitment) VALUES (?, ?, ?, ?)`, artifact.Manifest.TransferID[:], chunk.Index, chunk.Ciphertext, chunk.CiphertextCommitment[:]); err != nil {
			return errors.New("persist sender ciphertext")
		}
	}
	return tx.Commit()
}
