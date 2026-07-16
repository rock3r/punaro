package controller

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
)

// SenderIdentity is the pinned local source device. It is configured by the
// privileged worker, never inferred from a relay request.
type SenderIdentity struct {
	DeviceID   [16]byte
	Generation uint64
}

func (s SenderIdentity) valid() bool { return s.DeviceID != [16]byte{} && s.Generation != 0 }

type SenderStageOptions struct {
	Journal         *Journal
	ArtifactStore   *attachmentv3.ArtifactStore
	BindingResolver TransferBindingResolver
	Sender          SenderIdentity
	SigningKey      ed25519.PrivateKey
	Now             func() time.Time
	NewID           func() ([16]byte, error)
	ChunkSize       uint64
}

// SenderStager creates the encrypted, restart-safe source half of a v3
// transfer. It persists only ciphertext, signed metadata and the local file
// key in the private controller journal; plaintext never enters journal state.
type SenderStager struct{ options SenderStageOptions }

func NewSenderStager(options SenderStageOptions) (*SenderStager, error) {
	if options.Journal == nil || options.Journal.db == nil || options.ArtifactStore == nil || options.BindingResolver == nil || !options.Sender.valid() || len(options.SigningKey) != ed25519.PrivateKeySize || options.NewID == nil || options.ChunkSize == 0 || options.ChunkSize > 256<<10 {
		return nil, errors.New("invalid sender staging worker")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &SenderStager{options: options}, nil
}

// Stage fresh-verifies the exact configured mapping before creating a new
// transfer. It reserves cryptographic tuples in ArtifactStore before any
// encryption and writes the complete encrypted artifact to the controller
// journal before a caller can issue a relay operation.
func (s *SenderStager) Stage(ctx context.Context, relayConversationID string, plaintext []byte) (attachmentv3.Manifest, error) {
	if s == nil || len(plaintext) > 64<<20 {
		return attachmentv3.Manifest{}, errors.New("invalid sender staging request")
	}
	now := s.options.Now().UTC()
	mapping, found, err := s.options.Journal.mapping(relayConversationID)
	if err != nil || !found || mapping.SenderDeviceID != s.options.Sender.DeviceID || mapping.SenderGeneration != s.options.Sender.Generation {
		return attachmentv3.Manifest{}, errors.New("sender staging mapping is unavailable")
	}
	binding, err := s.options.BindingResolver.ResolveTransferBinding(ctx, mapping.ConversationID, mapping.SenderDeviceID, mapping.SenderGeneration, mapping.RecipientDeviceID, mapping.RecipientGeneration, mapping.MembershipCommitment, now)
	if err != nil || !exactTransferBinding(mapping, binding, now) {
		return attachmentv3.Manifest{}, errors.New("fresh sender staging binding is unavailable")
	}
	transferID, err := s.options.NewID()
	if err != nil || transferID == [16]byte{} {
		return attachmentv3.Manifest{}, errors.New("generate sender transfer identity")
	}
	manifest := attachmentv3.Manifest{Audience: binding.Permit.Audience, TransferID: transferID, ConversationID: mapping.ConversationID, SenderDeviceID: mapping.SenderDeviceID, SenderGeneration: mapping.SenderGeneration, RecipientDeviceID: mapping.RecipientDeviceID, RecipientGeneration: mapping.RecipientGeneration, DirectoryHead: binding.Permit.DirectoryHead, MembershipCommitment: mapping.MembershipCommitment, RevocationEpoch: binding.Permit.RevocationEpoch, IssuedAt: uint64(now.Unix()), ExpiresAt: binding.Permit.ExpiresAt, ChunkSize: s.options.ChunkSize, SignerKeyID: binding.Sender.SigningKeyID}
	artifact, fileKey, err := attachmentv3.PrepareSourceArtifact(plaintext, manifest, s.options.SigningKey, s.options.ArtifactStore)
	if err != nil {
		return attachmentv3.Manifest{}, err
	}
	rawManifest, err := attachmentv3.EncodeManifest(artifact.Manifest)
	if err != nil {
		return attachmentv3.Manifest{}, err
	}
	if err := s.persistStaged(mapping, rawManifest, artifact, fileKey); err != nil {
		return attachmentv3.Manifest{}, err
	}
	return artifact.Manifest, nil
}

func (s *SenderStager) persistStaged(mapping Mapping, raw []byte, artifact attachmentv3.SourceArtifact, fileKey [32]byte) error {
	tx, err := s.options.Journal.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO controller_sender_transfers(transfer_id, relay_conversation_id, manifest, manifest_commitment, file_key) VALUES (?, ?, ?, ?, ?)`, artifact.Manifest.TransferID[:], mapping.RelayConversationID, raw, artifact.ManifestCommitment[:], fileKey[:]); err != nil {
		return errors.New("persist sender transfer intent")
	}
	for _, chunk := range artifact.Chunks {
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO controller_sender_chunks(transfer_id, chunk_index, ciphertext, ciphertext_commitment) VALUES (?, ?, ?, ?)`, artifact.Manifest.TransferID[:], chunk.Index, chunk.Ciphertext, chunk.CiphertextCommitment[:]); err != nil {
			return errors.New("persist sender ciphertext")
		}
	}
	return tx.Commit()
}
