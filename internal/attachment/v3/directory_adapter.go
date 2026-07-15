package v3

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"errors"
	"time"

	attachmentv2 "github.com/rock3r/punaro/internal/attachment/v2"
)

// DirectoryAuthorityAdapter reuses only the already root-verified directory
// facts (devices, membership, head, revocation and issuer keys). V3 manifests,
// permits, operations and envelopes remain v3 records and are never decoded by
// the v2 attachment implementation.
type DirectoryAuthorityAdapter struct {
	provider *attachmentv2.FreshDirectoryAuthorityProvider
}

func NewDirectoryAuthorityAdapter(provider *attachmentv2.FreshDirectoryAuthorityProvider) (*DirectoryAuthorityAdapter, error) {
	if provider == nil {
		return nil, errors.New("missing v3 directory provider")
	}
	return &DirectoryAuthorityAdapter{provider: provider}, nil
}
func (a *DirectoryAuthorityAdapter) ResolveAttachmentAuthority(ctx context.Context, now time.Time) (AttachmentAuthority, error) {
	if a == nil || a.provider == nil {
		return nil, errors.New("missing v3 directory provider")
	}
	authority, err := a.provider.ResolveAttachmentAuthority(ctx, now)
	if err != nil {
		return nil, err
	}
	resolver, ok := authority.(*attachmentv2.DirectorySnapshotResolver)
	if !ok || resolver == nil {
		return nil, errors.New("invalid v3 directory authority")
	}
	return directoryAuthorityView{resolver: resolver}, nil
}

type directoryAuthorityView struct {
	resolver *attachmentv2.DirectorySnapshotResolver
}

func (v directoryAuthorityView) ValidateManifestAuthority(m Manifest, now time.Time) (ed25519.PublicKey, error) {
	return v.resolver.ValidateManifestAuthority(attachmentv2.Manifest{Audience: m.Audience, TransferID: m.TransferID, ConversationID: m.ConversationID, SenderDeviceID: m.SenderDeviceID, SenderGeneration: m.SenderGeneration, RecipientDeviceID: m.RecipientDeviceID, RecipientGeneration: m.RecipientGeneration, DirectoryHead: m.DirectoryHead, MembershipCommitment: m.MembershipCommitment, RevocationEpoch: m.RevocationEpoch, IssuedAt: m.IssuedAt, ExpiresAt: m.ExpiresAt, ContentSalt: m.ContentSalt, PlaintextCommitment: m.PlaintextCommitment, ChunkSize: m.ChunkSize, ChunkCount: m.ChunkCount, PlaintextSize: m.PlaintextSize, SignerKeyID: m.SignerKeyID}, now)
}
func (v directoryAuthorityView) ValidatePermitAuthority(p Permit, now time.Time) (ed25519.PublicKey, error) {
	return v.resolver.ValidatePermitAuthority(attachmentv2.Permit{Audience: p.Audience, Serial: p.Serial, IssuerKeyID: p.IssuerKeyID, HolderDeviceID: p.HolderDeviceID, HolderGeneration: p.HolderGeneration, HolderRole: p.HolderRole, TransferID: p.TransferID, ConversationID: p.ConversationID, SenderDeviceID: p.SenderDeviceID, SenderGeneration: p.SenderGeneration, RecipientDeviceID: p.RecipientDeviceID, RecipientGeneration: p.RecipientGeneration, AttemptGeneration: p.AttemptGeneration, Operation: attachmentv2.PermitOperationOffer, DirectoryHead: p.DirectoryHead, MembershipCommitment: p.MembershipCommitment, RevocationEpoch: p.RevocationEpoch, IssuedAt: p.IssuedAt, ExpiresAt: p.ExpiresAt, MaxBytes: p.MaxBytes, MaxChunks: p.MaxChunks, MaxOperations: p.MaxOperations}, now)
}
func (v directoryAuthorityView) CurrentDeviceSigningKey(id [16]byte, generation uint64) (ed25519.PublicKey, error) {
	return v.resolver.CurrentDeviceSigningKey(id, generation)
}
func (v directoryAuthorityView) CurrentRecipientHPKEKey(id [16]byte, generation uint64) ([32]byte, *ecdh.PublicKey, error) {
	return v.resolver.CurrentRecipientHPKEKey(id, generation)
}
func (v directoryAuthorityView) ResolveRecipientHPKEKey(id [16]byte, generation uint64, keyID [32]byte) (*ecdh.PublicKey, error) {
	return v.resolver.ResolveRecipientHPKEKey(id, generation, keyID)
}
