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

// NewDirectoryAuthorityAdapter projects verified v2 directory facts into the
// v3 authority interfaces without accepting v2 attachment records.
func NewDirectoryAuthorityAdapter(provider *attachmentv2.FreshDirectoryAuthorityProvider) (*DirectoryAuthorityAdapter, error) {
	if provider == nil {
		return nil, errors.New("missing v3 directory provider")
	}
	return &DirectoryAuthorityAdapter{provider: provider}, nil
}

// ResolveAttachmentAuthority returns the current root-verified v3 attachment
// authority view.
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

// ResolvePermitIssuanceAuthority uses the same fresh root-verified snapshot
// as attachment redemption. It projects only directory facts into the v3
// issuance authority; no v2 permit or request bytes cross this boundary.
func (a *DirectoryAuthorityAdapter) ResolvePermitIssuanceAuthority(ctx context.Context, now time.Time) (PermitIssuanceAuthority, error) {
	if a == nil || a.provider == nil {
		return nil, errors.New("missing v3 directory provider")
	}
	authority, err := a.provider.ResolvePermitIssuanceAuthority(ctx, now)
	if err != nil {
		return nil, err
	}
	resolver, ok := authority.(*attachmentv2.DirectorySnapshotResolver)
	if !ok || resolver == nil {
		return nil, errors.New("invalid v3 directory authority")
	}
	return directoryAuthorityView{resolver: resolver}, nil
}

// ResolveTransferBinding fetches a new root-verified directory snapshot and
// returns only the exact locally selected relationship. It must never be used
// to discover a recipient or replace an existing local conversation mapping.
func (a *DirectoryAuthorityAdapter) ResolveTransferBinding(ctx context.Context, conversationID, senderID [16]byte, senderGeneration uint64, recipientID [16]byte, recipientGeneration uint64, membershipCommitment [32]byte, now time.Time) (attachmentv2.DirectoryTransferBinding, error) {
	if a == nil || a.provider == nil {
		return attachmentv2.DirectoryTransferBinding{}, errors.New("missing v3 directory provider")
	}
	authority, err := a.provider.ResolveAttachmentAuthority(ctx, now)
	if err != nil {
		return attachmentv2.DirectoryTransferBinding{}, errors.New("fresh v3 directory authority is unavailable")
	}
	resolver, ok := authority.(*attachmentv2.DirectorySnapshotResolver)
	if !ok || resolver == nil {
		return attachmentv2.DirectoryTransferBinding{}, errors.New("invalid v3 directory authority")
	}
	return resolver.ResolveTransferBinding(conversationID, senderID, senderGeneration, recipientID, recipientGeneration, membershipCommitment, now)
}

type directoryAuthorityView struct {
	resolver *attachmentv2.DirectorySnapshotResolver
}

func (v directoryAuthorityView) ValidateManifestAuthority(m Manifest, now time.Time) (ed25519.PublicKey, error) {
	return v.resolver.ValidateManifestAuthority(attachmentv2.Manifest{Audience: m.Audience, TransferID: m.TransferID, ConversationID: m.ConversationID, SenderDeviceID: m.SenderDeviceID, SenderGeneration: m.SenderGeneration, RecipientDeviceID: m.RecipientDeviceID, RecipientGeneration: m.RecipientGeneration, DirectoryHead: m.DirectoryHead, MembershipCommitment: m.MembershipCommitment, RevocationEpoch: m.RevocationEpoch, IssuedAt: m.IssuedAt, ExpiresAt: m.ExpiresAt, ContentSalt: m.ContentSalt, PlaintextCommitment: m.PlaintextCommitment, ChunkSize: m.ChunkSize, ChunkCount: m.ChunkCount, PlaintextSize: m.PlaintextSize, SignerKeyID: m.SignerKeyID}, now)
}
func (v directoryAuthorityView) ValidatePermitAuthority(p Permit, now time.Time) (ed25519.PublicKey, error) {
	return v.resolver.ValidatePermitDirectoryBinding(attachmentv2.PermitDirectoryBinding{Audience: p.Audience, IssuerKeyID: p.IssuerKeyID, HolderDeviceID: p.HolderDeviceID, HolderGeneration: p.HolderGeneration, HolderRole: p.HolderRole, ConversationID: p.ConversationID, SenderDeviceID: p.SenderDeviceID, SenderGeneration: p.SenderGeneration, RecipientDeviceID: p.RecipientDeviceID, RecipientGeneration: p.RecipientGeneration, DirectoryHead: p.DirectoryHead, MembershipCommitment: p.MembershipCommitment, RevocationEpoch: p.RevocationEpoch, ExpiresAt: p.ExpiresAt}, now)
}
func (v directoryAuthorityView) CurrentDeviceSigningKey(id [16]byte, generation uint64) (ed25519.PublicKey, error) {
	return v.resolver.CurrentDeviceSigningKey(id, generation)
}
func (v directoryAuthorityView) CurrentPermitIssuerKey(keyID [32]byte) (ed25519.PublicKey, error) {
	return v.resolver.CurrentPermitIssuerKey(keyID)
}
func (v directoryAuthorityView) CurrentPermitBinding(now time.Time) (DirectoryPermitBinding, error) {
	binding, err := v.resolver.CurrentPermitBinding(now)
	if err != nil {
		return DirectoryPermitBinding{}, err
	}
	return DirectoryPermitBinding{Audience: binding.Audience, DirectoryHead: binding.DirectoryHead, RevocationEpoch: binding.RevocationEpoch, ExpiresAt: binding.ExpiresAt}, nil
}
func (v directoryAuthorityView) CurrentRecipientHPKEKey(id [16]byte, generation uint64) ([32]byte, *ecdh.PublicKey, error) {
	return v.resolver.CurrentRecipientHPKEKey(id, generation)
}
func (v directoryAuthorityView) ResolveRecipientHPKEKey(id [16]byte, generation uint64, keyID [32]byte) (*ecdh.PublicKey, error) {
	return v.resolver.ResolveRecipientHPKEKey(id, generation, keyID)
}
