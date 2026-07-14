package v2

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"
)

// DirectorySnapshot is the complete signed directory view needed to verify a
// short-lived attachment operation. Its entries and proof are untrusted until
// NewDirectorySnapshotResolver verifies them against the pinned root trust.
type DirectorySnapshot struct {
	RawHead []byte
	Proof   *FullConsistencyProof
	Entries []DirectoryEntry
}

// DirectorySnapshotFetcher retrieves the current complete directory view.
// It must not return a cached view after its signed head expires.
type DirectorySnapshotFetcher interface {
	FetchDirectorySnapshot(context.Context) (DirectorySnapshot, error)
}

// FreshDirectoryAuthorityProvider fetches and verifies a complete snapshot
// for every attachment request. It shares a durable checkpoint store through
// DirectoryTrust, so refreshes detect rollback and freeze equivocation across
// process restarts.
type FreshDirectoryAuthorityProvider struct {
	fetcher DirectorySnapshotFetcher
	trust   DirectoryTrust
}

// NewFreshDirectoryAuthorityProvider creates a fail-closed authority provider
// from an explicitly root-pinned directory trust configuration.
func NewFreshDirectoryAuthorityProvider(fetcher DirectorySnapshotFetcher, trust DirectoryTrust) (*FreshDirectoryAuthorityProvider, error) {
	if fetcher == nil || isZero32(trust.Audience) || isZero32(trust.RootKeyID) || len(trust.RootPublicKey) != ed25519.PublicKeySize || trust.Checkpoints == nil {
		return nil, errors.New("fresh directory provider requires fetcher and pinned trust")
	}
	trust.RootPublicKey = append(ed25519.PublicKey(nil), trust.RootPublicKey...)
	return &FreshDirectoryAuthorityProvider{fetcher: fetcher, trust: trust}, nil
}

// ResolveAttachmentAuthority always fetches then verifies the current signed
// snapshot; it deliberately does not serve a stale last-known-good resolver.
func (p *FreshDirectoryAuthorityProvider) ResolveAttachmentAuthority(ctx context.Context, now time.Time) (AttachmentAuthority, error) {
	if p == nil || p.fetcher == nil {
		return nil, errors.New("directory authority provider is unavailable")
	}
	snapshot, err := p.fetcher.FetchDirectorySnapshot(ctx)
	if err != nil {
		return nil, errors.New("fresh directory snapshot is unavailable")
	}
	resolver, err := NewDirectorySnapshotResolver(snapshot.RawHead, p.trust, now, snapshot.Proof, snapshot.Entries)
	if err != nil {
		return nil, errors.New("fresh directory snapshot is invalid")
	}
	return resolver, nil
}
