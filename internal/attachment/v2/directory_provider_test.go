package v2

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

type directorySnapshotFetcherStub struct {
	snapshot DirectorySnapshot
	err      error
	calls    int
}

func (s *directorySnapshotFetcherStub) FetchDirectorySnapshot(context.Context) (DirectorySnapshot, error) {
	s.calls++
	return s.snapshot, s.err
}

func TestFreshDirectoryAuthorityProviderFetchesAndVerifiesSnapshotPerRequest(t *testing.T) {
	t.Parallel()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	audience, rootID, issuerID := directoryBytes32(1), directoryBytes32(2), directoryBytes32(3)
	entries := []DirectoryEntry{{Issuer: &DirectoryPermitIssuer{KeyID: issuerID, PublicKey: [32]byte(issuerPublic)}}}
	leaves, err := DirectoryEntryHashes(entries)
	if err != nil {
		t.Fatal(err)
	}
	head := signedDirectoryHead(t, rootPrivate, DirectoryHead{Audience: audience, RootKeyID: rootID, TreeSize: 1, TreeRoot: directoryMerkleRoot(leaves), Sequence: 1, IssuedAt: testUnix(t, now.Add(-time.Second)), ExpiresAt: testUnix(t, now.Add(20*time.Second))})
	rawHead, err := EncodeDirectoryHead(head)
	if err != nil {
		t.Fatal(err)
	}
	fetcher := &directorySnapshotFetcherStub{snapshot: DirectorySnapshot{RawHead: rawHead, Entries: entries}}
	provider, err := NewFreshDirectoryAuthorityProvider(fetcher, DirectoryTrust{Audience: audience, RootKeyID: rootID, RootPublicKey: rootPublic, Checkpoints: &memoryCheckpointStore{checkpoints: make(map[[32]byte]DirectoryCheckpoint)}})
	if err != nil {
		t.Fatal(err)
	}
	authority, err := provider.ResolveAttachmentAuthority(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := authority.(*DirectorySnapshotResolver).CurrentPermitIssuerKey(issuerID)
	if err != nil || string(resolved) != string(issuerPublic) || fetcher.calls != 1 {
		t.Fatalf("issuer=%x calls=%d err=%v", resolved, fetcher.calls, err)
	}
	if _, err := provider.ResolveAttachmentAuthority(context.Background(), now); err != nil || fetcher.calls != 2 {
		t.Fatalf("second fetch calls=%d err=%v", fetcher.calls, err)
	}
	issuanceAuthority, err := provider.ResolvePermitIssuanceAuthority(context.Background(), now)
	if err != nil || fetcher.calls != 3 {
		t.Fatalf("issuance authority calls=%d err=%v", fetcher.calls, err)
	}
	if _, err := issuanceAuthority.CurrentPermitBinding(now); err != nil {
		t.Fatal(err)
	}
}

func TestFreshDirectoryAuthorityProviderFailsClosedWhenRefreshFails(t *testing.T) {
	t.Parallel()
	fetcher := &directorySnapshotFetcherStub{err: errors.New("unavailable")}
	provider, err := NewFreshDirectoryAuthorityProvider(fetcher, DirectoryTrust{Audience: directoryBytes32(1), RootKeyID: directoryBytes32(2), RootPublicKey: ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)), Checkpoints: &memoryCheckpointStore{checkpoints: make(map[[32]byte]DirectoryCheckpoint)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.ResolveAttachmentAuthority(context.Background(), time.Now()); err == nil || fetcher.calls != 1 {
		t.Fatalf("calls=%d err=%v", fetcher.calls, err)
	}
}
