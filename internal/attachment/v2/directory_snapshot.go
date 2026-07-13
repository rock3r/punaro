package v2

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/zeebo/blake3"
)

const directoryLeafDomain = "punaro/attachment/directory-leaf/v2\x00"

// DirectoryDevice is one append-only device-generation record in the signed
// directory. A later record for the same generation may revoke it, but cannot
// change its key bindings.
type DirectoryDevice struct {
	DeviceID         [16]byte
	Generation       uint64
	SigningKeyID     [32]byte
	SigningPublicKey [32]byte
	HPKEKeyID        [32]byte
	HPKEPublicKey    [32]byte
	Revoked          bool
}

// DirectoryMembership binds one sender/recipient generation snapshot to a
// conversation and its manifest membership commitment.
type DirectoryMembership struct {
	ConversationID      [16]byte
	SenderDeviceID      [16]byte
	SenderGeneration    uint64
	RecipientDeviceID   [16]byte
	RecipientGeneration uint64
	Commitment          [32]byte
}

// DirectoryEntry is one ordered transparency-log leaf. Exactly one field must
// be non-nil; order is part of the signed tree commitment.
type DirectoryEntry struct {
	Device     *DirectoryDevice
	Membership *DirectoryMembership
}

// DirectoryEntryHashes returns the ordered leaf commitments for entries.
func DirectoryEntryHashes(entries []DirectoryEntry) ([][32]byte, error) {
	if len(entries) == 0 || len(entries) > maxDirectoryLeaves {
		return nil, errors.New("invalid directory entries")
	}
	hashes := make([][32]byte, 0, len(entries))
	for _, entry := range entries {
		payload, err := entry.canonicalBytes()
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, blake3.Sum256(append([]byte(directoryLeafDomain), payload...)))
	}
	return hashes, nil
}

func (entry DirectoryEntry) canonicalBytes() ([]byte, error) {
	if (entry.Device == nil) == (entry.Membership == nil) {
		return nil, errors.New("invalid directory entry kind")
	}
	if entry.Device != nil {
		value := entry.Device
		if isZero16(value.DeviceID) || value.Generation == 0 || isZero32(value.SigningKeyID) || isZero32(value.SigningPublicKey) || isZero32(value.HPKEKeyID) || isZero32(value.HPKEPublicKey) {
			return nil, errors.New("invalid directory device")
		}
		return canonicalEncoding.Marshal(map[uint64]any{1: uint64(1), 2: value.DeviceID, 3: value.Generation, 4: value.SigningKeyID, 5: value.SigningPublicKey, 6: value.HPKEKeyID, 7: value.HPKEPublicKey, 8: value.Revoked})
	}
	value := entry.Membership
	if isZero16(value.ConversationID) || isZero16(value.SenderDeviceID) || value.SenderGeneration == 0 || isZero16(value.RecipientDeviceID) || value.RecipientGeneration == 0 || isZero32(value.Commitment) {
		return nil, errors.New("invalid directory membership")
	}
	return canonicalEncoding.Marshal(map[uint64]any{1: uint64(2), 2: value.ConversationID, 3: value.SenderDeviceID, 4: value.SenderGeneration, 5: value.RecipientDeviceID, 6: value.RecipientGeneration, 7: value.Commitment})
}

// DirectorySnapshotResolver resolves manifest and envelope key authority only
// from a freshly verified root-signed snapshot.
type DirectorySnapshotResolver struct {
	head    DirectoryHead
	entries []DirectoryEntry
}

// NewDirectorySnapshotResolver verifies the exact supplied ordered directory
// entries against a signed head, then durably checkpoints that verified
// snapshot. A consistency proof, when required, must describe these same
// leaves.
func NewDirectorySnapshotResolver(rawHead []byte, trust DirectoryTrust, now time.Time, proof *FullConsistencyProof, entries []DirectoryEntry) (*DirectorySnapshotResolver, error) {
	head, err := verifyDirectoryHead(rawHead, trust, now)
	if err != nil {
		return nil, err
	}
	hashes, err := DirectoryEntryHashes(entries)
	if err != nil || uint64(len(hashes)) != head.TreeSize || directoryMerkleRoot(hashes) != head.TreeRoot {
		return nil, errors.New("directory snapshot does not match head")
	}
	if proof != nil && !sameHashes(proof.LeafHashes, hashes) {
		return nil, errors.New("directory snapshot differs from consistency proof")
	}
	if err := validateDirectoryEntryHistory(entries); err != nil {
		return nil, err
	}
	if _, err := advanceVerifiedDirectoryHead(rawHead, head, trust, proof); err != nil {
		return nil, err
	}
	return &DirectorySnapshotResolver{head: head, entries: append([]DirectoryEntry(nil), entries...)}, nil
}

// validateDirectoryEntryHistory makes a device generation immutable. Its only
// permitted subsequent state change is revocation, and membership snapshots
// are immutable too. This prevents a validly signed tree from accidentally
// reviving a device or rebinding its established identity.
func validateDirectoryEntryHistory(entries []DirectoryEntry) error {
	type deviceGeneration struct {
		id         [16]byte
		generation uint64
	}
	type membershipIdentity struct {
		conversation [16]byte
		sender       [16]byte
		senderGen    uint64
		recipient    [16]byte
		recipientGen uint64
	}
	devices := make(map[deviceGeneration]DirectoryDevice)
	memberships := make(map[membershipIdentity]struct{})
	for _, entry := range entries {
		if entry.Device != nil {
			current := *entry.Device
			key := deviceGeneration{id: current.DeviceID, generation: current.Generation}
			previous, seen := devices[key]
			if !seen {
				if current.Revoked {
					return errors.New("directory device cannot begin revoked")
				}
				devices[key] = current
				continue
			}
			if previous.DeviceID != current.DeviceID || previous.Generation != current.Generation || previous.SigningKeyID != current.SigningKeyID || previous.SigningPublicKey != current.SigningPublicKey || previous.HPKEKeyID != current.HPKEKeyID || previous.HPKEPublicKey != current.HPKEPublicKey || previous.Revoked || !current.Revoked {
				return errors.New("invalid directory device history")
			}
			devices[key] = current
			continue
		}
		current := *entry.Membership
		key := membershipIdentity{conversation: current.ConversationID, sender: current.SenderDeviceID, senderGen: current.SenderGeneration, recipient: current.RecipientDeviceID, recipientGen: current.RecipientGeneration}
		if _, exists := memberships[key]; exists {
			return errors.New("duplicate directory membership")
		}
		memberships[key] = struct{}{}
	}
	return nil
}

func sameHashes(left, right [][32]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// ValidateManifestAuthority implements DirectoryKeyResolver and checks every
// manifest device, key, membership, directory-head, and revocation binding.
func (r *DirectorySnapshotResolver) ValidateManifestAuthority(manifest Manifest, now time.Time) (ed25519.PublicKey, error) {
	if r == nil || !r.fresh(now) {
		return nil, errors.New("invalid manifest directory authority")
	}
	nowUnix := now.UTC().Unix()
	if nowUnix < 0 {
		return nil, errors.New("invalid manifest directory authority")
	}
	headCommitment, err := directoryHeadCommitment(r.head)
	if err != nil || manifest.Audience != r.head.Audience || manifest.RevocationEpoch != r.head.RevocationEpoch || manifest.DirectoryHead != headCommitment || manifest.IssuedAt > uint64(nowUnix) || manifest.ExpiresAt <= uint64(nowUnix) || manifest.ExpiresAt > r.head.ExpiresAt {
		return nil, errors.New("invalid manifest directory authority")
	}
	sender, found := r.device(manifest.SenderDeviceID, manifest.SenderGeneration)
	if !found || sender.Revoked || sender.SigningKeyID != manifest.SignerKeyID || !r.membership(manifest) {
		return nil, errors.New("invalid manifest directory authority")
	}
	return ed25519.PublicKey(append([]byte(nil), sender.SigningPublicKey[:]...)), nil
}

// CurrentRecipientHPKEKey resolves the current non-revoked recipient HPKE key.
func (r *DirectorySnapshotResolver) CurrentRecipientHPKEKey(deviceID [16]byte, generation uint64) ([32]byte, *ecdh.PublicKey, error) {
	device, found := r.device(deviceID, generation)
	if !found || device.Revoked {
		return [32]byte{}, nil, errors.New("unknown recipient directory key")
	}
	key, err := ecdh.X25519().NewPublicKey(device.HPKEPublicKey[:])
	if err != nil {
		return [32]byte{}, nil, errors.New("invalid recipient directory key")
	}
	return device.HPKEKeyID, key, nil
}

// ResolveRecipientHPKEKey resolves the exact non-revoked recipient HPKE key
// named by a received envelope.
func (r *DirectorySnapshotResolver) ResolveRecipientHPKEKey(deviceID [16]byte, generation uint64, keyID [32]byte) (*ecdh.PublicKey, error) {
	resolvedID, key, err := r.CurrentRecipientHPKEKey(deviceID, generation)
	if err != nil || resolvedID != keyID {
		return nil, errors.New("unknown recipient directory key")
	}
	return key, nil
}

func (r *DirectorySnapshotResolver) fresh(now time.Time) bool {
	unix := now.UTC().Unix()
	if unix < 0 {
		return false
	}
	nowUnix := uint64(unix)
	return r.head.IssuedAt <= nowUnix && r.head.ExpiresAt > nowUnix
}

func (r *DirectorySnapshotResolver) device(deviceID [16]byte, generation uint64) (DirectoryDevice, bool) {
	for index := len(r.entries) - 1; index >= 0; index-- {
		if record := r.entries[index].Device; record != nil && record.DeviceID == deviceID && record.Generation == generation {
			return *record, true
		}
	}
	return DirectoryDevice{}, false
}

func (r *DirectorySnapshotResolver) membership(manifest Manifest) bool {
	for index := len(r.entries) - 1; index >= 0; index-- {
		if record := r.entries[index].Membership; record != nil && record.ConversationID == manifest.ConversationID && record.SenderDeviceID == manifest.SenderDeviceID && record.SenderGeneration == manifest.SenderGeneration && record.RecipientDeviceID == manifest.RecipientDeviceID && record.RecipientGeneration == manifest.RecipientGeneration && record.Commitment == manifest.MembershipCommitment {
			return true
		}
	}
	return false
}

func directoryHeadCommitment(head DirectoryHead) ([32]byte, error) {
	raw, err := EncodeDirectoryHead(head)
	if err != nil {
		return [32]byte{}, err
	}
	return blake3.Sum256(raw), nil
}

var _ DirectoryKeyResolver = (*DirectorySnapshotResolver)(nil)
