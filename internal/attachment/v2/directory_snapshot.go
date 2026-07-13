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
	Revoked             bool
}

// DirectoryPermitIssuer is a root-authorized relay signing key for attachment
// permits. It is distinct from all device signing keys.
type DirectoryPermitIssuer struct {
	KeyID     [32]byte
	PublicKey [32]byte
	Revoked   bool
}

// DirectoryEntry is one ordered transparency-log leaf. Exactly one field must
// be non-nil; order is part of the signed tree commitment.
type DirectoryEntry struct {
	Device     *DirectoryDevice
	Membership *DirectoryMembership
	Issuer     *DirectoryPermitIssuer
}

type directoryDeviceKey struct {
	id         [16]byte
	generation uint64
}

type directoryMembershipKey struct {
	conversation [16]byte
	sender       [16]byte
	senderGen    uint64
	recipient    [16]byte
	recipientGen uint64
	commitment   [32]byte
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
	kinds := 0
	if entry.Device != nil {
		kinds++
	}
	if entry.Membership != nil {
		kinds++
	}
	if entry.Issuer != nil {
		kinds++
	}
	if kinds != 1 {
		return nil, errors.New("invalid directory entry kind")
	}
	if entry.Device != nil {
		value := entry.Device
		if isZero16(value.DeviceID) || value.Generation == 0 || isZero32(value.SigningKeyID) || isZero32(value.SigningPublicKey) || isZero32(value.HPKEKeyID) || isZero32(value.HPKEPublicKey) {
			return nil, errors.New("invalid directory device")
		}
		return canonicalEncoding.Marshal(map[uint64]any{1: uint64(1), 2: value.DeviceID, 3: value.Generation, 4: value.SigningKeyID, 5: value.SigningPublicKey, 6: value.HPKEKeyID, 7: value.HPKEPublicKey, 8: value.Revoked})
	}
	if entry.Issuer != nil {
		value := entry.Issuer
		if isZero32(value.KeyID) || isZero32(value.PublicKey) {
			return nil, errors.New("invalid directory permit issuer")
		}
		return canonicalEncoding.Marshal(map[uint64]any{1: uint64(3), 2: value.KeyID, 3: value.PublicKey, 4: value.Revoked})
	}
	value := entry.Membership
	if isZero16(value.ConversationID) || isZero16(value.SenderDeviceID) || value.SenderGeneration == 0 || isZero16(value.RecipientDeviceID) || value.RecipientGeneration == 0 || isZero32(value.Commitment) {
		return nil, errors.New("invalid directory membership")
	}
	return canonicalEncoding.Marshal(map[uint64]any{1: uint64(2), 2: value.ConversationID, 3: value.SenderDeviceID, 4: value.SenderGeneration, 5: value.RecipientDeviceID, 6: value.RecipientGeneration, 7: value.Commitment, 8: value.Revoked})
}

// CurrentPermitIssuerKey resolves one active permit issuer from a fresh,
// current directory snapshot.
func (r *DirectorySnapshotResolver) CurrentPermitIssuerKey(keyID [32]byte) (ed25519.PublicKey, error) {
	if r == nil || !r.fresh(r.now()) || !r.current() {
		return nil, errors.New("stale permit issuer directory authority")
	}
	issuer, found := r.issuers[keyID]
	if !found || issuer.Revoked {
		return nil, errors.New("unknown permit issuer key")
	}
	return ed25519.PublicKey(append([]byte(nil), issuer.PublicKey[:]...)), nil
}

// DirectorySnapshotResolver resolves manifest and envelope key authority only
// from a freshly verified root-signed snapshot.
type DirectorySnapshotResolver struct {
	head             DirectoryHead
	devices          map[directoryDeviceKey]DirectoryDevice
	latestGeneration map[[16]byte]uint64
	memberships      map[directoryMembershipKey]DirectoryMembership
	issuers          map[[32]byte]DirectoryPermitIssuer
	checkpoints      CheckpointStore
	now              func() time.Time
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
	entries = cloneDirectoryEntries(entries)
	hashes, err := DirectoryEntryHashes(entries)
	if err != nil || uint64(len(hashes)) != head.TreeSize || directoryMerkleRoot(hashes) != head.TreeRoot {
		return nil, errors.New("directory snapshot does not match head")
	}
	if proof != nil && !sameHashes(proof.LeafHashes, hashes) {
		return nil, errors.New("directory snapshot differs from consistency proof")
	}
	devices, latestGeneration, memberships, issuers, err := validateDirectoryEntryHistory(entries)
	if err != nil {
		return nil, err
	}
	if _, err := advanceVerifiedDirectoryHead(rawHead, head, trust, proof); err != nil {
		return nil, err
	}
	return &DirectorySnapshotResolver{head: head, devices: devices, latestGeneration: latestGeneration, memberships: memberships, issuers: issuers, checkpoints: trust.Checkpoints, now: time.Now}, nil
}

func cloneDirectoryEntries(entries []DirectoryEntry) []DirectoryEntry {
	cloned := make([]DirectoryEntry, len(entries))
	for index, entry := range entries {
		if entry.Device != nil {
			device := *entry.Device
			cloned[index].Device = &device
		}
		if entry.Membership != nil {
			membership := *entry.Membership
			cloned[index].Membership = &membership
		}
		if entry.Issuer != nil {
			issuer := *entry.Issuer
			cloned[index].Issuer = &issuer
		}
	}
	return cloned
}

// validateDirectoryEntryHistory makes a device generation immutable. Its only
// permitted subsequent state change is revocation, and membership snapshots
// are immutable too. This prevents a validly signed tree from accidentally
// reviving a device or rebinding its established identity.
func validateDirectoryEntryHistory(entries []DirectoryEntry) (map[directoryDeviceKey]DirectoryDevice, map[[16]byte]uint64, map[directoryMembershipKey]DirectoryMembership, map[[32]byte]DirectoryPermitIssuer, error) {
	devices := make(map[directoryDeviceKey]DirectoryDevice)
	latestGeneration := make(map[[16]byte]uint64)
	memberships := make(map[directoryMembershipKey]DirectoryMembership)
	issuers := make(map[[32]byte]DirectoryPermitIssuer)
	for _, entry := range entries {
		if entry.Device != nil {
			current := *entry.Device
			key := directoryDeviceKey{id: current.DeviceID, generation: current.Generation}
			previous, seen := devices[key]
			if !seen {
				if current.Revoked {
					return nil, nil, nil, nil, errors.New("directory device cannot begin revoked")
				}
				if current.SigningKeyID == current.HPKEKeyID {
					return nil, nil, nil, nil, errors.New("directory device key identifiers must differ")
				}
				devices[key] = current
				if current.Generation > latestGeneration[current.DeviceID] {
					latestGeneration[current.DeviceID] = current.Generation
				}
				continue
			}
			if previous.DeviceID != current.DeviceID || previous.Generation != current.Generation || previous.SigningKeyID != current.SigningKeyID || previous.SigningPublicKey != current.SigningPublicKey || previous.HPKEKeyID != current.HPKEKeyID || previous.HPKEPublicKey != current.HPKEPublicKey || previous.Revoked || !current.Revoked {
				return nil, nil, nil, nil, errors.New("invalid directory device history")
			}
			devices[key] = current
			continue
		}
		if entry.Issuer != nil {
			current := *entry.Issuer
			if isZero32(current.KeyID) || isZero32(current.PublicKey) {
				return nil, nil, nil, nil, errors.New("invalid directory permit issuer")
			}
			previous, seen := issuers[current.KeyID]
			if !seen {
				if current.Revoked {
					return nil, nil, nil, nil, errors.New("directory permit issuer cannot begin revoked")
				}
				issuers[current.KeyID] = current
				continue
			}
			if previous.KeyID != current.KeyID || previous.PublicKey != current.PublicKey || previous.Revoked || !current.Revoked {
				return nil, nil, nil, nil, errors.New("invalid directory permit issuer history")
			}
			issuers[current.KeyID] = current
			continue
		}
		current := *entry.Membership
		key := directoryMembershipKey{conversation: current.ConversationID, sender: current.SenderDeviceID, senderGen: current.SenderGeneration, recipient: current.RecipientDeviceID, recipientGen: current.RecipientGeneration, commitment: current.Commitment}
		previous, seen := memberships[key]
		if !seen {
			if current.Revoked {
				return nil, nil, nil, nil, errors.New("directory membership cannot begin revoked")
			}
			memberships[key] = current
			continue
		}
		if previous.ConversationID != current.ConversationID || previous.SenderDeviceID != current.SenderDeviceID || previous.SenderGeneration != current.SenderGeneration || previous.RecipientDeviceID != current.RecipientDeviceID || previous.RecipientGeneration != current.RecipientGeneration || previous.Commitment != current.Commitment || previous.Revoked || !current.Revoked {
			return nil, nil, nil, nil, errors.New("invalid directory membership history")
		}
		memberships[key] = current
	}
	return devices, latestGeneration, memberships, issuers, nil
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
	if r == nil || !r.fresh(now) || !r.current() {
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
	_, recipientFound := r.device(manifest.RecipientDeviceID, manifest.RecipientGeneration)
	if !found || !recipientFound || sender.SigningKeyID != manifest.SignerKeyID || !r.membership(manifest) {
		return nil, errors.New("invalid manifest directory authority")
	}
	return ed25519.PublicKey(append([]byte(nil), sender.SigningPublicKey[:]...)), nil
}

// CurrentRecipientHPKEKey resolves the current non-revoked recipient HPKE key.
func (r *DirectorySnapshotResolver) CurrentRecipientHPKEKey(deviceID [16]byte, generation uint64) ([32]byte, *ecdh.PublicKey, error) {
	if r == nil || !r.fresh(r.now()) || !r.current() {
		return [32]byte{}, nil, errors.New("stale recipient directory authority")
	}
	device, found := r.device(deviceID, generation)
	if !found {
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

func (r *DirectorySnapshotResolver) current() bool {
	if r.checkpoints == nil {
		return false
	}
	frozen, err := r.checkpoints.AudienceFrozen(r.head.Audience)
	if err != nil || frozen {
		return false
	}
	checkpoint, found, err := r.checkpoints.LoadCheckpoint(r.head.Audience)
	return err == nil && found && checkpoint == checkpointFor(r.head)
}

func (r *DirectorySnapshotResolver) device(deviceID [16]byte, generation uint64) (DirectoryDevice, bool) {
	if r.latestGeneration[deviceID] != generation {
		return DirectoryDevice{}, false
	}
	record, found := r.devices[directoryDeviceKey{id: deviceID, generation: generation}]
	return record, found && !record.Revoked
}

func (r *DirectorySnapshotResolver) membership(manifest Manifest) bool {
	record, found := r.memberships[directoryMembershipKey{conversation: manifest.ConversationID, sender: manifest.SenderDeviceID, senderGen: manifest.SenderGeneration, recipient: manifest.RecipientDeviceID, recipientGen: manifest.RecipientGeneration, commitment: manifest.MembershipCommitment}]
	return found && !record.Revoked
}

func directoryHeadCommitment(head DirectoryHead) ([32]byte, error) {
	raw, err := EncodeDirectoryHead(head)
	if err != nil {
		return [32]byte{}, err
	}
	return blake3.Sum256(raw), nil
}

var _ DirectoryKeyResolver = (*DirectorySnapshotResolver)(nil)
