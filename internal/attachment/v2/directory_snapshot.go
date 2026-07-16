package v2

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/fxamacker/cbor/v2"
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

// EncodeDirectoryEntry returns one canonical directory leaf payload suitable
// for a signed snapshot transport. It performs the same validation used when
// calculating the transparency-tree leaf hash.
func EncodeDirectoryEntry(entry DirectoryEntry) ([]byte, error) {
	return entry.canonicalBytes()
}

// DecodeDirectoryEntry accepts one complete canonical directory leaf payload.
func DecodeDirectoryEntry(raw []byte) (DirectoryEntry, error) {
	var fields map[uint64]cbor.RawMessage
	if len(raw) == 0 || strictDecoding.Unmarshal(raw, &fields) != nil {
		return DirectoryEntry{}, errors.New("invalid directory entry")
	}
	var kind uint64
	if decodeDirectoryField(fields, 1, &kind) != nil {
		return DirectoryEntry{}, errors.New("invalid directory entry")
	}
	var entry DirectoryEntry
	switch kind {
	case 1:
		value := DirectoryDevice{}
		if decodeDirectoryField(fields, 2, &value.DeviceID) != nil || decodeDirectoryField(fields, 3, &value.Generation) != nil || decodeDirectoryField(fields, 4, &value.SigningKeyID) != nil || decodeDirectoryField(fields, 5, &value.SigningPublicKey) != nil || decodeDirectoryField(fields, 6, &value.HPKEKeyID) != nil || decodeDirectoryField(fields, 7, &value.HPKEPublicKey) != nil || decodeDirectoryField(fields, 8, &value.Revoked) != nil {
			return DirectoryEntry{}, errors.New("invalid directory entry")
		}
		entry.Device = &value
	case 2:
		value := DirectoryMembership{}
		if decodeDirectoryField(fields, 2, &value.ConversationID) != nil || decodeDirectoryField(fields, 3, &value.SenderDeviceID) != nil || decodeDirectoryField(fields, 4, &value.SenderGeneration) != nil || decodeDirectoryField(fields, 5, &value.RecipientDeviceID) != nil || decodeDirectoryField(fields, 6, &value.RecipientGeneration) != nil || decodeDirectoryField(fields, 7, &value.Commitment) != nil || decodeDirectoryField(fields, 8, &value.Revoked) != nil {
			return DirectoryEntry{}, errors.New("invalid directory entry")
		}
		entry.Membership = &value
	case 3:
		value := DirectoryPermitIssuer{}
		if decodeDirectoryField(fields, 2, &value.KeyID) != nil || decodeDirectoryField(fields, 3, &value.PublicKey) != nil || decodeDirectoryField(fields, 4, &value.Revoked) != nil {
			return DirectoryEntry{}, errors.New("invalid directory entry")
		}
		entry.Issuer = &value
	default:
		return DirectoryEntry{}, errors.New("invalid directory entry")
	}
	canonical, err := entry.canonicalBytes()
	if err != nil || !bytes.Equal(raw, canonical) {
		return DirectoryEntry{}, errors.New("non-canonical directory entry")
	}
	return entry, nil
}

func decodeDirectoryField(fields map[uint64]cbor.RawMessage, field uint64, target any) error {
	raw, found := fields[field]
	if !found {
		return errors.New("missing directory field")
	}
	return strictDecoding.Unmarshal(raw, target)
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

// PermitDirectoryBinding contains only version-neutral directory facts. It is
// deliberately not a permit wire record: another attachment version may reuse
// the root-verified authority checks without accidentally inheriting v2 route,
// attempt, or operation-number policy.
type PermitDirectoryBinding struct {
	Audience             [32]byte
	IssuerKeyID          [32]byte
	HolderDeviceID       [16]byte
	HolderGeneration     uint64
	HolderRole           uint64
	ConversationID       [16]byte
	SenderDeviceID       [16]byte
	SenderGeneration     uint64
	RecipientDeviceID    [16]byte
	RecipientGeneration  uint64
	DirectoryHead        [32]byte
	MembershipCommitment [32]byte
	RevocationEpoch      uint64
	ExpiresAt            uint64
}

// ValidatePermitDirectoryBinding validates only fresh directory membership,
// key, device, revocation and signed-head facts. It intentionally has no
// operation or attempt field, so it remains safe for separately-versioned
// attachment protocols.
func (r *DirectorySnapshotResolver) ValidatePermitDirectoryBinding(binding PermitDirectoryBinding, now time.Time) (ed25519.PublicKey, error) {
	if r == nil || !r.fresh(now) || !r.current() {
		return nil, errors.New("invalid permit directory authority")
	}
	headCommitment, err := directoryHeadCommitment(r.head)
	if err != nil || binding.Audience != r.head.Audience || binding.DirectoryHead != headCommitment || binding.RevocationEpoch != r.head.RevocationEpoch || binding.ExpiresAt > r.head.ExpiresAt {
		return nil, errors.New("invalid permit directory authority")
	}
	issuer, found := r.issuers[binding.IssuerKeyID]
	if !found || issuer.Revoked {
		return nil, errors.New("invalid permit directory authority")
	}
	if _, found := r.device(binding.SenderDeviceID, binding.SenderGeneration); !found {
		return nil, errors.New("invalid permit directory authority")
	}
	if _, found := r.device(binding.RecipientDeviceID, binding.RecipientGeneration); !found {
		return nil, errors.New("invalid permit directory authority")
	}
	if _, found := r.device(binding.HolderDeviceID, binding.HolderGeneration); !found {
		return nil, errors.New("invalid permit directory authority")
	}
	if binding.HolderRole != PermitHolderSender && binding.HolderRole != PermitHolderRecipient {
		return nil, errors.New("invalid permit holder binding")
	}
	if (binding.HolderRole == PermitHolderSender && (binding.HolderDeviceID != binding.SenderDeviceID || binding.HolderGeneration != binding.SenderGeneration)) || (binding.HolderRole == PermitHolderRecipient && (binding.HolderDeviceID != binding.RecipientDeviceID || binding.HolderGeneration != binding.RecipientGeneration)) {
		return nil, errors.New("invalid permit holder binding")
	}
	membership, found := r.memberships[directoryMembershipKey{conversation: binding.ConversationID, sender: binding.SenderDeviceID, senderGen: binding.SenderGeneration, recipient: binding.RecipientDeviceID, recipientGen: binding.RecipientGeneration, commitment: binding.MembershipCommitment}]
	if !found || membership.Revoked {
		return nil, errors.New("invalid permit directory authority")
	}
	return ed25519.PublicKey(append([]byte(nil), issuer.PublicKey[:]...)), nil
}

// ValidatePermitAuthority implements PermitAuthorityResolver. A permit is
// usable only while every signed directory binding names this exact fresh,
// current snapshot; a merely current issuer key is not sufficient.
func (r *DirectorySnapshotResolver) ValidatePermitAuthority(permit Permit, now time.Time) (ed25519.PublicKey, error) {
	return r.ValidatePermitDirectoryBinding(PermitDirectoryBinding{Audience: permit.Audience, IssuerKeyID: permit.IssuerKeyID, HolderDeviceID: permit.HolderDeviceID, HolderGeneration: permit.HolderGeneration, HolderRole: permit.HolderRole, ConversationID: permit.ConversationID, SenderDeviceID: permit.SenderDeviceID, SenderGeneration: permit.SenderGeneration, RecipientDeviceID: permit.RecipientDeviceID, RecipientGeneration: permit.RecipientGeneration, DirectoryHead: permit.DirectoryHead, MembershipCommitment: permit.MembershipCommitment, RevocationEpoch: permit.RevocationEpoch, ExpiresAt: permit.ExpiresAt}, now)
}

// CurrentDeviceSigningKey resolves one active device signing key for a
// permit-holder operation record.
func (r *DirectorySnapshotResolver) CurrentDeviceSigningKey(deviceID [16]byte, generation uint64) (ed25519.PublicKey, error) {
	if r == nil || !r.fresh(r.now()) || !r.current() {
		return nil, errors.New("stale device directory authority")
	}
	device, found := r.device(deviceID, generation)
	if !found {
		return nil, errors.New("unknown device signing key")
	}
	return ed25519.PublicKey(append([]byte(nil), device.SigningPublicKey[:]...)), nil
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

// DirectoryPermitBinding is the exact fresh directory authority an issuer
// binds into a newly minted permit. It deliberately omits keys: callers must
// resolve the issuer and holder through the same resolver interfaces.
type DirectoryPermitBinding struct {
	Audience        [32]byte
	DirectoryHead   [32]byte
	RevocationEpoch uint64
	ExpiresAt       uint64
}

// DirectoryTransferBinding is the exact current, root-verified directory
// authority for one already-approved attachment relationship. It deliberately
// includes the immutable membership commitment rather than allowing callers to
// discover a recipient from an arbitrary device entry.
type DirectoryTransferBinding struct {
	Permit     DirectoryPermitBinding
	Sender     DirectoryDevice
	Recipient  DirectoryDevice
	Membership DirectoryMembership
}

// CurrentPermitBinding returns the signed-head commitment and expiry only when
// the resolver is still fresh and matches its durable checkpoint.
func (r *DirectorySnapshotResolver) CurrentPermitBinding(now time.Time) (DirectoryPermitBinding, error) {
	if r == nil || !r.fresh(now) || !r.current() {
		return DirectoryPermitBinding{}, errors.New("stale permit directory authority")
	}
	commitment, err := directoryHeadCommitment(r.head)
	if err != nil {
		return DirectoryPermitBinding{}, errors.New("invalid permit directory authority")
	}
	return DirectoryPermitBinding{Audience: r.head.Audience, DirectoryHead: commitment, RevocationEpoch: r.head.RevocationEpoch, ExpiresAt: r.head.ExpiresAt}, nil
}

// ResolveTransferBinding returns only an exact active sender/recipient
// membership from the resolver's current checkpointed directory snapshot. A
// caller must supply every identifier from its immutable local policy; this
// method never selects a recipient or membership opportunistically.
func (r *DirectorySnapshotResolver) ResolveTransferBinding(conversationID, senderID [16]byte, senderGeneration uint64, recipientID [16]byte, recipientGeneration uint64, membershipCommitment [32]byte, now time.Time) (DirectoryTransferBinding, error) {
	if r == nil || conversationID == [16]byte{} || senderID == [16]byte{} || recipientID == [16]byte{} || senderGeneration == 0 || recipientGeneration == 0 || membershipCommitment == [32]byte{} {
		return DirectoryTransferBinding{}, errors.New("invalid transfer directory binding")
	}
	permit, err := r.CurrentPermitBinding(now)
	if err != nil {
		return DirectoryTransferBinding{}, errors.New("stale transfer directory authority")
	}
	sender, senderFound := r.device(senderID, senderGeneration)
	recipient, recipientFound := r.device(recipientID, recipientGeneration)
	membership, membershipFound := r.memberships[directoryMembershipKey{conversation: conversationID, sender: senderID, senderGen: senderGeneration, recipient: recipientID, recipientGen: recipientGeneration, commitment: membershipCommitment}]
	if !senderFound || !recipientFound || !membershipFound || membership.Revoked {
		return DirectoryTransferBinding{}, errors.New("unknown or revoked transfer directory binding")
	}
	return DirectoryTransferBinding{Permit: permit, Sender: sender, Recipient: recipient, Membership: membership}, nil
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
var _ PermitAuthorityResolver = (*DirectorySnapshotResolver)(nil)
