package v2

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/zeebo/blake3"
)

const (
	directoryHeadDomain = "punaro/attachment/directory-head/v2\x00"
	directoryNodeDomain = "punaro/attachment/directory-node/v2\x00"
	maxDirectoryLeaves  = 4096
	maxDirectoryHead    = 4 << 10
	// Directory snapshots are refreshed frequently, but they must survive
	// ordinary scheduling, transport, and NTP convergence delays. Permits stay
	// much shorter-lived and are independently bound to a fresh directory view.
	maxDirectoryHeadLifetimeSeconds = 5 * 60
	maxDirectoryFutureSkewSeconds   = 60
)

// DirectoryHead is the root-signed, canonical, short-lived authority snapshot
// for one attachment audience.
type DirectoryHead struct {
	Audience        [32]byte
	RootKeyID       [32]byte
	TreeSize        uint64
	TreeRoot        [32]byte
	Sequence        uint64
	IssuedAt        uint64
	ExpiresAt       uint64
	RevocationEpoch uint64
	Signature       [ed25519.SignatureSize]byte
}

type directoryHeadWire struct {
	Version         uint64                      `cbor:"1,keyasint"`
	Audience        [32]byte                    `cbor:"2,keyasint"`
	RootKeyID       [32]byte                    `cbor:"3,keyasint"`
	TreeSize        uint64                      `cbor:"4,keyasint"`
	TreeRoot        [32]byte                    `cbor:"5,keyasint"`
	Sequence        uint64                      `cbor:"6,keyasint"`
	IssuedAt        uint64                      `cbor:"7,keyasint"`
	ExpiresAt       uint64                      `cbor:"8,keyasint"`
	RevocationEpoch uint64                      `cbor:"9,keyasint"`
	Signature       [ed25519.SignatureSize]byte `cbor:"99,keyasint"`
}

// DirectoryCheckpoint is the durable anti-rollback checkpoint for an
// audience. It is safe to retain indefinitely and contains no private key.
type DirectoryCheckpoint struct {
	Sequence        uint64
	TreeSize        uint64
	TreeRoot        [32]byte
	RevocationEpoch uint64
}

// CheckpointStore persists attachment directory checkpoints and evidence of
// equivocation. Implementations must make each operation durable before
// returning success.
type CheckpointStore interface {
	// Advance atomically checks the current checkpoint, validates the supplied
	// append-only proof against it, persists a newer checkpoint, or durably
	// freezes an equivocated audience before returning. Implementations must
	// serialize this operation for one audience.
	Advance(audience [32]byte, next DirectoryCheckpoint, evidence []byte, proof *FullConsistencyProof) error
	LoadCheckpoint(audience [32]byte) (DirectoryCheckpoint, bool, error)
	AudienceFrozen(audience [32]byte) (bool, error)
}

// DirectoryTrust pins exactly one root authority for an attachment audience.
type DirectoryTrust struct {
	Audience      [32]byte
	RootKeyID     [32]byte
	RootPublicKey ed25519.PublicKey
	Checkpoints   CheckpointStore
}

// FullConsistencyProof proves an append-only advance by supplying every
// bounded leaf hash. It is intentionally stronger than a logarithmic proof;
// the first release is limited to a small device directory and avoids an
// underspecified compact-proof format.
type FullConsistencyProof struct{ LeafHashes [][32]byte }

func (h DirectoryHead) signingBytes() ([]byte, error) {
	encoded, err := canonicalEncoding.Marshal(map[uint64]any{1: uint64(protocolVersion), 2: h.Audience, 3: h.RootKeyID, 4: h.TreeSize, 5: h.TreeRoot, 6: h.Sequence, 7: h.IssuedAt, 8: h.ExpiresAt, 9: h.RevocationEpoch})
	return append([]byte(directoryHeadDomain), encoded...), err
}

func (h DirectoryHead) wire() directoryHeadWire {
	return directoryHeadWire{Version: protocolVersion, Audience: h.Audience, RootKeyID: h.RootKeyID, TreeSize: h.TreeSize, TreeRoot: h.TreeRoot, Sequence: h.Sequence, IssuedAt: h.IssuedAt, ExpiresAt: h.ExpiresAt, RevocationEpoch: h.RevocationEpoch, Signature: h.Signature}
}

func validateDirectoryHead(h DirectoryHead) error {
	if isZero32(h.Audience) || isZero32(h.RootKeyID) || isZero32(h.TreeRoot) || h.TreeSize == 0 || h.TreeSize > maxDirectoryLeaves || h.Sequence == 0 || h.ExpiresAt <= h.IssuedAt || h.ExpiresAt-h.IssuedAt > maxDirectoryHeadLifetimeSeconds {
		return errors.New("invalid directory head")
	}
	return nil
}

// SignDirectoryHead validates and signs a canonical directory head.
func SignDirectoryHead(head *DirectoryHead, private ed25519.PrivateKey) error {
	if head == nil || len(private) != ed25519.PrivateKeySize || validateDirectoryHead(*head) != nil {
		return errors.New("invalid directory head signer")
	}
	payload, err := head.signingBytes()
	if err != nil {
		return err
	}
	copy(head.Signature[:], ed25519.Sign(private, payload))
	return nil
}

// EncodeDirectoryHead returns the strict canonical full signed head record.
func EncodeDirectoryHead(head DirectoryHead) ([]byte, error) {
	if err := validateDirectoryHead(head); err != nil {
		return nil, err
	}
	return canonicalEncoding.Marshal(head.wire())
}

func decodeDirectoryHead(raw []byte) (DirectoryHead, error) {
	if len(raw) == 0 || len(raw) > maxDirectoryHead {
		return DirectoryHead{}, errors.New("invalid directory head size")
	}
	var wire directoryHeadWire
	if err := strictDecoding.Unmarshal(raw, &wire); err != nil {
		return DirectoryHead{}, fmt.Errorf("decode directory head: %w", err)
	}
	if wire.Version != protocolVersion {
		return DirectoryHead{}, errors.New("unsupported directory head version")
	}
	head := DirectoryHead{Audience: wire.Audience, RootKeyID: wire.RootKeyID, TreeSize: wire.TreeSize, TreeRoot: wire.TreeRoot, Sequence: wire.Sequence, IssuedAt: wire.IssuedAt, ExpiresAt: wire.ExpiresAt, RevocationEpoch: wire.RevocationEpoch, Signature: wire.Signature}
	if err := validateDirectoryHead(head); err != nil {
		return DirectoryHead{}, err
	}
	canonical, err := EncodeDirectoryHead(head)
	if err != nil || !bytes.Equal(raw, canonical) {
		return DirectoryHead{}, errors.New("non-canonical directory head")
	}
	return head, nil
}

// verifyAndAdvanceDirectoryHead is retained only for package-level tests of
// head verification. Production code must use NewDirectorySnapshotResolver so
// an unsigned or withheld snapshot can never advance a checkpoint.
func verifyAndAdvanceDirectoryHead(raw []byte, trust DirectoryTrust, now time.Time, proof *FullConsistencyProof) (DirectoryHead, error) {
	head, err := verifyDirectoryHead(raw, trust, now)
	if err != nil {
		return DirectoryHead{}, err
	}
	return advanceVerifiedDirectoryHead(raw, head, trust, proof)
}

// verifyDirectoryHead performs the pure, cryptographic and freshness checks
// for a directory head. Callers that also validate a full snapshot must do so
// before calling advanceVerifiedDirectoryHead, otherwise a withheld or invalid
// snapshot could advance the durable checkpoint and cause a local DoS.
func verifyDirectoryHead(raw []byte, trust DirectoryTrust, now time.Time) (DirectoryHead, error) {
	if isZero32(trust.Audience) || isZero32(trust.RootKeyID) || len(trust.RootPublicKey) != ed25519.PublicKeySize || trust.Checkpoints == nil {
		return DirectoryHead{}, errors.New("invalid directory trust")
	}
	head, err := decodeDirectoryHead(raw)
	if err != nil || head.Audience != trust.Audience || head.RootKeyID != trust.RootKeyID {
		return DirectoryHead{}, errors.New("invalid directory authority")
	}
	payload, err := head.signingBytes()
	if err != nil || !ed25519.Verify(trust.RootPublicKey, payload, head.Signature[:]) {
		return DirectoryHead{}, errors.New("invalid directory signature")
	}
	nowUnix := now.UTC().Unix()
	if nowUnix < 0 || head.IssuedAt > uint64(nowUnix)+maxDirectoryFutureSkewSeconds || head.ExpiresAt <= uint64(nowUnix) {
		return DirectoryHead{}, errors.New("stale directory head")
	}
	return head, nil
}

func advanceVerifiedDirectoryHead(raw []byte, head DirectoryHead, trust DirectoryTrust, proof *FullConsistencyProof) (DirectoryHead, error) {
	if err := trust.Checkpoints.Advance(trust.Audience, checkpointFor(head), append([]byte(nil), raw...), proof); err != nil {
		return DirectoryHead{}, err
	}
	return head, nil
}

func advanceCheckpoint(previous DirectoryCheckpoint, found bool, frozen bool, next DirectoryCheckpoint, proof *FullConsistencyProof) (save, freeze bool, result error) {
	if frozen {
		return false, false, errors.New("directory audience is frozen")
	}
	if !found {
		return true, false, nil
	}
	if next.Sequence < previous.Sequence || next.RevocationEpoch < previous.RevocationEpoch {
		return false, false, errors.New("directory rollback")
	}
	if next.Sequence == previous.Sequence {
		if next.TreeSize != previous.TreeSize || next.TreeRoot != previous.TreeRoot || next.RevocationEpoch != previous.RevocationEpoch {
			return false, true, errors.New("directory equivocation")
		}
		return false, false, nil
	}
	head := DirectoryHead{TreeSize: next.TreeSize, TreeRoot: next.TreeRoot}
	if proof == nil || !proof.valid(previous, head) {
		return false, false, errors.New("invalid directory consistency proof")
	}
	return true, false, nil
}

func checkpointFor(head DirectoryHead) DirectoryCheckpoint {
	return DirectoryCheckpoint{Sequence: head.Sequence, TreeSize: head.TreeSize, TreeRoot: head.TreeRoot, RevocationEpoch: head.RevocationEpoch}
}

func (p FullConsistencyProof) valid(previous DirectoryCheckpoint, next DirectoryHead) bool {
	if uint64(len(p.LeafHashes)) != next.TreeSize || previous.TreeSize > next.TreeSize || previous.TreeSize == 0 || previous.TreeSize > uint64(len(p.LeafHashes)) {
		return false
	}
	return directoryMerkleRoot(p.LeafHashes[:previous.TreeSize]) == previous.TreeRoot && directoryMerkleRoot(p.LeafHashes) == next.TreeRoot
}

func directoryMerkleRoot(leaves [][32]byte) [32]byte {
	if len(leaves) == 0 {
		return [32]byte{}
	}
	level := append([][32]byte(nil), leaves...)
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for index := 0; index < len(level); index += 2 {
			if index+1 == len(level) {
				next = append(next, level[index])
				continue
			}
			next = append(next, blake3.Sum256(append(append([]byte(directoryNodeDomain), level[index][:]...), level[index+1][:]...)))
		}
		level = next
	}
	return level[0]
}

// DirectoryMerkleRoot calculates the ordered directory tree root used by a
// publisher before it signs a DirectoryHead. Consumers still must verify the
// full snapshot and signed head through NewDirectorySnapshotResolver.
func DirectoryMerkleRoot(leaves [][32]byte) [32]byte {
	return directoryMerkleRoot(leaves)
}
