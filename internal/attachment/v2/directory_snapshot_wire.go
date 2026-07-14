package v2

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

const maxDirectorySnapshotEncodedBytes = 2 << 20

var directorySnapshotDecoding cbor.DecMode

func init() {
	var err error
	directorySnapshotDecoding, err = (cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF, IndefLength: cbor.IndefLengthForbidden, TagsMd: cbor.TagsForbidden, ExtraReturnErrors: cbor.ExtraDecErrorUnknownField, UTF8: cbor.UTF8RejectInvalid, MaxNestedLevels: 4, MaxArrayElements: maxDirectoryLeaves, MaxMapPairs: 16}).DecMode()
	if err != nil {
		panic(fmt.Sprintf("configure directory snapshot CBOR: %v", err))
	}
}

type directorySnapshotWire struct {
	Version uint64     `cbor:"1,keyasint"`
	Head    []byte     `cbor:"2,keyasint"`
	Proof   [][32]byte `cbor:"3,keyasint"`
	Entries [][]byte   `cbor:"4,keyasint"`
}

// EncodeDirectorySnapshot returns the bounded canonical wire representation
// of a complete directory view. It never accepts caller-supplied leaf bytes.
func EncodeDirectorySnapshot(snapshot DirectorySnapshot) ([]byte, error) {
	if _, err := decodeDirectoryHead(snapshot.RawHead); err != nil || len(snapshot.Entries) == 0 || len(snapshot.Entries) > maxDirectoryLeaves {
		return nil, errors.New("invalid directory snapshot")
	}
	entries := make([][]byte, 0, len(snapshot.Entries))
	for _, entry := range snapshot.Entries {
		raw, err := EncodeDirectoryEntry(entry)
		if err != nil {
			return nil, err
		}
		entries = append(entries, raw)
	}
	var proof [][32]byte
	if snapshot.Proof != nil {
		proof = append([][32]byte(nil), snapshot.Proof.LeafHashes...)
	}
	if len(proof) > maxDirectoryLeaves {
		return nil, errors.New("invalid directory snapshot proof")
	}
	return canonicalEncoding.Marshal(directorySnapshotWire{Version: protocolVersion, Head: append([]byte(nil), snapshot.RawHead...), Proof: proof, Entries: entries})
}

// DecodeDirectorySnapshot accepts only the complete canonical snapshot wire
// envelope. Callers must still verify it through NewDirectorySnapshotResolver.
func DecodeDirectorySnapshot(raw []byte) (DirectorySnapshot, error) {
	if len(raw) == 0 || len(raw) > maxDirectorySnapshotEncodedBytes {
		return DirectorySnapshot{}, errors.New("invalid directory snapshot")
	}
	var wire directorySnapshotWire
	if err := directorySnapshotDecoding.Unmarshal(raw, &wire); err != nil || wire.Version != protocolVersion || len(wire.Entries) == 0 || len(wire.Entries) > maxDirectoryLeaves || len(wire.Proof) > maxDirectoryLeaves {
		return DirectorySnapshot{}, errors.New("invalid directory snapshot")
	}
	if _, err := decodeDirectoryHead(wire.Head); err != nil {
		return DirectorySnapshot{}, errors.New("invalid directory snapshot")
	}
	entries := make([]DirectoryEntry, 0, len(wire.Entries))
	for _, rawEntry := range wire.Entries {
		entry, err := DecodeDirectoryEntry(rawEntry)
		if err != nil {
			return DirectorySnapshot{}, errors.New("invalid directory snapshot entry")
		}
		entries = append(entries, entry)
	}
	snapshot := DirectorySnapshot{RawHead: append([]byte(nil), wire.Head...), Entries: entries}
	if len(wire.Proof) != 0 {
		snapshot.Proof = &FullConsistencyProof{LeafHashes: append([][32]byte(nil), wire.Proof...)}
	}
	canonical, err := EncodeDirectorySnapshot(snapshot)
	if err != nil || !bytes.Equal(raw, canonical) {
		return DirectorySnapshot{}, errors.New("non-canonical directory snapshot")
	}
	return snapshot, nil
}
