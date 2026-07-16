package v3

import (
	"bytes"
	"errors"
)

// TransferState is the lifecycle state returned by a successful v3 attachment
// operation. It is informational only: callers must still retain and verify
// their exact permit/operation records before advancing local durable state.
type TransferState uint64

const (
	TransferStateSourceUploading TransferState = TransferState(transferSourceUploading)
	TransferStateSourceReady     TransferState = TransferState(transferSourceReady)
	TransferStateOffered         TransferState = TransferState(transferOffered)
	TransferStateAccepted        TransferState = TransferState(transferAccepted)
	TransferStateTransferring    TransferState = TransferState(transferTransferring)
	TransferStateCompleted       TransferState = TransferState(transferCompleted)
	TransferStateExpired         TransferState = TransferState(transferExpired)
	TransferStateCancelled       TransferState = TransferState(transferCancelled)
	TransferStateRevoked         TransferState = TransferState(transferRevoked)
)

// TransferResult is the canonical lifecycle response from a v3 attachment
// route. It intentionally contains no filename, plaintext, permit, or key.
type TransferResult struct {
	TransferID         [16]byte
	ManifestCommitment [32]byte
	State              TransferState
	AttemptGeneration  uint64
	ExpiresAt          int64
}

type transferResultWire struct {
	Version            uint64   `cbor:"1,keyasint"`
	TransferID         [16]byte `cbor:"2,keyasint"`
	ManifestCommitment [32]byte `cbor:"3,keyasint"`
	State              uint64   `cbor:"4,keyasint"`
	AttemptGeneration  uint64   `cbor:"5,keyasint"`
	ExpiresAt          int64    `cbor:"6,keyasint"`
}

// DecodeTransferResult accepts only the deterministic response emitted by a
// v3 route. Malformed, unrecognized, or non-canonical responses cannot drive
// a controller's lifecycle journal.
func DecodeTransferResult(raw []byte) (TransferResult, error) {
	if len(raw) == 0 || len(raw) > 256 {
		return TransferResult{}, errors.New("invalid v3 transfer result")
	}
	var wire transferResultWire
	if err := strictDecoding.Unmarshal(raw, &wire); err != nil || wire.Version != protocolVersion {
		return TransferResult{}, errors.New("invalid v3 transfer result")
	}
	status := transferStatus(wire.State)
	if status < transferSourceUploading || status > transferRevoked || !validTransferRecord(transferRecord{TransferID: wire.TransferID, ManifestCommitment: wire.ManifestCommitment, Status: status, AttemptGeneration: wire.AttemptGeneration, ExpiresAt: wire.ExpiresAt}) {
		return TransferResult{}, errors.New("invalid v3 transfer result")
	}
	canonical, err := canonicalEncoding.Marshal(wire)
	if err != nil || !bytes.Equal(raw, canonical) {
		return TransferResult{}, errors.New("non-canonical v3 transfer result")
	}
	return TransferResult{TransferID: wire.TransferID, ManifestCommitment: wire.ManifestCommitment, State: TransferState(wire.State), AttemptGeneration: wire.AttemptGeneration, ExpiresAt: wire.ExpiresAt}, nil
}
