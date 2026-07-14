package v2

import (
	"errors"
	"time"
)

// TransferStatus is the durable attachment lifecycle state. Terminal states
// cannot transition again; retries are handled above this state machine by the
// signed operation ledger.
type TransferStatus uint64

const (
	TransferCreated TransferStatus = iota + 1
	TransferSourceReady
	TransferOffered
	TransferAccepted
	TransferTransferring
	TransferCompleted
	TransferExpired
	TransferCancelled
	TransferRevoked
)

// Terminal reports whether the state can never be revived.
func (status TransferStatus) Terminal() bool {
	return status == TransferCompleted || status == TransferExpired || status == TransferCancelled || status == TransferRevoked
}

// TransferAction is the only state transition input. The concrete relay route
// must first redeem its exact signed permit before applying this action.
type TransferAction uint64

const (
	TransferActionSourceReady TransferAction = iota + 1
	TransferActionOffer
	TransferActionAccept
	TransferActionBegin
	TransferActionComplete
	TransferActionExpire
	TransferActionCancel
	TransferActionRevoke
)

// TransferRecord contains only non-secret lifecycle data. Ciphertext and the
// recipient envelope live in separate immutable relay records.
type TransferRecord struct {
	TransferID         [16]byte
	ManifestCommitment [32]byte
	Status             TransferStatus
	AttemptGeneration  uint64
	ExpiresAt          uint64
}

// NewTransferRecord makes a created transfer. Inputs are checked by every
// transition so a zero record can never be made live by mistake.
func NewTransferRecord(transferID [16]byte, manifestCommitment [32]byte, expiresAt uint64) TransferRecord {
	return TransferRecord{TransferID: transferID, ManifestCommitment: manifestCommitment, Status: TransferCreated, ExpiresAt: expiresAt}
}

// Transition applies one lifecycle action without mutating the receiver.
// Attempt generation is fixed at one for the only currently permitted live
// attempt; retrying an operation returns through the redemption ledger rather
// than creating another attempt.
func (record TransferRecord) Transition(action TransferAction, now time.Time) (TransferRecord, error) {
	seconds := now.UTC().Unix()
	if isZero16(record.TransferID) || isZero32(record.ManifestCommitment) || record.Status < TransferCreated || record.Status > TransferRevoked || record.ExpiresAt == 0 || seconds < 0 {
		return TransferRecord{}, errors.New("invalid transfer record")
	}
	if record.Status.Terminal() {
		return TransferRecord{}, errors.New("terminal transfer")
	}
	nowUnix := uint64(seconds)
	if action == TransferActionExpire {
		if nowUnix < record.ExpiresAt {
			return TransferRecord{}, errors.New("transfer has not expired")
		}
		record.Status = TransferExpired
		return record, nil
	}
	if nowUnix >= record.ExpiresAt {
		return TransferRecord{}, errors.New("transfer expired")
	}
	switch action {
	case TransferActionSourceReady:
		if record.Status != TransferCreated {
			return TransferRecord{}, errors.New("source-ready requires created transfer")
		}
		record.Status = TransferSourceReady
	case TransferActionOffer:
		if record.Status != TransferSourceReady || record.AttemptGeneration != 0 {
			return TransferRecord{}, errors.New("offer requires source-ready transfer")
		}
		record.Status, record.AttemptGeneration = TransferOffered, 1
	case TransferActionAccept:
		if record.Status != TransferOffered || record.AttemptGeneration != 1 {
			return TransferRecord{}, errors.New("accept requires offered transfer")
		}
		record.Status = TransferAccepted
	case TransferActionBegin:
		if record.Status != TransferAccepted || record.AttemptGeneration != 1 {
			return TransferRecord{}, errors.New("begin requires accepted transfer")
		}
		record.Status = TransferTransferring
	case TransferActionComplete:
		if record.Status != TransferTransferring || record.AttemptGeneration != 1 {
			return TransferRecord{}, errors.New("complete requires transferring transfer")
		}
		record.Status = TransferCompleted
	case TransferActionCancel:
		record.Status = TransferCancelled
	case TransferActionRevoke:
		record.Status = TransferRevoked
	default:
		return TransferRecord{}, errors.New("unknown transfer action")
	}
	return record, nil
}
