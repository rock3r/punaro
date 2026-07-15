package v3

import (
	"errors"
	"time"
)

type transferStatus uint64

const (
	transferCreated transferStatus = iota + 1
	transferSourceUploading
	transferSourceReady
	transferOffered
	transferAccepted
	transferTransferring
	transferCompleted
	transferExpired
	transferCancelled
	transferRevoked
)

func (s transferStatus) terminal() bool {
	return s == transferCompleted || s == transferExpired || s == transferCancelled || s == transferRevoked
}

type transferAction uint64

const (
	transferActionSourceInit transferAction = iota + 1
	transferActionSourceReady
	transferActionOffer
	transferActionAccept
	transferActionBegin
	transferActionComplete
	transferActionExpire
	transferActionCancel
	transferActionRevoke
)

type transferRecord struct {
	TransferID         [16]byte
	ManifestCommitment [32]byte
	Status             transferStatus
	AttemptGeneration  uint64
	ExpiresAt          int64
}

// transitionProof may only be created by the source/receipt stores after
// they have verified every immutable chunk in their own transaction.
type transitionProof struct {
	sourceComplete            bool
	receiptComplete           bool
	expectedAttemptGeneration uint64
}

func newTransferRecord(transferID [16]byte, commitment [32]byte, expiresAt int64) transferRecord {
	return transferRecord{TransferID: transferID, ManifestCommitment: commitment, Status: transferCreated, ExpiresAt: expiresAt}
}

func (r transferRecord) transition(action transferAction, now time.Time, proof transitionProof) (transferRecord, error) {
	if !validTransferRecord(r) || r.Status.terminal() {
		return transferRecord{}, errors.New("invalid or terminal transfer")
	}
	seconds := now.UTC().Unix()
	if seconds < 0 {
		return transferRecord{}, errors.New("invalid transition time")
	}
	if action == transferActionExpire {
		if seconds < r.ExpiresAt {
			return transferRecord{}, errors.New("transfer has not expired")
		}
		r.Status = transferExpired
		return r, nil
	}
	if seconds >= r.ExpiresAt {
		return transferRecord{}, errors.New("transfer expired")
	}
	if action == transferActionCancel || action == transferActionRevoke {
		r.Status = map[transferAction]transferStatus{transferActionCancel: transferCancelled, transferActionRevoke: transferRevoked}[action]
		return r, nil
	}
	switch action {
	case transferActionSourceInit:
		if r.Status == transferCreated {
			r.Status = transferSourceUploading
			return r, nil
		}
	case transferActionSourceReady:
		if r.Status == transferSourceUploading && proof.sourceComplete {
			r.Status = transferSourceReady
			return r, nil
		}
	case transferActionOffer:
		if r.Status == transferSourceReady {
			r.Status = transferOffered
			return r, nil
		}
	case transferActionAccept:
		if r.Status == transferOffered {
			r.Status = transferAccepted
			return r, nil
		}
	case transferActionBegin:
		if r.Status == transferAccepted && r.AttemptGeneration == 0 && proof.expectedAttemptGeneration == 0 {
			r.Status, r.AttemptGeneration = transferTransferring, 1
			return r, nil
		}
	case transferActionComplete:
		if r.Status == transferTransferring && r.AttemptGeneration == 1 && proof.receiptComplete && proof.expectedAttemptGeneration == r.AttemptGeneration {
			r.Status = transferCompleted
			return r, nil
		}
	}
	return transferRecord{}, errors.New("invalid transfer transition")
}

func validTransferRecord(r transferRecord) bool {
	if r.TransferID == [16]byte{} || r.ManifestCommitment == [32]byte{} || r.ExpiresAt <= 0 || r.Status < transferCreated || r.Status > transferRevoked || r.AttemptGeneration > 1 {
		return false
	}
	switch r.Status {
	case transferCreated, transferSourceUploading, transferSourceReady, transferOffered, transferAccepted:
		return r.AttemptGeneration == 0
	case transferTransferring, transferCompleted:
		return r.AttemptGeneration == 1
	case transferExpired, transferCancelled, transferRevoked:
		return true
	default:
		return false
	}
}
