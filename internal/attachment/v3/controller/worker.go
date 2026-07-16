package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"time"

	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
	"github.com/zeebo/blake3"
)

// RecipientAttachmentTransport is the controller-owned, machine-authenticated
// v3 transport. It is deliberately not exposed by the agent command: callers
// receive a lifecycle result, never a permit or an operation capability.
type RecipientAttachmentTransport interface {
	IssueV3Permit(context.Context, attachmentv3.PermitRequest) (attachmentv3.Permit, error)
	DoV3Attachment(context.Context, string, string, []byte, attachmentv3.Permit, attachmentv3.OperationRecord) ([]byte, error)
}

// RecipientAcceptanceAuthority is one root-verified directory snapshot for a
// single Accept attempt. Splitting any of these checks across independently
// refreshed views would let an offer, permit, and holder signature refer to
// incompatible authority facts.
type RecipientAcceptanceAuthority interface {
	TransferBindingResolver
	attachmentv3.EnvelopeDirectoryKeyResolver
	attachmentv3.PermitAuthorityResolver
	attachmentv3.OperationHolderResolver
}
type RecipientAcceptanceAuthorityProvider interface {
	ResolveRecipientAcceptanceAuthority(context.Context, time.Time) (RecipientAcceptanceAuthority, error)
}

// RecipientOperationSigner keeps the enrolled recipient signing key behind a
// narrow operation-specific interface. It must reject every non-recipient
// request rather than acting as a general-purpose signing oracle.
type RecipientOperationSigner interface {
	SignReceiptPermit(*attachmentv3.PermitRequest) error
	BuildReceiptOperation(attachmentv3.Permit, string, string, []byte, [16]byte, [32]byte, uint64, uint64) (attachmentv3.OperationRecord, error)
	SignOutcomePermit(*attachmentv3.PermitRequest) error
	BuildOutcomeOperation(attachmentv3.Permit, string, string, [16]byte, [32]byte, uint64, uint64) (attachmentv3.OperationRecord, error)
}

type localRecipientOperationSigner struct {
	recipient RecipientIdentity
	private   ed25519.PrivateKey
}

// NewLocalRecipientOperationSigner creates the private key-owning signer used
// by a local privileged worker. The key remains in process and is never
// accepted from a mailbox body or emitted through this package's CLI.
func NewLocalRecipientOperationSigner(recipient RecipientIdentity, private ed25519.PrivateKey) RecipientOperationSigner {
	return &localRecipientOperationSigner{recipient: recipient, private: append(ed25519.PrivateKey(nil), private...)}
}

func (s *localRecipientOperationSigner) SignReceiptPermit(request *attachmentv3.PermitRequest) error {
	if s == nil || !s.recipient.valid() || request == nil || len(s.private) != ed25519.PrivateKeySize || request.HolderDeviceID != s.recipient.DeviceID || request.HolderGeneration != s.recipient.Generation || request.HolderRole != attachmentv3.PermitHolderRecipient || request.Operation != attachmentv3.PermitOperationAccept || request.AttemptGeneration != 0 {
		return errors.New("invalid local recipient acceptance signing request")
	}
	return attachmentv3.SignPermitRequest(request, s.private)
}

func (s *localRecipientOperationSigner) BuildReceiptOperation(permit attachmentv3.Permit, method, path string, body []byte, operationID [16]byte, idempotencyKey [32]byte, issuedAt, expiresAt uint64) (attachmentv3.OperationRecord, error) {
	if s == nil || !s.recipient.valid() || len(s.private) != ed25519.PrivateKeySize || permit.HolderDeviceID != s.recipient.DeviceID || permit.HolderGeneration != s.recipient.Generation || permit.HolderRole != attachmentv3.PermitHolderRecipient || permit.Operation != attachmentv3.PermitOperationAccept || permit.AttemptGeneration != 0 {
		return attachmentv3.OperationRecord{}, errors.New("invalid local recipient acceptance operation")
	}
	return attachmentv3.BuildSignedAttachmentOperation(permit, method, path, body, operationID, idempotencyKey, issuedAt, expiresAt, s.private)
}

func (s *localRecipientOperationSigner) SignOutcomePermit(request *attachmentv3.PermitRequest) error {
	if s == nil || !s.recipient.valid() || request == nil || len(s.private) != ed25519.PrivateKeySize || request.HolderDeviceID != s.recipient.DeviceID || request.HolderGeneration != s.recipient.Generation || request.HolderRole != attachmentv3.PermitHolderRecipient || request.Operation != attachmentv3.PermitOperationOutcome || request.AttemptGeneration != 0 {
		return errors.New("invalid local recipient outcome signing request")
	}
	return attachmentv3.SignPermitRequest(request, s.private)
}

func (s *localRecipientOperationSigner) BuildOutcomeOperation(permit attachmentv3.Permit, method, path string, operationID [16]byte, idempotencyKey [32]byte, issuedAt, expiresAt uint64) (attachmentv3.OperationRecord, error) {
	if s == nil || !s.recipient.valid() || len(s.private) != ed25519.PrivateKeySize || permit.HolderDeviceID != s.recipient.DeviceID || permit.HolderGeneration != s.recipient.Generation || permit.HolderRole != attachmentv3.PermitHolderRecipient || permit.Operation != attachmentv3.PermitOperationOutcome || permit.AttemptGeneration != 0 {
		return attachmentv3.OperationRecord{}, errors.New("invalid local recipient outcome operation")
	}
	return attachmentv3.BuildSignedAttachmentOperation(permit, method, path, nil, operationID, idempotencyKey, issuedAt, expiresAt, s.private)
}

type RecipientAcceptanceWorkerOptions struct {
	Journal           *Journal
	AuthorityProvider RecipientAcceptanceAuthorityProvider
	Signer            RecipientOperationSigner
	Transport         RecipientAttachmentTransport
	Now               func() time.Time
	NewID             func() ([16]byte, error)
	NewIdempotencyKey func() ([32]byte, error)
}

// RecipientAcceptanceWorker owns the first live recipient state transition:
// a locally approved, freshly verified offer becomes one durable accept
// operation. It cannot fetch/decrypt bytes or select an output path.
type RecipientAcceptanceWorker struct {
	options RecipientAcceptanceWorkerOptions
}

func NewRecipientAcceptanceWorker(options RecipientAcceptanceWorkerOptions) (*RecipientAcceptanceWorker, error) {
	if options.Journal == nil || options.Journal.db == nil || !options.Journal.recipient.valid() || options.AuthorityProvider == nil || options.Signer == nil || options.Transport == nil || options.NewID == nil || options.NewIdempotencyKey == nil {
		return nil, errors.New("invalid recipient acceptance worker")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &RecipientAcceptanceWorker{options: options}, nil
}

// Accept performs the v3 accept transition at most once per recorded mailbox
// offer. Every retry rechecks approval, the exact current mapping, and the
// signed offer. It persists the immutable request, permit, and operation
// before its remote use, so a crash retries the same capability rather than
// creating a second acceptance.
func (w *RecipientAcceptanceWorker) Accept(ctx context.Context, inbound InboundOffer) (attachmentv3.TransferResult, error) {
	if w == nil {
		return attachmentv3.TransferResult{}, errors.New("recipient acceptance worker is unavailable")
	}
	// This controller journal is deliberately single-writer. The mutex keeps
	// concurrent local callers from issuing/using the same exact operation in
	// parallel; cross-process retries remain safe because the database stores
	// the request, permit, operation ID, and idempotency key immutably.
	w.options.Journal.acceptMu.Lock()
	defer w.options.Journal.acceptMu.Unlock()
	now := w.options.Now().UTC()
	if now.Unix() < 0 {
		return attachmentv3.TransferResult{}, errors.New("invalid recipient acceptance clock")
	}
	state, foundReconciliation, err := w.options.Journal.receiptReconciliation(inbound.PunaroMessageID)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	} else if foundReconciliation && state == receiptStateTerminal {
		return attachmentv3.TransferResult{}, errors.New("recipient acceptance requires operator reconciliation")
	}
	authority, err := w.options.AuthorityProvider.ResolveRecipientAcceptanceAuthority(ctx, now)
	if err != nil || authority == nil {
		return attachmentv3.TransferResult{}, errors.New("fresh recipient acceptance authority is unavailable")
	}
	if foundReconciliation && state == receiptStateUncertain {
		record, found, err := w.options.Journal.receiptAcceptance(inbound.PunaroMessageID)
		if err != nil || !found {
			return attachmentv3.TransferResult{}, errors.New("uncertain recipient acceptance record is unavailable")
		}
		if permit, err := attachmentv3.DecodePermit(record.permit); err == nil && permit.ExpiresAt <= uint64(now.Unix()) {
			return w.reconcileExpiredAcceptance(ctx, inbound.PunaroMessageID, record, authority, now)
		}
	}
	notice, err := w.options.Journal.PrepareApprovedReceipt(ctx, inbound, authority, authority, now)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	mapping, found, err := w.options.Journal.mapping(inbound.RelayConversationID)
	if err != nil || !found || mapping.RecipientDeviceID != w.options.Journal.recipient.DeviceID || mapping.RecipientGeneration != w.options.Journal.recipient.Generation {
		return attachmentv3.TransferResult{}, errors.New("recipient acceptance mapping is unavailable")
	}
	commitment := blake3.Sum256(notice.ManifestRaw)
	record, err := w.options.Journal.ensureReceiptAcceptance(inbound.PunaroMessageID, notice, mapping, now, w.options.Signer, w.options.NewID, w.options.NewIdempotencyKey)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	if len(record.result) != 0 {
		return exactAcceptedResult(record.result, notice.Manifest.TransferID, commitment)
	}
	permit, operation, err := w.acceptanceCredentials(ctx, record, authority, now)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	// Persist the ambiguity boundary before the irreversible remote state
	// transition. A process death after the relay accepts this operation must
	// still enter outcome reconciliation after the short-lived permit expires.
	if err := w.options.Journal.markReceiptUncertain(inbound.PunaroMessageID, now); err != nil {
		return attachmentv3.TransferResult{}, err
	}
	rawResult, err := w.options.Transport.DoV3Attachment(ctx, "POST", acceptancePath(notice.Manifest.TransferID), notice.AcceptanceNonce[:], permit, operation)
	if err != nil {
		return attachmentv3.TransferResult{}, fmt.Errorf("submit recipient acceptance: %w", err)
	}
	result, err := exactAcceptedResult(rawResult, notice.Manifest.TransferID, commitment)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	if err := w.options.Journal.storeReceiptAcceptanceResult(inbound.PunaroMessageID, rawResult); err != nil {
		return attachmentv3.TransferResult{}, err
	}
	return result, nil
}

func (j *Journal) markReceiptUncertain(messageID string, now time.Time) error {
	if j == nil || j.db == nil || messageID == "" || now.UTC().Unix() < 0 {
		return errors.New("invalid recipient reconciliation state")
	}
	_, err := j.db.ExecContext(context.Background(), `INSERT INTO controller_receipt_reconciliation(punaro_message_id,state,uncertain_at) VALUES (?, 'uncertain', ?) ON CONFLICT(punaro_message_id) DO NOTHING`, messageID, now.UTC().Unix())
	return err
}

type receiptReconciliationState string

const (
	receiptStateUncertain receiptReconciliationState = "uncertain"
	receiptStateTerminal  receiptReconciliationState = "terminal_uncertain"
)

func (j *Journal) receiptReconciliation(messageID string) (receiptReconciliationState, bool, error) {
	var state string
	err := j.db.QueryRowContext(context.Background(), `SELECT state FROM controller_receipt_reconciliation WHERE punaro_message_id=?`, messageID).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil || (state != string(receiptStateUncertain) && state != string(receiptStateTerminal)) {
		return "", false, errors.New("invalid recipient reconciliation state")
	}
	return receiptReconciliationState(state), true, nil
}
func (j *Journal) terminalizeReceiptUncertain(messageID string, now time.Time) error {
	if j == nil || j.db == nil || messageID == "" || now.UTC().Unix() < 0 {
		return errors.New("invalid terminal recipient reconciliation")
	}
	r, err := j.db.ExecContext(context.Background(), `UPDATE controller_receipt_reconciliation SET state='terminal_uncertain',terminal_at=? WHERE punaro_message_id=? AND state='uncertain'`, now.UTC().Unix(), messageID)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil || n != 1 {
		return errors.New("recipient reconciliation state transition failed")
	}
	return nil
}

type receiptOutcomeAttempt struct {
	index                     uint64
	request                   []byte
	operationID               [16]byte
	idempotencyKey            [32]byte
	permit, operation, result []byte
}

func (j *Journal) latestReceiptOutcomeAttempt(messageID string) (receiptOutcomeAttempt, bool, error) {
	var r receiptOutcomeAttempt
	var index int64
	var id, key []byte
	err := j.db.QueryRowContext(context.Background(), `SELECT attempt_index,permit_request,operation_id,idempotency_key,permit,operation,result FROM controller_receipt_outcome_attempts WHERE punaro_message_id=? ORDER BY attempt_index DESC LIMIT 1`, messageID).Scan(&index, &r.request, &id, &key, &r.permit, &r.operation, &r.result)
	if errors.Is(err, sql.ErrNoRows) {
		return r, false, nil
	}
	if err != nil || index < 0 || len(r.request) == 0 || len(id) != 16 || len(key) != 32 {
		return r, false, errors.New("invalid receipt outcome attempt")
	}
	r.index = uint64(index)
	copy(r.operationID[:], id)
	copy(r.idempotencyKey[:], key)
	return r, true, nil
}

func (j *Journal) storeReceiptOutcomeAttempt(messageID string, attempt receiptOutcomeAttempt) (receiptOutcomeAttempt, error) {
	if j == nil || j.db == nil || messageID == "" || len(attempt.request) == 0 || attempt.operationID == [16]byte{} || attempt.idempotencyKey == [32]byte{} || attempt.index > uint64(^uint(0)>>1) {
		return receiptOutcomeAttempt{}, errors.New("invalid receipt outcome attempt")
	}
	_, err := j.db.ExecContext(context.Background(), `INSERT INTO controller_receipt_outcome_attempts(punaro_message_id,attempt_index,permit_request,operation_id,idempotency_key) SELECT ?,?,?,?,? WHERE EXISTS (SELECT 1 FROM controller_receipt_reconciliation WHERE punaro_message_id=? AND state='uncertain') ON CONFLICT(punaro_message_id,attempt_index) DO NOTHING`, messageID, int64(attempt.index), attempt.request, attempt.operationID[:], attempt.idempotencyKey[:], messageID)
	if err != nil {
		return receiptOutcomeAttempt{}, err
	}
	stored, found, err := j.latestReceiptOutcomeAttempt(messageID)
	if err != nil || !found || stored.index != attempt.index || !bytes.Equal(stored.request, attempt.request) || stored.operationID != attempt.operationID || stored.idempotencyKey != attempt.idempotencyKey {
		return receiptOutcomeAttempt{}, errors.New("changed receipt outcome attempt")
	}
	return stored, nil
}

func (j *Journal) storeReceiptOutcomeAttemptCredentials(messageID string, index uint64, permit, operation []byte) (receiptOutcomeAttempt, error) {
	if len(permit) == 0 || len(operation) == 0 || index > uint64(^uint(0)>>1) {
		return receiptOutcomeAttempt{}, errors.New("invalid receipt outcome credentials")
	}
	_, err := j.db.ExecContext(context.Background(), `UPDATE controller_receipt_outcome_attempts SET permit=?,operation=? WHERE punaro_message_id=? AND attempt_index=? AND permit IS NULL AND operation IS NULL`, permit, operation, messageID, int64(index))
	if err != nil {
		return receiptOutcomeAttempt{}, err
	}
	stored, found, err := j.latestReceiptOutcomeAttempt(messageID)
	if err != nil || !found || stored.index != index || len(stored.permit) == 0 || len(stored.operation) == 0 {
		return receiptOutcomeAttempt{}, errors.New("missing receipt outcome credentials")
	}
	return stored, nil
}

func (j *Journal) storeReceiptOutcomeAttemptResult(messageID string, index uint64, result []byte) (receiptOutcomeAttempt, error) {
	if len(result) == 0 || index > uint64(^uint(0)>>1) {
		return receiptOutcomeAttempt{}, errors.New("invalid receipt outcome result")
	}
	_, err := j.db.ExecContext(context.Background(), `UPDATE controller_receipt_outcome_attempts SET result=? WHERE punaro_message_id=? AND attempt_index=? AND result IS NULL`, result, messageID, int64(index))
	if err != nil {
		return receiptOutcomeAttempt{}, err
	}
	stored, found, err := j.latestReceiptOutcomeAttempt(messageID)
	if err != nil || !found || stored.index != index || len(stored.result) == 0 {
		return receiptOutcomeAttempt{}, errors.New("missing receipt outcome result")
	}
	return stored, nil
}

// reconcileExpiredAcceptance is the only path that may proceed after an
// accepted operation's short-lived permit has expired. It asks the relay for
// the durable lifecycle outcome; it never emits another accept operation.
func (w *RecipientAcceptanceWorker) reconcileExpiredAcceptance(ctx context.Context, messageID string, record receiptAcceptanceRecord, authority RecipientAcceptanceAuthority, now time.Time) (attachmentv3.TransferResult, error) {
	terminal := func() (attachmentv3.TransferResult, error) {
		_ = w.options.Journal.terminalizeReceiptUncertain(messageID, now)
		return attachmentv3.TransferResult{}, errors.New("recipient acceptance outcome requires operator reconciliation")
	}
	outcome, found, err := w.options.Journal.latestReceiptOutcomeAttempt(messageID)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	if found && len(outcome.result) != 0 {
		return w.finishReceiptOutcome(messageID, record, outcome.result, now, terminal)
	}
	// A capability is one-use only for its short lifetime. Retain every old
	// attempt for audit, but create a new one after expiry so a client crash or
	// a transient GET failure cannot strand the recipient permanently.
	if !found || outcomeAttemptExpired(outcome, now) {
		outcome, err = w.newReceiptOutcomeAttempt(messageID, record, outcome, found, now)
		if err != nil {
			return attachmentv3.TransferResult{}, err
		}
	}
	request, err := attachmentv3.DecodePermitRequest(outcome.request)
	if err != nil || !exactOutcomeRequest(request, record, now) {
		return attachmentv3.TransferResult{}, errors.New("invalid durable recipient outcome request")
	}
	if len(outcome.permit) == 0 || len(outcome.operation) == 0 {
		permit, err := w.options.Transport.IssueV3Permit(ctx, request)
		if err != nil || !exactOutcomePermit(permit, request, record, now) || attachmentv3.VerifyPermit(permit, authority, now) != nil {
			return attachmentv3.TransferResult{}, errors.New("recipient outcome permit is unavailable")
		}
		op, err := w.options.Signer.BuildOutcomeOperation(permit, "GET", outcomePath(record.transferID), outcome.operationID, outcome.idempotencyKey, permit.IssuedAt, permit.ExpiresAt)
		if err != nil {
			return attachmentv3.TransferResult{}, err
		}
		rawPermit, err := attachmentv3.EncodePermit(permit)
		if err != nil {
			return attachmentv3.TransferResult{}, err
		}
		rawOp, err := attachmentv3.EncodeOperation(op)
		if err != nil {
			return attachmentv3.TransferResult{}, err
		}
		outcome, err = w.options.Journal.storeReceiptOutcomeAttemptCredentials(messageID, outcome.index, rawPermit, rawOp)
		if err != nil {
			return attachmentv3.TransferResult{}, err
		}
	}
	permit, err := attachmentv3.DecodePermit(outcome.permit)
	if err != nil || !exactOutcomePermit(permit, request, record, now) || attachmentv3.VerifyPermit(permit, authority, now) != nil {
		return attachmentv3.TransferResult{}, errors.New("invalid durable recipient outcome permit")
	}
	op, err := attachmentv3.DecodeOperation(outcome.operation)
	if err != nil {
		return attachmentv3.TransferResult{}, errors.New("invalid durable recipient outcome operation")
	}
	route, requestOp, err := attachmentv3.NewAttachmentOperationRequest("GET", outcomePath(record.transferID), nil, nil)
	if err != nil || op.OperationID != outcome.operationID || op.IdempotencyKey != outcome.idempotencyKey {
		return attachmentv3.TransferResult{}, errors.New("invalid durable recipient outcome operation")
	}
	if _, _, err := attachmentv3.VerifyAttachmentOperationRequest(op, permit, authority, route, requestOp, now); err != nil {
		return attachmentv3.TransferResult{}, errors.New("invalid durable recipient outcome operation")
	}
	raw, err := w.options.Transport.DoV3Attachment(ctx, "GET", outcomePath(record.transferID), nil, permit, op)
	if err != nil {
		// Do not terminalize: the remote GET may have succeeded just before this
		// transport error. The durable attempt will be retried while valid, or a
		// fresh attempt will be used after it expires.
		return attachmentv3.TransferResult{}, fmt.Errorf("query recipient acceptance outcome: %w", err)
	}
	outcome, err = w.options.Journal.storeReceiptOutcomeAttemptResult(messageID, outcome.index, raw)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	return w.finishReceiptOutcome(messageID, record, outcome.result, now, terminal)
}

func (w *RecipientAcceptanceWorker) newReceiptOutcomeAttempt(messageID string, record receiptAcceptanceRecord, previous receiptOutcomeAttempt, found bool, now time.Time) (receiptOutcomeAttempt, error) {
	if now.Unix() < 0 || (found && previous.index == ^uint64(0)) {
		return receiptOutcomeAttempt{}, errors.New("cannot create recipient outcome attempt")
	}
	requestID, err := w.options.NewID()
	if err != nil || requestID == [16]byte{} {
		return receiptOutcomeAttempt{}, errors.New("generate recipient outcome request identity")
	}
	opID, err := w.options.NewID()
	if err != nil || opID == [16]byte{} {
		return receiptOutcomeAttempt{}, errors.New("generate recipient outcome operation identity")
	}
	key, err := w.options.NewIdempotencyKey()
	if err != nil || key == [32]byte{} {
		return receiptOutcomeAttempt{}, errors.New("generate recipient outcome idempotency identity")
	}
	original, err := attachmentv3.DecodePermit(record.permit)
	if err != nil || original.Operation != attachmentv3.PermitOperationAccept || original.Serial == [16]byte{} {
		return receiptOutcomeAttempt{}, errors.New("invalid durable recipient acceptance permit for outcome")
	}
	request := record.request
	request.RequestID, request.Operation, request.AttemptGeneration = requestID, attachmentv3.PermitOperationOutcome, 0
	request.OutcomeOfSerial = original.Serial
	request.IssuedAt, request.ExpiresAt = uint64(now.Unix()), uint64(now.Add(20*time.Second).Unix())
	if err := w.options.Signer.SignOutcomePermit(&request); err != nil {
		return receiptOutcomeAttempt{}, err
	}
	raw, err := attachmentv3.EncodePermitRequest(request)
	if err != nil {
		return receiptOutcomeAttempt{}, err
	}
	index := uint64(0)
	if found {
		index = previous.index + 1
	}
	return w.options.Journal.storeReceiptOutcomeAttempt(messageID, receiptOutcomeAttempt{index: index, request: raw, operationID: opID, idempotencyKey: key})
}

func outcomeAttemptExpired(outcome receiptOutcomeAttempt, now time.Time) bool {
	request, err := attachmentv3.DecodePermitRequest(outcome.request)
	if err != nil || now.Unix() < 0 {
		return true
	}
	if len(outcome.permit) != 0 {
		permit, err := attachmentv3.DecodePermit(outcome.permit)
		return err != nil || permit.ExpiresAt <= uint64(now.Unix())
	}
	return request.ExpiresAt <= uint64(now.Unix())
}

func (w *RecipientAcceptanceWorker) finishReceiptOutcome(messageID string, record receiptAcceptanceRecord, raw []byte, now time.Time, terminal func() (attachmentv3.TransferResult, error)) (attachmentv3.TransferResult, error) {
	result, err := attachmentv3.DecodeTransferResult(raw)
	if err != nil || result.TransferID != record.transferID || result.ManifestCommitment != record.manifestCommitment || result.State != attachmentv3.TransferStateAccepted || result.AttemptGeneration != 0 {
		return terminal()
	}
	if err := w.options.Journal.storeReceiptAcceptanceResult(messageID, raw); err != nil {
		return terminal()
	}
	return result, nil
}

func outcomePath(transfer [16]byte) string {
	return fmt.Sprintf("/v3/attachments/%x/outcome", transfer)
}

func (w *RecipientAcceptanceWorker) acceptanceCredentials(ctx context.Context, record receiptAcceptanceRecord, authority RecipientAcceptanceAuthority, now time.Time) (attachmentv3.Permit, attachmentv3.OperationRecord, error) {
	if len(record.permit) != 0 || len(record.operation) != 0 {
		if len(record.permit) == 0 || len(record.operation) == 0 {
			return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("incomplete durable recipient acceptance credentials")
		}
		permit, err := attachmentv3.DecodePermit(record.permit)
		if err != nil || !exactAcceptancePermit(permit, record.request, record.manifestCommitment, now) || attachmentv3.VerifyPermit(permit, authority, now) != nil {
			return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("invalid durable recipient acceptance permit")
		}
		operation, err := attachmentv3.DecodeOperation(record.operation)
		if err != nil || operation.OperationID != record.operationID || operation.IdempotencyKey != record.idempotencyKey || verifyAcceptanceOperation(operation, permit, record.acceptanceNonce, authority, now) != nil {
			return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("invalid durable recipient acceptance operation")
		}
		return permit, operation, nil
	}
	permit, err := w.options.Transport.IssueV3Permit(ctx, record.request)
	if err != nil || !exactAcceptancePermit(permit, record.request, record.manifestCommitment, now) || attachmentv3.VerifyPermit(permit, authority, now) != nil {
		return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("recipient acceptance permit is unavailable")
	}
	issuedAt := uint64(now.Unix())
	if issuedAt < permit.IssuedAt {
		issuedAt = permit.IssuedAt
	}
	operation, err := w.options.Signer.BuildReceiptOperation(permit, "POST", acceptancePath(permit.TransferID), record.acceptanceNonce[:], record.operationID, record.idempotencyKey, issuedAt, permit.ExpiresAt)
	if err != nil {
		return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, err
	}
	if err := verifyAcceptanceOperation(operation, permit, record.acceptanceNonce, authority, now); err != nil {
		return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, err
	}
	stored, err := w.options.Journal.storeReceiptAcceptanceCredentials(record.messageID, permit, operation)
	if err != nil {
		return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, err
	}
	permit, err = attachmentv3.DecodePermit(stored.permit)
	if err != nil || !exactAcceptancePermit(permit, record.request, record.manifestCommitment, now) || attachmentv3.VerifyPermit(permit, authority, now) != nil {
		return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("invalid stored recipient acceptance permit")
	}
	operation, err = attachmentv3.DecodeOperation(stored.operation)
	if err != nil || operation.OperationID != record.operationID || operation.IdempotencyKey != record.idempotencyKey || verifyAcceptanceOperation(operation, permit, record.acceptanceNonce, authority, now) != nil {
		return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("invalid stored recipient acceptance operation")
	}
	return permit, operation, nil
}

func verifyAcceptanceOperation(operation attachmentv3.OperationRecord, permit attachmentv3.Permit, nonce [32]byte, authority RecipientAcceptanceAuthority, now time.Time) error {
	path := acceptancePath(permit.TransferID)
	route, request, err := attachmentv3.NewAttachmentOperationRequest("POST", path, nonce[:], nil)
	if err != nil {
		return errors.New("invalid recipient acceptance operation")
	}
	if _, _, err := attachmentv3.VerifyAttachmentOperationRequest(operation, permit, authority, route, request, now); err != nil {
		return errors.New("invalid recipient acceptance operation")
	}
	return nil
}

type receiptAcceptanceRecord struct {
	messageID          string
	transferID         [16]byte
	manifestCommitment [32]byte
	acceptanceNonce    [32]byte
	request            attachmentv3.PermitRequest
	operationID        [16]byte
	idempotencyKey     [32]byte
	permit, operation  []byte
	result             []byte
}

func (j *Journal) ensureReceiptAcceptance(messageID string, notice attachmentv3.OfferNotice, mapping Mapping, now time.Time, signer RecipientOperationSigner, newID func() ([16]byte, error), newKey func() ([32]byte, error)) (receiptAcceptanceRecord, error) {
	if j == nil || j.db == nil || signer == nil || !mapping.valid() || messageID == "" {
		return receiptAcceptanceRecord{}, errors.New("invalid recipient acceptance intent")
	}
	if existing, found, err := j.receiptAcceptance(messageID); err != nil || found {
		if err != nil || !found || existing.transferID != notice.Manifest.TransferID || existing.manifestCommitment != blake3.Sum256(notice.ManifestRaw) || existing.acceptanceNonce != notice.AcceptanceNonce {
			return receiptAcceptanceRecord{}, errors.New("changed recipient acceptance intent")
		}
		return existing, nil
	}
	requestID, err := newID()
	if err != nil || requestID == [16]byte{} {
		return receiptAcceptanceRecord{}, errors.New("generate recipient acceptance request identity")
	}
	opID, err := newID()
	if err != nil || opID == [16]byte{} {
		return receiptAcceptanceRecord{}, errors.New("generate recipient acceptance operation identity")
	}
	idempotency, err := newKey()
	if err != nil || idempotency == [32]byte{} {
		return receiptAcceptanceRecord{}, errors.New("generate recipient acceptance idempotency identity")
	}
	expires := now.Add(20 * time.Second).Unix()
	if uint64(expires) > notice.Manifest.ExpiresAt {
		expires = int64(notice.Manifest.ExpiresAt)
	}
	if expires <= now.Unix() {
		return receiptAcceptanceRecord{}, errors.New("expired recipient acceptance offer")
	}
	maxBytes := notice.Manifest.PlaintextSize + notice.Manifest.ChunkCount*16
	if maxBytes == 0 || maxBytes < notice.Manifest.PlaintextSize {
		return receiptAcceptanceRecord{}, errors.New("invalid recipient acceptance size")
	}
	record := receiptAcceptanceRecord{messageID: messageID, transferID: notice.Manifest.TransferID, manifestCommitment: blake3.Sum256(notice.ManifestRaw), acceptanceNonce: notice.AcceptanceNonce, operationID: opID, idempotencyKey: idempotency}
	record.request = attachmentv3.PermitRequest{RequestID: requestID, HolderDeviceID: j.recipient.DeviceID, HolderGeneration: j.recipient.Generation, HolderRole: attachmentv3.PermitHolderRecipient, TransferID: notice.Manifest.TransferID, ConversationID: mapping.ConversationID, SenderDeviceID: mapping.SenderDeviceID, SenderGeneration: mapping.SenderGeneration, RecipientDeviceID: mapping.RecipientDeviceID, RecipientGeneration: mapping.RecipientGeneration, Operation: attachmentv3.PermitOperationAccept, MembershipCommitment: mapping.MembershipCommitment, StagedManifestCommitment: record.manifestCommitment, IssuedAt: uint64(now.Unix()), ExpiresAt: uint64(expires), MaxBytes: maxBytes, MaxChunks: notice.Manifest.ChunkCount, MaxOperations: 1}
	if err := signer.SignReceiptPermit(&record.request); err != nil {
		return receiptAcceptanceRecord{}, err
	}
	rawRequest, err := attachmentv3.EncodePermitRequest(record.request)
	if err != nil {
		return receiptAcceptanceRecord{}, err
	}
	result, err := j.db.ExecContext(context.Background(), `INSERT INTO controller_receipt_acceptances(punaro_message_id, transfer_id, manifest_commitment, acceptance_nonce, permit_request, operation_id, idempotency_key) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(punaro_message_id) DO NOTHING`, messageID, record.transferID[:], record.manifestCommitment[:], record.acceptanceNonce[:], rawRequest, record.operationID[:], record.idempotencyKey[:])
	if err != nil {
		return receiptAcceptanceRecord{}, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return receiptAcceptanceRecord{}, err
	}
	if inserted == 1 {
		return record, nil
	}
	stored, found, err := j.receiptAcceptance(messageID)
	if err != nil || !found || stored.transferID != record.transferID || stored.manifestCommitment != record.manifestCommitment {
		return receiptAcceptanceRecord{}, errors.New("changed recipient acceptance retry")
	}
	return stored, nil
}

func (j *Journal) receiptAcceptance(messageID string) (receiptAcceptanceRecord, bool, error) {
	var record receiptAcceptanceRecord
	var transfer, commitment, nonce, request, operationID, idempotency []byte
	err := j.db.QueryRowContext(context.Background(), `SELECT transfer_id, manifest_commitment, acceptance_nonce, permit_request, operation_id, idempotency_key, permit, operation, result FROM controller_receipt_acceptances WHERE punaro_message_id = ?`, messageID).Scan(&transfer, &commitment, &nonce, &request, &operationID, &idempotency, &record.permit, &record.operation, &record.result)
	if errors.Is(err, sql.ErrNoRows) {
		return receiptAcceptanceRecord{}, false, nil
	}
	if err != nil || len(transfer) != 16 || len(commitment) != 32 || len(nonce) != 32 || len(operationID) != 16 || len(idempotency) != 32 {
		return receiptAcceptanceRecord{}, false, errors.New("invalid durable recipient acceptance")
	}
	record.request, err = attachmentv3.DecodePermitRequest(request)
	if err != nil {
		return receiptAcceptanceRecord{}, false, errors.New("invalid durable recipient acceptance request")
	}
	record.messageID = messageID
	copy(record.transferID[:], transfer)
	copy(record.manifestCommitment[:], commitment)
	copy(record.acceptanceNonce[:], nonce)
	copy(record.operationID[:], operationID)
	copy(record.idempotencyKey[:], idempotency)
	return record, true, nil
}

func (j *Journal) storeReceiptAcceptanceCredentials(messageID string, permit attachmentv3.Permit, operation attachmentv3.OperationRecord) (receiptAcceptanceRecord, error) {
	rawPermit, err := attachmentv3.EncodePermit(permit)
	if err != nil {
		return receiptAcceptanceRecord{}, err
	}
	rawOperation, err := attachmentv3.EncodeOperation(operation)
	if err != nil {
		return receiptAcceptanceRecord{}, err
	}
	result, err := j.db.ExecContext(context.Background(), `UPDATE controller_receipt_acceptances SET permit = ?, operation = ? WHERE punaro_message_id = ? AND permit IS NULL AND operation IS NULL`, rawPermit, rawOperation, messageID)
	if err != nil {
		return receiptAcceptanceRecord{}, err
	}
	_, err = result.RowsAffected()
	if err != nil {
		return receiptAcceptanceRecord{}, err
	}
	stored, found, err := j.receiptAcceptance(messageID)
	if err != nil || !found || len(stored.permit) == 0 || len(stored.operation) == 0 {
		return receiptAcceptanceRecord{}, errors.New("missing durable recipient acceptance credentials")
	}
	return stored, nil
}

func (j *Journal) storeReceiptAcceptanceResult(messageID string, raw []byte) error {
	result, err := j.db.ExecContext(context.Background(), `UPDATE controller_receipt_acceptances SET result = ? WHERE punaro_message_id = ? AND result IS NULL`, raw, messageID)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed == 1 {
		return nil
	}
	stored, found, err := j.receiptAcceptance(messageID)
	if err != nil || !found || !bytes.Equal(stored.result, raw) {
		return errors.New("changed durable recipient acceptance result")
	}
	return nil
}

func exactAcceptancePermit(permit attachmentv3.Permit, request attachmentv3.PermitRequest, commitment [32]byte, now time.Time) bool {
	if _, err := attachmentv3.DecodePermit(mustEncodePermit(permit)); err != nil || permit.HolderDeviceID != request.HolderDeviceID || permit.HolderGeneration != request.HolderGeneration || permit.HolderRole != attachmentv3.PermitHolderRecipient || permit.TransferID != request.TransferID || permit.ConversationID != request.ConversationID || permit.SenderDeviceID != request.SenderDeviceID || permit.SenderGeneration != request.SenderGeneration || permit.RecipientDeviceID != request.RecipientDeviceID || permit.RecipientGeneration != request.RecipientGeneration || permit.AttemptGeneration != 0 || permit.Operation != attachmentv3.PermitOperationAccept || permit.MembershipCommitment != request.MembershipCommitment || permit.StagedManifestCommitment != commitment || permit.MaxBytes != request.MaxBytes || permit.MaxChunks != request.MaxChunks || permit.MaxOperations != 1 {
		return false
	}
	return now.Unix() >= 0 && permit.IssuedAt <= uint64(now.Unix()) && permit.ExpiresAt > uint64(now.Unix())
}

// exactOutcomeRequest and exactOutcomePermit bind a reconciliation lookup to
// the immutable acceptance record, not merely to whatever capability happened
// to be returned by the permit service. In particular, a valid recipient
// outcome permit for another transfer or conversation must never reach the
// transport layer.
func exactOutcomeRequest(request attachmentv3.PermitRequest, record receiptAcceptanceRecord, now time.Time) bool {
	original, err := attachmentv3.DecodePermit(record.permit)
	if err != nil || original.Operation != attachmentv3.PermitOperationAccept || request.OutcomeOfSerial != original.Serial || now.Unix() < 0 || request.RequestID == [16]byte{} || request.HolderDeviceID != record.request.HolderDeviceID || request.HolderGeneration != record.request.HolderGeneration || request.HolderRole != attachmentv3.PermitHolderRecipient || request.TransferID != record.transferID || request.ConversationID != record.request.ConversationID || request.SenderDeviceID != record.request.SenderDeviceID || request.SenderGeneration != record.request.SenderGeneration || request.RecipientDeviceID != record.request.RecipientDeviceID || request.RecipientGeneration != record.request.RecipientGeneration || request.AttemptGeneration != 0 || request.Operation != attachmentv3.PermitOperationOutcome || request.MembershipCommitment != record.request.MembershipCommitment || request.StagedManifestCommitment != record.manifestCommitment || request.MaxBytes != record.request.MaxBytes || request.MaxChunks != record.request.MaxChunks || request.MaxOperations != 1 {
		return false
	}
	return request.IssuedAt <= uint64(now.Unix()) && request.ExpiresAt > uint64(now.Unix())
}

func exactOutcomePermit(permit attachmentv3.Permit, request attachmentv3.PermitRequest, record receiptAcceptanceRecord, now time.Time) bool {
	if !exactOutcomeRequest(request, record, now) {
		return false
	}
	if _, err := attachmentv3.DecodePermit(mustEncodePermit(permit)); err != nil {
		return false
	}
	if permit.HolderDeviceID != request.HolderDeviceID || permit.HolderGeneration != request.HolderGeneration || permit.HolderRole != attachmentv3.PermitHolderRecipient || permit.TransferID != record.transferID || permit.ConversationID != request.ConversationID || permit.SenderDeviceID != request.SenderDeviceID || permit.SenderGeneration != request.SenderGeneration || permit.RecipientDeviceID != request.RecipientDeviceID || permit.RecipientGeneration != request.RecipientGeneration || permit.AttemptGeneration != 0 || permit.Operation != attachmentv3.PermitOperationOutcome || permit.OutcomeOfSerial != request.OutcomeOfSerial || permit.MembershipCommitment != request.MembershipCommitment || permit.StagedManifestCommitment != record.manifestCommitment || permit.MaxBytes != request.MaxBytes || permit.MaxChunks != request.MaxChunks || permit.MaxOperations != 1 {
		return false
	}
	return permit.IssuedAt >= request.IssuedAt && permit.ExpiresAt <= request.ExpiresAt && permit.IssuedAt <= uint64(now.Unix()) && permit.ExpiresAt > uint64(now.Unix())
}
func mustEncodePermit(permit attachmentv3.Permit) []byte {
	raw, err := attachmentv3.EncodePermit(permit)
	if err != nil {
		return nil
	}
	return raw
}
func exactAcceptedResult(raw []byte, transfer [16]byte, commitment [32]byte) (attachmentv3.TransferResult, error) {
	result, err := attachmentv3.DecodeTransferResult(raw)
	if err != nil || result.TransferID != transfer || result.ManifestCommitment != commitment || result.State != attachmentv3.TransferStateAccepted || result.AttemptGeneration != 0 {
		return attachmentv3.TransferResult{}, errors.New("invalid recipient acceptance result")
	}
	return result, nil
}
func acceptancePath(transfer [16]byte) string {
	return fmt.Sprintf("/v3/attachments/%x/accept", transfer)
}
