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
	rawResult, err := w.options.Transport.DoV3Attachment(ctx, "POST", acceptancePath(notice.Manifest.TransferID), notice.AcceptanceNonce[:], permit, operation)
	if err != nil {
		_ = w.options.Journal.markReceiptUncertain(inbound.PunaroMessageID, now)
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

type receiptOutcomeRecord struct {
	request                   []byte
	operationID               [16]byte
	idempotencyKey            [32]byte
	permit, operation, result []byte
}

func (j *Journal) storeReceiptOutcomeIntent(messageID string, request []byte, operationID [16]byte, idempotencyKey [32]byte) (receiptOutcomeRecord, error) {
	if j == nil || j.db == nil || messageID == "" || len(request) == 0 || operationID == [16]byte{} || idempotencyKey == [32]byte{} {
		return receiptOutcomeRecord{}, errors.New("invalid receipt outcome intent")
	}
	_, err := j.db.ExecContext(context.Background(), `UPDATE controller_receipt_reconciliation SET outcome_request=?,outcome_operation_id=?,outcome_idempotency_key=? WHERE punaro_message_id=? AND state='uncertain' AND outcome_request IS NULL`, request, operationID[:], idempotencyKey[:], messageID)
	if err != nil {
		return receiptOutcomeRecord{}, err
	}
	return j.receiptOutcome(messageID)
}
func (j *Journal) receiptOutcome(messageID string) (receiptOutcomeRecord, error) {
	var r receiptOutcomeRecord
	var id, key []byte
	err := j.db.QueryRowContext(context.Background(), `SELECT outcome_request,outcome_operation_id,outcome_idempotency_key,outcome_permit,outcome_operation,outcome_result FROM controller_receipt_reconciliation WHERE punaro_message_id=? AND state='uncertain'`, messageID).Scan(&r.request, &id, &key, &r.permit, &r.operation, &r.result)
	if err != nil || len(r.request) == 0 || len(id) != 16 || len(key) != 32 {
		return r, errors.New("invalid receipt outcome record")
	}
	copy(r.operationID[:], id)
	copy(r.idempotencyKey[:], key)
	return r, nil
}
func (j *Journal) storeReceiptOutcomeCredentials(messageID string, permit, operation []byte) (receiptOutcomeRecord, error) {
	if len(permit) == 0 || len(operation) == 0 {
		return receiptOutcomeRecord{}, errors.New("invalid receipt outcome credentials")
	}
	_, err := j.db.ExecContext(context.Background(), `UPDATE controller_receipt_reconciliation SET outcome_permit=?,outcome_operation=? WHERE punaro_message_id=? AND state='uncertain' AND outcome_permit IS NULL AND outcome_operation IS NULL`, permit, operation, messageID)
	if err != nil {
		return receiptOutcomeRecord{}, err
	}
	return j.receiptOutcome(messageID)
}
func (j *Journal) storeReceiptOutcomeResult(messageID string, result []byte) (receiptOutcomeRecord, error) {
	if len(result) == 0 {
		return receiptOutcomeRecord{}, errors.New("invalid receipt outcome result")
	}
	_, err := j.db.ExecContext(context.Background(), `UPDATE controller_receipt_reconciliation SET outcome_result=? WHERE punaro_message_id=? AND state='uncertain' AND outcome_result IS NULL`, result, messageID)
	if err != nil {
		return receiptOutcomeRecord{}, err
	}
	return j.receiptOutcome(messageID)
}

// reconcileExpiredAcceptance is the only path that may proceed after an
// accepted operation's short-lived permit has expired. It asks the relay for
// the durable lifecycle outcome; it never emits another accept operation.
func (w *RecipientAcceptanceWorker) reconcileExpiredAcceptance(ctx context.Context, messageID string, record receiptAcceptanceRecord, authority RecipientAcceptanceAuthority, now time.Time) (attachmentv3.TransferResult, error) {
	terminal := func() (attachmentv3.TransferResult, error) {
		_ = w.options.Journal.terminalizeReceiptUncertain(messageID, now)
		return attachmentv3.TransferResult{}, errors.New("recipient acceptance outcome requires operator reconciliation")
	}
	outcome, err := w.options.Journal.receiptOutcome(messageID)
	if err != nil {
		request := record.request
		requestID, err := w.options.NewID()
		if err != nil || requestID == [16]byte{} {
			return terminal()
		}
		opID, err := w.options.NewID()
		if err != nil || opID == [16]byte{} {
			return terminal()
		}
		key, err := w.options.NewIdempotencyKey()
		if err != nil || key == [32]byte{} {
			return terminal()
		}
		request.RequestID, request.Operation, request.AttemptGeneration = requestID, attachmentv3.PermitOperationOutcome, 0
		request.IssuedAt, request.ExpiresAt = uint64(now.Unix()), uint64(now.Add(20*time.Second).Unix())
		if err := w.options.Signer.SignOutcomePermit(&request); err != nil {
			return terminal()
		}
		raw, err := attachmentv3.EncodePermitRequest(request)
		if err != nil {
			return terminal()
		}
		outcome, err = w.options.Journal.storeReceiptOutcomeIntent(messageID, raw, opID, key)
		if err != nil {
			return terminal()
		}
	}
	request, err := attachmentv3.DecodePermitRequest(outcome.request)
	if err != nil {
		return terminal()
	}
	if len(outcome.permit) == 0 || len(outcome.operation) == 0 {
		permit, err := w.options.Transport.IssueV3Permit(ctx, request)
		if err != nil || attachmentv3.VerifyPermit(permit, authority, now) != nil || permit.Operation != attachmentv3.PermitOperationOutcome {
			return terminal()
		}
		op, err := w.options.Signer.BuildOutcomeOperation(permit, "GET", outcomePath(permit.TransferID), outcome.operationID, outcome.idempotencyKey, permit.IssuedAt, permit.ExpiresAt)
		if err != nil {
			return terminal()
		}
		rawPermit, err := attachmentv3.EncodePermit(permit)
		if err != nil {
			return terminal()
		}
		rawOp, err := attachmentv3.EncodeOperation(op)
		if err != nil {
			return terminal()
		}
		outcome, err = w.options.Journal.storeReceiptOutcomeCredentials(messageID, rawPermit, rawOp)
		if err != nil {
			return terminal()
		}
	}
	permit, err := attachmentv3.DecodePermit(outcome.permit)
	if err != nil || attachmentv3.VerifyPermit(permit, authority, now) != nil {
		return terminal()
	}
	op, err := attachmentv3.DecodeOperation(outcome.operation)
	if err != nil {
		return terminal()
	}
	route, requestOp, err := attachmentv3.NewAttachmentOperationRequest("GET", outcomePath(permit.TransferID), nil, nil)
	if err != nil {
		return terminal()
	}
	if _, _, err := attachmentv3.VerifyAttachmentOperationRequest(op, permit, authority, route, requestOp, now); err != nil {
		return terminal()
	}
	raw, err := w.options.Transport.DoV3Attachment(ctx, "GET", outcomePath(permit.TransferID), nil, permit, op)
	if err != nil {
		return terminal()
	}
	outcome, err = w.options.Journal.storeReceiptOutcomeResult(messageID, raw)
	if err != nil {
		return terminal()
	}
	result, err := attachmentv3.DecodeTransferResult(outcome.result)
	if err != nil || result.TransferID != record.transferID || result.ManifestCommitment != record.manifestCommitment || result.State != attachmentv3.TransferStateAccepted {
		return terminal()
	}
	if err := w.options.Journal.storeReceiptAcceptanceResult(messageID, outcome.result); err != nil {
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
