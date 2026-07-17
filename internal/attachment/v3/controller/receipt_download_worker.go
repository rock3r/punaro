package controller

import (
	"context"
	"crypto/ecdh"
	"errors"
	"fmt"
	"time"

	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
)

var errRecipientDownloadOutcome = errors.New("recipient download requires outcome reconciliation")

// RecipientEnvelopeOpener keeps the recipient HPKE private key behind the
// receipt worker boundary. It accepts only the already verified offer source
// and never returns the key to callers of Receive.
type RecipientEnvelopeOpener interface {
	OpenRecipientEnvelope([]byte, attachmentv3.VerifiedSource, attachmentv3.EnvelopeDirectoryKeyResolver, time.Time) ([32]byte, error)
}

type localRecipientEnvelopeOpener struct{ private *ecdh.PrivateKey }

// NewLocalRecipientEnvelopeOpener returns an opener that keeps the recipient
// HPKE private key within the local privileged worker.
func NewLocalRecipientEnvelopeOpener(private *ecdh.PrivateKey) RecipientEnvelopeOpener {
	return &localRecipientEnvelopeOpener{private: private}
}

func (o *localRecipientEnvelopeOpener) OpenRecipientEnvelope(raw []byte, source attachmentv3.VerifiedSource, directory attachmentv3.EnvelopeDirectoryKeyResolver, now time.Time) ([32]byte, error) {
	if o == nil || o.private == nil {
		return [32]byte{}, errors.New("recipient envelope key is unavailable")
	}
	return attachmentv3.OpenRecipientEnvelope(raw, source, directory, o.private, now)
}

// RecipientDownloadWorkerOptions configures the recipient-side download
// worker and its local authority boundaries.
type RecipientDownloadWorkerOptions struct {
	Acceptance        *RecipientAcceptanceWorker
	AuthorityProvider RecipientAcceptanceAuthorityProvider
	Signer            RecipientDownloadSigner
	Transport         RecipientAttachmentTransport
	EnvelopeOpener    RecipientEnvelopeOpener
	Now               func() time.Time
	NewID             func() ([16]byte, error)
	NewIdempotencyKey func() ([32]byte, error)
}

// RecipientDownloadWorker completes the recipient-controlled half of a v3
// attachment. It first uses the existing approval/acceptance worker, then
// durably commits every begin/download/complete capability before transport.
// Plaintext is emitted only after the relay has completed and all ciphertext
// frames verify through the atomic output boundary.
type RecipientDownloadWorker struct {
	options RecipientDownloadWorkerOptions
}

// NewRecipientDownloadWorker constructs a recipient worker with all required
// approval, authority, signing, transport, and output dependencies.
func NewRecipientDownloadWorker(options RecipientDownloadWorkerOptions) (*RecipientDownloadWorker, error) {
	if options.Acceptance == nil || options.Acceptance.options.Journal == nil || options.AuthorityProvider == nil || options.Signer == nil || options.Transport == nil || options.EnvelopeOpener == nil || options.NewID == nil || options.NewIdempotencyKey == nil {
		return nil, errors.New("invalid recipient download worker")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &RecipientDownloadWorker{options: options}, nil
}

// Receive fetches one explicitly approved offer to an absolute, caller-owned
// destination. The destination becomes immutable in the local journal before
// any network read, and must not be replaced by a later retry.
func (w *RecipientDownloadWorker) Receive(ctx context.Context, inbound InboundOffer, destination string) (attachmentv3.TransferResult, error) {
	if w == nil || destination == "" {
		return attachmentv3.TransferResult{}, errors.New("recipient download worker is unavailable")
	}
	journal := w.options.Acceptance.options.Journal
	journal.receiptMu.Lock()
	defer journal.receiptMu.Unlock()
	now := w.options.Now().UTC()
	if now.Unix() < 0 {
		return attachmentv3.TransferResult{}, errors.New("invalid recipient download clock")
	}
	if existing, found, err := journal.receiptDownload(inbound.PunaroMessageID); err != nil {
		return attachmentv3.TransferResult{}, err
	} else if found {
		if existing.outputPath != destination {
			return attachmentv3.TransferResult{}, errors.New("changed receipt download destination")
		}
		if existing.state == receiptDownloadWritten {
			return w.completedResult(existing)
		}
		matched, err := completedReceiptOutputMatches(existing)
		if err != nil {
			return attachmentv3.TransferResult{}, err
		}
		if matched {
			if err := journal.markReceiptDownloadWritten(existing); err != nil {
				return attachmentv3.TransferResult{}, err
			}
			return w.completedResult(existing)
		}
	}
	if err := validateReceiptOutputDestination(destination); err != nil {
		return attachmentv3.TransferResult{}, err
	}
	accepted, err := w.options.Acceptance.Accept(ctx, inbound)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	if accepted.State != attachmentv3.TransferStateAccepted || accepted.AttemptGeneration != 0 {
		return attachmentv3.TransferResult{}, errors.New("recipient attachment is not accepted")
	}
	authority, err := w.options.AuthorityProvider.ResolveRecipientAcceptanceAuthority(ctx, now)
	if err != nil || authority == nil {
		return attachmentv3.TransferResult{}, errors.New("fresh recipient download authority is unavailable")
	}
	notice, err := journal.PrepareApprovedReceipt(ctx, inbound, authority, authority, now)
	if err != nil || accepted.TransferID != notice.Manifest.TransferID {
		return attachmentv3.TransferResult{}, errors.New("approved recipient offer is unavailable")
	}
	source, err := attachmentv3.DecodeAndVerifyRetainedSource(notice.ManifestRaw, authority, now)
	if err != nil || source.ManifestCommitment() != accepted.ManifestCommitment {
		return attachmentv3.TransferResult{}, errors.New("approved recipient source is unavailable")
	}
	fileKey, err := w.options.EnvelopeOpener.OpenRecipientEnvelope(notice.EnvelopeRaw, source, authority, now)
	if err != nil || fileKey == [32]byte{} {
		return attachmentv3.TransferResult{}, errors.New("recipient envelope cannot be opened")
	}
	record, err := journal.ensureReceiptDownload(inbound.PunaroMessageID, notice, destination)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	if record.state == receiptDownloadWritten {
		return w.completedResult(record)
	}
	if _, err := w.advance(ctx, record, receiptDownloadBegin, 0, 1, 1, attachmentv3.TransferStateTransferring, authority, now); err != nil {
		return attachmentv3.TransferResult{}, err
	}
	downloadChunks := func() error {
		for index := uint64(0); index < notice.Manifest.ChunkCount; index++ {
			if _, found, err := journal.receiptDownloadChunk(record, index); err != nil {
				return err
			} else if found {
				continue
			}
			maxBytes, err := receiptCiphertextLength(notice.Manifest, index)
			if err != nil {
				return err
			}
			if _, err := w.advance(ctx, record, receiptDownloadChunk, index, maxBytes, 1, attachmentv3.TransferStateTransferring, authority, now); err != nil {
				return err
			}
		}
		return nil
	}
	if err := downloadChunks(); err != nil {
		return attachmentv3.TransferResult{}, err
	}
	// Do not terminalize the relay receipt based merely on journal hashes: a
	// local disk fault can change both stored ciphertext and its local hash.
	// Verify every encrypted frame before Complete; one reset/re-fetch pass is
	// safe because the relay preserves immutable ciphertext for this recipient.
	chunks, err := journal.receiptDownloadChunks(record, notice.Manifest.ChunkCount)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	if _, err := attachmentv3.OpenSourceArtifact(record.manifest, chunks, fileKey, authority, now); err != nil {
		if err := journal.clearReceiptDownloadChunks(record); err != nil {
			return attachmentv3.TransferResult{}, err
		}
		if err := downloadChunks(); err != nil {
			return attachmentv3.TransferResult{}, err
		}
		chunks, err = journal.receiptDownloadChunks(record, notice.Manifest.ChunkCount)
		if err != nil {
			return attachmentv3.TransferResult{}, err
		}
		if _, err := attachmentv3.OpenSourceArtifact(record.manifest, chunks, fileKey, authority, now); err != nil {
			return attachmentv3.TransferResult{}, errors.New("invalid recipient ciphertext after recovery")
		}
	}
	completed, err := w.advance(ctx, record, receiptDownloadComplete, 0, 1, 1, attachmentv3.TransferStateCompleted, authority, now)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	if err := WriteCompletedReceiptAtomically(record.outputPath, record.manifest, chunks, fileKey, authority, now.Unix()); err != nil {
		return attachmentv3.TransferResult{}, err
	}
	if err := journal.markReceiptDownloadWritten(record); err != nil {
		return attachmentv3.TransferResult{}, err
	}
	return completed, nil
}

func (w *RecipientDownloadWorker) advance(ctx context.Context, record receiptDownloadRecord, phase receiptDownloadPhase, chunk, maxBytes, maxChunks uint64, expected attachmentv3.TransferState, _ RecipientAcceptanceAuthority, _ time.Time) (attachmentv3.TransferResult, error) {
	// Each remote capability is deliberately minted from a fresh clock and
	// authority view. A large transfer must not reuse Receive's start time and
	// accidentally issue already-expired permits after earlier chunks took time.
	now := w.options.Now().UTC()
	if now.Unix() < 0 {
		return attachmentv3.TransferResult{}, errors.New("invalid recipient download clock")
	}
	authority, err := w.options.AuthorityProvider.ResolveRecipientAcceptanceAuthority(ctx, now)
	if err != nil || authority == nil {
		return attachmentv3.TransferResult{}, errors.New("fresh recipient download authority is unavailable")
	}
	if phase == receiptDownloadChunk {
		if _, found, err := w.options.Acceptance.options.Journal.receiptDownloadChunk(record, chunk); err != nil || found {
			if err != nil {
				return attachmentv3.TransferResult{}, err
			}
			return attachmentv3.TransferResult{TransferID: record.transferID, ManifestCommitment: record.manifestCommitment, State: attachmentv3.TransferStateTransferring, AttemptGeneration: 1}, nil
		}
	}
	op, err := w.options.Acceptance.options.Journal.ensureReceiptDownloadOperation(record, phase, chunk, maxBytes, maxChunks, now, w.options.Signer.SignReceiptDownloadPermit, w.options.NewID, w.options.NewIdempotencyKey)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	active, found, err := w.options.Acceptance.options.Journal.receiptDownloadActiveOperation(record.messageID, phase, chunk)
	if err != nil || !found {
		return attachmentv3.TransferResult{}, errors.New("missing durable recipient download operation")
	}
	op = active
	if phase != receiptDownloadChunk && len(op.result) != 0 {
		return exactReceiptDownloadResult(op.result, record, expected)
	}
	if receiptDownloadOperationExpired(op, now) {
		return w.reconcileExpiredDownload(ctx, record, phase, chunk, maxBytes, maxChunks, expected, op, authority, now)
	}
	permit, signed, err := w.credentials(ctx, record, op, authority, now)
	if err != nil {
		if errors.Is(err, errRecipientDownloadOutcome) {
			active, found, activeErr := w.options.Acceptance.options.Journal.receiptDownloadActiveOperation(record.messageID, phase, chunk)
			if activeErr != nil || !found {
				return attachmentv3.TransferResult{}, errors.New("missing recipient download outcome origin")
			}
			return w.reconcileExpiredDownload(ctx, record, phase, chunk, maxBytes, maxChunks, expected, active, authority, now)
		}
		return attachmentv3.TransferResult{}, err
	}
	method, path := receiptDownloadRoute(record.transferID, phase, chunk)
	raw, err := w.options.Transport.DoV3Attachment(ctx, method, path, nil, permit, signed)
	if err != nil {
		return attachmentv3.TransferResult{}, fmt.Errorf("submit recipient %s: %w", phase, err)
	}
	if phase == receiptDownloadChunk {
		expectedBytes, err := receiptCiphertextLengthFromRecord(record, chunk)
		if err != nil || uint64(len(raw)) != expectedBytes {
			return attachmentv3.TransferResult{}, errors.New("invalid recipient download ciphertext")
		}
		if err := w.options.Acceptance.options.Journal.storeReceiptDownloadChunk(record, chunk, raw); err != nil {
			return attachmentv3.TransferResult{}, err
		}
		return attachmentv3.TransferResult{TransferID: record.transferID, ManifestCommitment: record.manifestCommitment, State: attachmentv3.TransferStateTransferring, AttemptGeneration: 1}, nil
	}
	result, err := exactReceiptDownloadResult(raw, record, expected)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	if err := w.options.Acceptance.options.Journal.storeReceiptDownloadResult(record, op, raw); err != nil {
		return attachmentv3.TransferResult{}, err
	}
	return result, nil
}

func receiptDownloadOperationExpired(operation receiptDownloadOperation, now time.Time) bool {
	if len(operation.permit) == 0 || now.Unix() < 0 {
		return false
	}
	permit, err := attachmentv3.DecodePermit(operation.permit)
	// #nosec G115 -- the caller rejects pre-epoch times before permit use.
	return err != nil || permit.ExpiresAt <= uint64(now.Unix())
}

// reconcileExpiredDownload queries the outcome of exactly one retained relay
// operation. It never replays its expired permit. A chunk in transferring
// state has no response body to persist, so only that confirmed state creates
// a new immutable retrieval capability.
func (w *RecipientDownloadWorker) reconcileExpiredDownload(ctx context.Context, record receiptDownloadRecord, phase receiptDownloadPhase, chunk, maxBytes, maxChunks uint64, expected attachmentv3.TransferState, original receiptDownloadOperation, authority RecipientAcceptanceAuthority, now time.Time) (attachmentv3.TransferResult, error) {
	originalPermit, err := attachmentv3.DecodePermit(original.permit)
	// #nosec G115 -- the caller rejects pre-epoch times before reconciliation.
	if err != nil || originalPermit.ExpiresAt > uint64(now.Unix()) || originalPermit.Serial == [16]byte{} {
		return attachmentv3.TransferResult{}, errors.New("recipient download operation is not reconcilable")
	}
	attempt, found, err := w.options.Acceptance.options.Journal.latestReceiptDownloadOutcomeAttempt(record.messageID, phase, chunk, original.attempt)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	if !found || receiptDownloadOutcomeAttemptExpired(attempt, now) {
		attempt, err = w.newReceiptDownloadOutcomeAttempt(record, phase, chunk, original, attempt, found, now)
		if err != nil {
			return attachmentv3.TransferResult{}, err
		}
	}
	if len(attempt.result) == 0 {
		permit, operation, err := w.receiptDownloadOutcomeCredentials(ctx, record, phase, chunk, original, attempt, authority, now)
		if err != nil {
			return attachmentv3.TransferResult{}, err
		}
		raw, err := w.options.Transport.DoV3Attachment(ctx, "GET", outcomePath(record.transferID), nil, permit, operation)
		if err != nil {
			return attachmentv3.TransferResult{}, fmt.Errorf("query recipient download outcome: %w", err)
		}
		attempt, err = w.options.Acceptance.options.Journal.storeReceiptDownloadOutcomeResult(record, phase, chunk, attempt, raw)
		if err != nil {
			return attachmentv3.TransferResult{}, err
		}
	}
	result, err := attachmentv3.DecodeTransferResult(attempt.result)
	if err != nil || result.TransferID != record.transferID || result.ManifestCommitment != record.manifestCommitment || result.AttemptGeneration != 1 {
		return attachmentv3.TransferResult{}, errors.New("invalid recipient download outcome")
	}
	if result.State == attachmentv3.TransferStateCancelled || result.State == attachmentv3.TransferStateExpired || result.State == attachmentv3.TransferStateRevoked {
		return attachmentv3.TransferResult{}, errors.New("recipient download has terminal relay outcome")
	}
	if phase == receiptDownloadChunk {
		if result.State != attachmentv3.TransferStateTransferring {
			return attachmentv3.TransferResult{}, errors.New("invalid recipient download chunk outcome")
		}
		if _, err := w.options.Acceptance.options.Journal.newReceiptDownloadRetryOperation(record, original, now, w.options.Signer.SignReceiptDownloadPermit, w.options.NewID, w.options.NewIdempotencyKey); err != nil {
			return attachmentv3.TransferResult{}, err
		}
		return w.advance(ctx, record, phase, chunk, maxBytes, maxChunks, expected, authority, now)
	}
	if result.State != expected {
		return attachmentv3.TransferResult{}, errors.New("invalid recipient download operation outcome")
	}
	if err := w.options.Acceptance.options.Journal.storeReceiptDownloadResult(record, original, attempt.result); err != nil {
		return attachmentv3.TransferResult{}, err
	}
	return result, nil
}

func receiptDownloadOutcomeAttemptExpired(attempt receiptDownloadOutcomeAttempt, now time.Time) bool {
	if now.Unix() < 0 {
		return true
	}
	if len(attempt.permit) != 0 {
		permit, err := attachmentv3.DecodePermit(attempt.permit)
		// #nosec G115 -- the caller rejects pre-epoch times before permit use.
		return err != nil || permit.ExpiresAt <= uint64(now.Unix())
	}
	// #nosec G115 -- the surrounding v3 validation bounds this conversion and fails closed.
	return attempt.request.ExpiresAt <= uint64(now.Unix())
}

func (w *RecipientDownloadWorker) newReceiptDownloadOutcomeAttempt(record receiptDownloadRecord, phase receiptDownloadPhase, chunk uint64, original receiptDownloadOperation, previous receiptDownloadOutcomeAttempt, found bool, now time.Time) (receiptDownloadOutcomeAttempt, error) {
	requestID, err := w.options.NewID()
	if err != nil || requestID == [16]byte{} {
		return receiptDownloadOutcomeAttempt{}, errors.New("generate recipient download outcome request identity")
	}
	opID, err := w.options.NewID()
	if err != nil || opID == [16]byte{} {
		return receiptDownloadOutcomeAttempt{}, errors.New("generate recipient download outcome operation identity")
	}
	key, err := w.options.NewIdempotencyKey()
	if err != nil || key == [32]byte{} {
		return receiptDownloadOutcomeAttempt{}, errors.New("generate recipient download outcome idempotency identity")
	}
	originalPermit, err := attachmentv3.DecodePermit(original.permit)
	if err != nil || originalPermit.Serial == [16]byte{} {
		return receiptDownloadOutcomeAttempt{}, errors.New("invalid recipient download outcome origin")
	}
	manifest, err := attachmentv3.DecodeManifest(record.manifest)
	if err != nil {
		return receiptDownloadOutcomeAttempt{}, errors.New("invalid recipient download outcome manifest")
	}
	request := original.request
	request.RequestID, request.Operation, request.AttemptGeneration, request.OutcomeOfSerial = requestID, attachmentv3.PermitOperationOutcome, 0, originalPermit.Serial
	request.MaxOperations = 1
	expires := now.UTC().Add(20 * time.Second).Unix()
	// #nosec G115 -- the surrounding v3 validation bounds this conversion and fails closed.
	if uint64(expires) > manifest.ExpiresAt {
		// #nosec G115 -- the surrounding v3 validation bounds this conversion and fails closed.
		expires = int64(manifest.ExpiresAt)
	}
	if expires <= now.UTC().Unix() {
		return receiptDownloadOutcomeAttempt{}, errors.New("recipient download outcome exceeds manifest lifetime")
	}
	// #nosec G115 -- the surrounding v3 validation bounds this conversion and fails closed.
	request.IssuedAt, request.ExpiresAt = uint64(now.UTC().Unix()), uint64(expires)
	if err := w.options.Acceptance.options.Signer.SignOutcomePermit(&request); err != nil {
		return receiptDownloadOutcomeAttempt{}, err
	}
	index := uint64(0)
	if found {
		if previous.index == ^uint64(0) {
			return receiptDownloadOutcomeAttempt{}, errors.New("recipient download outcome index overflow")
		}
		index = previous.index + 1
	}
	return w.options.Acceptance.options.Journal.storeReceiptDownloadOutcomeAttempt(record, phase, chunk, receiptDownloadOutcomeAttempt{operationAttempt: original.attempt, index: index, request: request, operationID: opID, idempotencyKey: key})
}

func (w *RecipientDownloadWorker) receiptDownloadOutcomeCredentials(ctx context.Context, record receiptDownloadRecord, phase receiptDownloadPhase, chunk uint64, original receiptDownloadOperation, attempt receiptDownloadOutcomeAttempt, authority RecipientAcceptanceAuthority, now time.Time) (attachmentv3.Permit, attachmentv3.OperationRecord, error) {
	if len(attempt.permit) == 0 || len(attempt.operation) == 0 {
		permit, err := w.options.Transport.IssueV3Permit(ctx, attempt.request)
		if err != nil || !exactReceiptDownloadOutcomePermit(permit, attempt.request, record, original, now) || attachmentv3.VerifyPermit(permit, authority, now) != nil {
			return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("recipient download outcome permit is unavailable")
		}
		op, err := w.options.Acceptance.options.Signer.BuildOutcomeOperation(permit, "GET", outcomePath(record.transferID), attempt.operationID, attempt.idempotencyKey, permit.IssuedAt, permit.ExpiresAt)
		if err != nil || !verifyReceiptDownloadOperation(op, permit, "GET", outcomePath(record.transferID), authority, now) {
			return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("invalid recipient download outcome operation")
		}
		stored, err := w.options.Acceptance.options.Journal.storeReceiptDownloadOutcomeCredentials(record, phase, chunk, attempt, permit, op)
		if err != nil {
			return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, err
		}
		attempt = stored
	}
	permit, err := attachmentv3.DecodePermit(attempt.permit)
	if err != nil || !exactReceiptDownloadOutcomePermit(permit, attempt.request, record, original, now) || attachmentv3.VerifyPermit(permit, authority, now) != nil {
		return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("invalid durable recipient download outcome permit")
	}
	op, err := attachmentv3.DecodeOperation(attempt.operation)
	if err != nil || op.OperationID != attempt.operationID || op.IdempotencyKey != attempt.idempotencyKey || !verifyReceiptDownloadOperation(op, permit, "GET", outcomePath(record.transferID), authority, now) {
		return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("invalid durable recipient download outcome operation")
	}
	return permit, op, nil
}

func exactReceiptDownloadOutcomePermit(permit attachmentv3.Permit, request attachmentv3.PermitRequest, record receiptDownloadRecord, original receiptDownloadOperation, now time.Time) bool {
	origin, err := attachmentv3.DecodePermit(original.permit)
	// #nosec G115 -- the surrounding v3 validation bounds this conversion and fails closed.
	if err != nil || request.OutcomeOfSerial != origin.Serial || request.RequestID == [16]byte{} || request.Operation != attachmentv3.PermitOperationOutcome || request.AttemptGeneration != 0 || request.TransferID != record.transferID || request.StagedManifestCommitment != record.manifestCommitment || request.HolderRole != attachmentv3.PermitHolderRecipient || !attachmentv3.IssuedWithinClockSkew(request.IssuedAt, now) || request.ExpiresAt <= uint64(now.Unix()) {
		return false
	}
	// #nosec G115 -- the surrounding v3 validation bounds this conversion and fails closed.
	return permit.HolderDeviceID == request.HolderDeviceID && permit.HolderGeneration == request.HolderGeneration && permit.HolderRole == request.HolderRole && permit.TransferID == request.TransferID && permit.ConversationID == request.ConversationID && permit.SenderDeviceID == request.SenderDeviceID && permit.SenderGeneration == request.SenderGeneration && permit.RecipientDeviceID == request.RecipientDeviceID && permit.RecipientGeneration == request.RecipientGeneration && permit.Operation == request.Operation && permit.AttemptGeneration == 0 && permit.OutcomeOfSerial == request.OutcomeOfSerial && permit.MembershipCommitment == request.MembershipCommitment && permit.StagedManifestCommitment == request.StagedManifestCommitment && permit.MaxBytes == request.MaxBytes && permit.MaxChunks == request.MaxChunks && permit.MaxOperations == 1 && permit.IssuedAt >= request.IssuedAt && permit.ExpiresAt <= request.ExpiresAt && permit.ExpiresAt > uint64(now.Unix())
}

func (w *RecipientDownloadWorker) credentials(ctx context.Context, record receiptDownloadRecord, operation receiptDownloadOperation, authority RecipientAcceptanceAuthority, now time.Time) (attachmentv3.Permit, attachmentv3.OperationRecord, error) {
	if len(operation.permit) != 0 || len(operation.operation) != 0 {
		if len(operation.permit) == 0 {
			return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("incomplete durable recipient download credentials")
		}
		permit, err := attachmentv3.DecodePermit(operation.permit)
		// #nosec G115 -- the surrounding v3 validation bounds this conversion and fails closed.
		if err != nil || !exactReceiptDownloadPermitFields(permit, operation.request, record) || attachmentv3.VerifyPermit(permit, authority, time.Unix(int64(permit.IssuedAt), 0).UTC()) != nil {
			return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("invalid durable recipient download permit")
		}
		// #nosec G115 -- the surrounding v3 validation bounds this conversion and fails closed.
		if permit.ExpiresAt <= uint64(now.Unix()) {
			return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errRecipientDownloadOutcome
		}
		if len(operation.operation) == 0 {
			method, path := receiptDownloadRoute(record.transferID, operation.phase, operation.chunk)
			signed, err := w.options.Signer.BuildReceiptDownloadOperation(permit, method, path, nil, operation.operationID, operation.idempotencyKey, permit.IssuedAt, permit.ExpiresAt)
			if err != nil || !verifyReceiptDownloadOperation(signed, permit, method, path, authority, now) {
				return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("invalid recipient download operation")
			}
			stored, err := w.options.Acceptance.options.Journal.storeReceiptDownloadOperationSignature(record, operation, signed)
			if err != nil {
				return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, err
			}
			return w.credentials(ctx, record, stored, authority, now)
		}
		signed, err := attachmentv3.DecodeOperation(operation.operation)
		method, path := receiptDownloadRoute(record.transferID, operation.phase, operation.chunk)
		if err != nil || signed.OperationID != operation.operationID || signed.IdempotencyKey != operation.idempotencyKey || !verifyReceiptDownloadOperation(signed, permit, method, path, authority, now) {
			return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("invalid durable recipient download operation")
		}
		return permit, signed, nil
	}
	permit, err := w.options.Transport.IssueV3Permit(ctx, operation.request)
	// #nosec G115 -- the surrounding v3 validation bounds this conversion and fails closed.
	if err != nil || !exactReceiptDownloadPermitFields(permit, operation.request, record) || attachmentv3.VerifyPermit(permit, authority, time.Unix(int64(permit.IssuedAt), 0).UTC()) != nil {
		return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("recipient download permit is unavailable")
	}
	stored, err := w.options.Acceptance.options.Journal.storeReceiptDownloadPermit(record, operation, permit)
	if err != nil {
		return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, err
	}
	// #nosec G115 -- the surrounding v3 validation bounds this conversion and fails closed.
	if permit.ExpiresAt <= uint64(now.Unix()) {
		return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errRecipientDownloadOutcome
	}
	method, path := receiptDownloadRoute(record.transferID, operation.phase, operation.chunk)
	issuedAt := permit.IssuedAt
	// #nosec G115 -- the surrounding v3 validation bounds this conversion and fails closed.
	if uint64(now.Unix()) > issuedAt {
		// #nosec G115 -- the surrounding v3 validation bounds this conversion and fails closed.
		issuedAt = uint64(now.Unix())
	}
	signed, err := w.options.Signer.BuildReceiptDownloadOperation(permit, method, path, nil, operation.operationID, operation.idempotencyKey, issuedAt, permit.ExpiresAt)
	if err != nil || !verifyReceiptDownloadOperation(signed, permit, method, path, authority, now) {
		return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("invalid recipient download operation")
	}
	stored, err = w.options.Acceptance.options.Journal.storeReceiptDownloadOperationSignature(record, stored, signed)
	if err != nil {
		return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, err
	}
	return w.credentials(ctx, record, stored, authority, now)
}

func exactReceiptDownloadPermitFields(permit attachmentv3.Permit, request attachmentv3.PermitRequest, record receiptDownloadRecord) bool {
	if _, err := attachmentv3.EncodePermit(permit); err != nil || permit.HolderDeviceID != request.HolderDeviceID || permit.HolderGeneration != request.HolderGeneration || permit.HolderRole != attachmentv3.PermitHolderRecipient || permit.TransferID != record.transferID || permit.ConversationID != request.ConversationID || permit.SenderDeviceID != request.SenderDeviceID || permit.SenderGeneration != request.SenderGeneration || permit.RecipientDeviceID != request.RecipientDeviceID || permit.RecipientGeneration != request.RecipientGeneration || permit.AttemptGeneration != 1 || permit.Operation != request.Operation || permit.MembershipCommitment != request.MembershipCommitment || permit.StagedManifestCommitment != record.manifestCommitment || permit.MaxBytes != request.MaxBytes || permit.MaxChunks != request.MaxChunks || permit.MaxOperations != 1 {
		return false
	}
	return permit.IssuedAt >= request.IssuedAt && permit.ExpiresAt <= request.ExpiresAt
}

func verifyReceiptDownloadOperation(signed attachmentv3.OperationRecord, permit attachmentv3.Permit, method, path string, authority RecipientAcceptanceAuthority, now time.Time) bool {
	route, request, err := attachmentv3.NewAttachmentOperationRequest(method, path, nil, nil)
	if err != nil {
		return false
	}
	if permit.Operation == attachmentv3.PermitOperationDownload {
		err = attachmentv3.VerifyAttachmentOperationAdmission(signed, permit, authority, route, request, now)
	} else {
		_, _, err = attachmentv3.VerifyAttachmentOperationRequest(signed, permit, authority, route, request, now)
	}
	return err == nil
}

func exactReceiptDownloadResult(raw []byte, record receiptDownloadRecord, expected attachmentv3.TransferState) (attachmentv3.TransferResult, error) {
	result, err := attachmentv3.DecodeTransferResult(raw)
	if err != nil || result.TransferID != record.transferID || result.ManifestCommitment != record.manifestCommitment || result.State != expected || result.AttemptGeneration != 1 {
		return attachmentv3.TransferResult{}, errors.New("invalid recipient download result")
	}
	return result, nil
}

func receiptDownloadRoute(transferID [16]byte, phase receiptDownloadPhase, chunk uint64) (string, string) {
	switch phase {
	case receiptDownloadBegin:
		return "POST", fmt.Sprintf("/v3/attachments/%x/attempts/1/begin", transferID)
	case receiptDownloadChunk:
		return "GET", fmt.Sprintf("/v3/attachments/%x/chunks/%d", transferID, chunk)
	case receiptDownloadComplete:
		return "POST", fmt.Sprintf("/v3/attachments/%x/complete", transferID)
	default:
		return "", ""
	}
}

func receiptCiphertextLength(manifest attachmentv3.Manifest, index uint64) (uint64, error) {
	if manifest.ChunkSize == 0 || manifest.ChunkCount == 0 || index >= manifest.ChunkCount || index > ^uint64(0)/manifest.ChunkSize {
		return 0, errors.New("invalid receipt manifest geometry")
	}
	if manifest.PlaintextSize == 0 {
		if manifest.ChunkCount != 1 || index != 0 {
			return 0, errors.New("invalid receipt manifest geometry")
		}
		return 16, nil
	}
	start := index * manifest.ChunkSize
	if start >= manifest.PlaintextSize {
		return 0, errors.New("invalid receipt manifest geometry")
	}
	length := manifest.ChunkSize
	if remain := manifest.PlaintextSize - start; remain < length {
		length = remain
	}
	if length > ^uint64(0)-16 {
		return 0, errors.New("invalid receipt ciphertext geometry")
	}
	return length + 16, nil
}

func receiptCiphertextLengthFromRecord(record receiptDownloadRecord, index uint64) (uint64, error) {
	manifest, err := attachmentv3.DecodeManifest(record.manifest)
	if err != nil || manifest.TransferID != record.transferID {
		return 0, errors.New("invalid durable receipt manifest")
	}
	return receiptCiphertextLength(manifest, index)
}

func (w *RecipientDownloadWorker) completedResult(record receiptDownloadRecord) (attachmentv3.TransferResult, error) {
	op, found, err := w.options.Acceptance.options.Journal.receiptDownloadOperation(record.messageID, receiptDownloadComplete, 0)
	if err != nil || !found || len(op.result) == 0 {
		return attachmentv3.TransferResult{}, errors.New("missing durable receipt completion")
	}
	return exactReceiptDownloadResult(op.result, record, attachmentv3.TransferStateCompleted)
}
