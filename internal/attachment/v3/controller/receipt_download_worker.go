package controller

import (
	"context"
	"crypto/ecdh"
	"errors"
	"fmt"
	"time"

	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
)

// RecipientEnvelopeOpener keeps the recipient HPKE private key behind the
// receipt worker boundary. It accepts only the already verified offer source
// and never returns the key to callers of Receive.
type RecipientEnvelopeOpener interface {
	OpenRecipientEnvelope([]byte, attachmentv3.VerifiedSource, attachmentv3.EnvelopeDirectoryKeyResolver, time.Time) ([32]byte, error)
}

type localRecipientEnvelopeOpener struct{ private *ecdh.PrivateKey }

func NewLocalRecipientEnvelopeOpener(private *ecdh.PrivateKey) RecipientEnvelopeOpener {
	return &localRecipientEnvelopeOpener{private: private}
}

func (o *localRecipientEnvelopeOpener) OpenRecipientEnvelope(raw []byte, source attachmentv3.VerifiedSource, directory attachmentv3.EnvelopeDirectoryKeyResolver, now time.Time) ([32]byte, error) {
	if o == nil || o.private == nil {
		return [32]byte{}, errors.New("recipient envelope key is unavailable")
	}
	return attachmentv3.OpenRecipientEnvelope(raw, source, directory, o.private, now)
}

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
	} else if found && existing.outputPath == destination {
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
	source, err := attachmentv3.DecodeAndVerifySourceInit(notice.ManifestRaw, authority, now)
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
	for index := uint64(0); index < notice.Manifest.ChunkCount; index++ {
		if _, found, err := journal.receiptDownloadChunk(record, index); err != nil {
			return attachmentv3.TransferResult{}, err
		} else if found {
			continue
		}
		maxBytes, err := receiptCiphertextLength(notice.Manifest, index)
		if err != nil {
			return attachmentv3.TransferResult{}, err
		}
		if _, err := w.advance(ctx, record, receiptDownloadChunk, index, maxBytes, 1, attachmentv3.TransferStateTransferring, authority, now); err != nil {
			return attachmentv3.TransferResult{}, err
		}
	}
	completed, err := w.advance(ctx, record, receiptDownloadComplete, 0, 1, 1, attachmentv3.TransferStateCompleted, authority, now)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	chunks, err := journal.receiptDownloadChunks(record, notice.Manifest.ChunkCount)
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

func (w *RecipientDownloadWorker) advance(ctx context.Context, record receiptDownloadRecord, phase receiptDownloadPhase, chunk, maxBytes, maxChunks uint64, expected attachmentv3.TransferState, authority RecipientAcceptanceAuthority, now time.Time) (attachmentv3.TransferResult, error) {
	// Each remote capability is deliberately minted from a fresh clock and
	// authority view. A large transfer must not reuse Receive's start time and
	// accidentally issue already-expired permits after earlier chunks took time.
	now = w.options.Now().UTC()
	if now.Unix() < 0 {
		return attachmentv3.TransferResult{}, errors.New("invalid recipient download clock")
	}
	var err error
	authority, err = w.options.AuthorityProvider.ResolveRecipientAcceptanceAuthority(ctx, now)
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
	if phase != receiptDownloadChunk && len(op.result) != 0 {
		return exactReceiptDownloadResult(op.result, record, expected)
	}
	permit, signed, err := w.credentials(ctx, record, op, authority, now)
	if err != nil {
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

func (w *RecipientDownloadWorker) credentials(ctx context.Context, record receiptDownloadRecord, operation receiptDownloadOperation, authority RecipientAcceptanceAuthority, now time.Time) (attachmentv3.Permit, attachmentv3.OperationRecord, error) {
	if len(operation.permit) != 0 || len(operation.operation) != 0 {
		if len(operation.permit) == 0 || len(operation.operation) == 0 {
			return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("incomplete durable recipient download credentials")
		}
		permit, err := attachmentv3.DecodePermit(operation.permit)
		if err != nil || !exactReceiptDownloadPermit(permit, operation.request, record, now) || attachmentv3.VerifyPermit(permit, authority, now) != nil {
			return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("recipient download requires outcome reconciliation")
		}
		signed, err := attachmentv3.DecodeOperation(operation.operation)
		method, path := receiptDownloadRoute(record.transferID, operation.phase, operation.chunk)
		if err != nil || signed.OperationID != operation.operationID || signed.IdempotencyKey != operation.idempotencyKey || !verifyReceiptDownloadOperation(signed, permit, method, path, authority, now) {
			return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("invalid durable recipient download operation")
		}
		return permit, signed, nil
	}
	permit, err := w.options.Transport.IssueV3Permit(ctx, operation.request)
	if err != nil || !exactReceiptDownloadPermit(permit, operation.request, record, now) || attachmentv3.VerifyPermit(permit, authority, now) != nil {
		return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("recipient download permit is unavailable")
	}
	method, path := receiptDownloadRoute(record.transferID, operation.phase, operation.chunk)
	issuedAt := permit.IssuedAt
	if uint64(now.Unix()) > issuedAt {
		issuedAt = uint64(now.Unix())
	}
	signed, err := w.options.Signer.BuildReceiptDownloadOperation(permit, method, path, nil, operation.operationID, operation.idempotencyKey, issuedAt, permit.ExpiresAt)
	if err != nil || !verifyReceiptDownloadOperation(signed, permit, method, path, authority, now) {
		return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("invalid recipient download operation")
	}
	stored, err := w.options.Acceptance.options.Journal.storeReceiptDownloadCredentials(record, operation, permit, signed)
	if err != nil {
		return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, err
	}
	return w.credentials(ctx, record, stored, authority, now)
}

func exactReceiptDownloadPermit(permit attachmentv3.Permit, request attachmentv3.PermitRequest, record receiptDownloadRecord, now time.Time) bool {
	if _, err := attachmentv3.EncodePermit(permit); err != nil || now.Unix() < 0 || permit.HolderDeviceID != request.HolderDeviceID || permit.HolderGeneration != request.HolderGeneration || permit.HolderRole != attachmentv3.PermitHolderRecipient || permit.TransferID != record.transferID || permit.ConversationID != request.ConversationID || permit.SenderDeviceID != request.SenderDeviceID || permit.SenderGeneration != request.SenderGeneration || permit.RecipientDeviceID != request.RecipientDeviceID || permit.RecipientGeneration != request.RecipientGeneration || permit.AttemptGeneration != 1 || permit.Operation != request.Operation || permit.MembershipCommitment != request.MembershipCommitment || permit.StagedManifestCommitment != record.manifestCommitment || permit.MaxBytes != request.MaxBytes || permit.MaxChunks != request.MaxChunks || permit.MaxOperations != 1 {
		return false
	}
	return permit.IssuedAt >= request.IssuedAt && permit.ExpiresAt <= request.ExpiresAt && permit.IssuedAt <= uint64(now.Unix()) && permit.ExpiresAt > uint64(now.Unix())
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
