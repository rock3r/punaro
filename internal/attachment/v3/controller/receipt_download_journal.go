package controller

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"time"

	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
	"github.com/zeebo/blake3"
)

type receiptDownloadPhase string

const (
	receiptDownloadBegin    receiptDownloadPhase = "begin"
	receiptDownloadChunk    receiptDownloadPhase = "chunk"
	receiptDownloadComplete receiptDownloadPhase = "complete"
	receiptDownloadActive                        = "active"
	receiptDownloadWritten                       = "written"
)

type receiptDownloadRecord struct {
	messageID          string
	transferID         [16]byte
	manifest           []byte
	envelope           []byte
	outputPath         string
	manifestCommitment [32]byte
	state              string
}

type receiptDownloadOperation struct {
	phase          receiptDownloadPhase
	chunk          uint64
	attempt        uint64
	request        attachmentv3.PermitRequest
	operationID    [16]byte
	idempotencyKey [32]byte
	permit         []byte
	operation      []byte
	result         []byte
}

type receiptDownloadOutcomeAttempt struct {
	operationAttempt          uint64
	index                     uint64
	request                   attachmentv3.PermitRequest
	operationID               [16]byte
	idempotencyKey            [32]byte
	permit, operation, result []byte
}

func (j *Journal) latestReceiptDownloadOutcomeAttempt(messageID string, phase receiptDownloadPhase, chunk, operationAttempt uint64) (receiptDownloadOutcomeAttempt, bool, error) {
	var out receiptDownloadOutcomeAttempt
	var index int64
	var raw, id, key []byte
	err := j.db.QueryRowContext(context.Background(), `SELECT attempt_index,permit_request,operation_id,idempotency_key,permit,operation,result FROM controller_receipt_download_outcome_attempts WHERE punaro_message_id=? AND phase=? AND chunk_index=? AND operation_attempt_index=? ORDER BY attempt_index DESC LIMIT 1`, messageID, string(phase), int64(chunk), int64(operationAttempt)).Scan(&index, &raw, &id, &key, &out.permit, &out.operation, &out.result)
	if errors.Is(err, sql.ErrNoRows) {
		return out, false, nil
	}
	if err != nil || index < 0 || len(id) != 16 || len(key) != 32 {
		return out, false, errors.New("invalid receipt download outcome attempt")
	}
	request, err := attachmentv3.DecodePermitRequest(raw)
	if err != nil {
		return out, false, errors.New("invalid receipt download outcome request")
	}
	out.operationAttempt, out.index, out.request = operationAttempt, uint64(index), request
	copy(out.operationID[:], id)
	copy(out.idempotencyKey[:], key)
	return out, true, nil
}

func (j *Journal) storeReceiptDownloadOutcomeAttempt(record receiptDownloadRecord, phase receiptDownloadPhase, chunk uint64, attempt receiptDownloadOutcomeAttempt) (receiptDownloadOutcomeAttempt, error) {
	raw, err := attachmentv3.EncodePermitRequest(attempt.request)
	if err != nil || attempt.operationID == [16]byte{} || attempt.idempotencyKey == [32]byte{} {
		return receiptDownloadOutcomeAttempt{}, errors.New("invalid receipt download outcome attempt")
	}
	_, err = j.db.ExecContext(context.Background(), `INSERT INTO controller_receipt_download_outcome_attempts(punaro_message_id,phase,chunk_index,operation_attempt_index,attempt_index,permit_request,operation_id,idempotency_key) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(punaro_message_id,phase,chunk_index,operation_attempt_index,attempt_index) DO NOTHING`, record.messageID, string(phase), int64(chunk), int64(attempt.operationAttempt), int64(attempt.index), raw, attempt.operationID[:], attempt.idempotencyKey[:])
	if err != nil {
		return receiptDownloadOutcomeAttempt{}, err
	}
	stored, found, err := j.latestReceiptDownloadOutcomeAttempt(record.messageID, phase, chunk, attempt.operationAttempt)
	if err != nil || !found || stored.index != attempt.index || stored.operationAttempt != attempt.operationAttempt {
		return receiptDownloadOutcomeAttempt{}, errors.New("changed receipt download outcome attempt")
	}
	return stored, nil
}

func (j *Journal) storeReceiptDownloadOutcomeCredentials(record receiptDownloadRecord, phase receiptDownloadPhase, chunk uint64, attempt receiptDownloadOutcomeAttempt, permit attachmentv3.Permit, operation attachmentv3.OperationRecord) (receiptDownloadOutcomeAttempt, error) {
	rawPermit, err := attachmentv3.EncodePermit(permit)
	if err != nil {
		return receiptDownloadOutcomeAttempt{}, err
	}
	rawOperation, err := attachmentv3.EncodeOperation(operation)
	if err != nil {
		return receiptDownloadOutcomeAttempt{}, err
	}
	result, err := j.db.ExecContext(context.Background(), `UPDATE controller_receipt_download_outcome_attempts SET permit=?,operation=? WHERE punaro_message_id=? AND phase=? AND chunk_index=? AND operation_attempt_index=? AND attempt_index=? AND permit IS NULL AND operation IS NULL`, rawPermit, rawOperation, record.messageID, string(phase), int64(chunk), int64(attempt.operationAttempt), int64(attempt.index))
	if err != nil {
		return receiptDownloadOutcomeAttempt{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return receiptDownloadOutcomeAttempt{}, err
	}
	stored, found, err := j.latestReceiptDownloadOutcomeAttempt(record.messageID, phase, chunk, attempt.operationAttempt)
	if err != nil || !found || stored.index != attempt.index || len(stored.permit) == 0 || len(stored.operation) == 0 || (changed == 0 && (!bytes.Equal(stored.permit, rawPermit) || !bytes.Equal(stored.operation, rawOperation))) {
		return receiptDownloadOutcomeAttempt{}, errors.New("changed receipt download outcome credentials")
	}
	return stored, nil
}

func (j *Journal) storeReceiptDownloadOutcomeResult(record receiptDownloadRecord, phase receiptDownloadPhase, chunk uint64, attempt receiptDownloadOutcomeAttempt, result []byte) (receiptDownloadOutcomeAttempt, error) {
	if len(result) == 0 {
		return receiptDownloadOutcomeAttempt{}, errors.New("invalid receipt download outcome result")
	}
	update, err := j.db.ExecContext(context.Background(), `UPDATE controller_receipt_download_outcome_attempts SET result=? WHERE punaro_message_id=? AND phase=? AND chunk_index=? AND operation_attempt_index=? AND attempt_index=? AND result IS NULL`, result, record.messageID, string(phase), int64(chunk), int64(attempt.operationAttempt), int64(attempt.index))
	if err != nil {
		return receiptDownloadOutcomeAttempt{}, err
	}
	changed, err := update.RowsAffected()
	if err != nil {
		return receiptDownloadOutcomeAttempt{}, err
	}
	stored, found, err := j.latestReceiptDownloadOutcomeAttempt(record.messageID, phase, chunk, attempt.operationAttempt)
	if err != nil || !found || stored.index != attempt.index || len(stored.result) == 0 || (changed == 0 && !bytes.Equal(stored.result, result)) {
		return receiptDownloadOutcomeAttempt{}, errors.New("changed receipt download outcome result")
	}
	return stored, nil
}

// receiptDownloadActiveOperation returns the latest distinct capability for a
// route. Attempt zero is the immutable original operation; later attempts are
// created only after the preceding permit's durable outcome says the relay is
// still transferring.
func (j *Journal) receiptDownloadActiveOperation(messageID string, phase receiptDownloadPhase, chunk uint64) (receiptDownloadOperation, bool, error) {
	var attempt int64
	err := j.db.QueryRowContext(context.Background(), `SELECT attempt_index FROM controller_receipt_download_operation_retries WHERE punaro_message_id=? AND phase=? AND chunk_index=? ORDER BY attempt_index DESC LIMIT 1`, messageID, string(phase), int64(chunk)).Scan(&attempt)
	if errors.Is(err, sql.ErrNoRows) {
		return j.receiptDownloadOperation(messageID, phase, chunk)
	}
	if err != nil || attempt <= 0 {
		return receiptDownloadOperation{}, false, errors.New("invalid durable receipt download retry")
	}
	return j.receiptDownloadRetryOperation(messageID, phase, chunk, uint64(attempt))
}

func (j *Journal) receiptDownloadRetryOperation(messageID string, phase receiptDownloadPhase, chunk, attempt uint64) (receiptDownloadOperation, bool, error) {
	var record receiptDownloadOperation
	var request, operationID, key []byte
	err := j.db.QueryRowContext(context.Background(), `SELECT permit_request,operation_id,idempotency_key,permit,operation,result FROM controller_receipt_download_operation_retries WHERE punaro_message_id=? AND phase=? AND chunk_index=? AND attempt_index=?`, messageID, string(phase), int64(chunk), int64(attempt)).Scan(&request, &operationID, &key, &record.permit, &record.operation, &record.result)
	if errors.Is(err, sql.ErrNoRows) {
		return receiptDownloadOperation{}, false, nil
	}
	if err != nil || len(operationID) != 16 || len(key) != 32 {
		return receiptDownloadOperation{}, false, errors.New("invalid durable receipt download retry")
	}
	decoded, err := attachmentv3.DecodePermitRequest(request)
	if err != nil {
		return receiptDownloadOperation{}, false, errors.New("invalid durable receipt download retry request")
	}
	record.phase, record.chunk, record.attempt, record.request = phase, chunk, attempt, decoded
	copy(record.operationID[:], operationID)
	copy(record.idempotencyKey[:], key)
	return record, true, nil
}

// ensureReceiptDownload makes the user-selected output destination immutable
// before any ciphertext is fetched. The relay offer remains the canonical
// source of the manifest and recipient envelope; no raw file key is ever
// stored in the local journal.
func (j *Journal) ensureReceiptDownload(messageID string, notice attachmentv3.OfferNotice, outputPath string) (receiptDownloadRecord, error) {
	if j == nil || j.db == nil || messageID == "" || !filepath.IsAbs(outputPath) || notice.Manifest.TransferID == [16]byte{} || len(notice.ManifestRaw) == 0 || len(notice.EnvelopeRaw) == 0 {
		return receiptDownloadRecord{}, errors.New("invalid receipt download intent")
	}
	commitment := blake3.Sum256(notice.ManifestRaw)
	if existing, found, err := j.receiptDownload(messageID); err != nil || found {
		if err != nil || !found || existing.transferID != notice.Manifest.TransferID || existing.manifestCommitment != commitment || !bytes.Equal(existing.manifest, notice.ManifestRaw) || !bytes.Equal(existing.envelope, notice.EnvelopeRaw) || existing.outputPath != outputPath {
			return receiptDownloadRecord{}, errors.New("changed receipt download intent")
		}
		return existing, nil
	}
	result, err := j.db.ExecContext(context.Background(), `INSERT INTO controller_receipt_downloads(punaro_message_id,transfer_id,manifest,envelope,output_path,manifest_commitment,state)
		SELECT ?,?,?,?,?,?,'active' WHERE EXISTS (SELECT 1 FROM controller_receipt_acceptances WHERE punaro_message_id=? AND result IS NOT NULL)
		ON CONFLICT(punaro_message_id) DO NOTHING`, messageID, notice.Manifest.TransferID[:], notice.ManifestRaw, notice.EnvelopeRaw, outputPath, commitment[:], messageID)
	if err != nil {
		return receiptDownloadRecord{}, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return receiptDownloadRecord{}, err
	}
	if inserted != 1 {
		stored, found, err := j.receiptDownload(messageID)
		if err != nil || !found || stored.transferID != notice.Manifest.TransferID || stored.manifestCommitment != commitment || !bytes.Equal(stored.manifest, notice.ManifestRaw) || !bytes.Equal(stored.envelope, notice.EnvelopeRaw) || stored.outputPath != outputPath {
			return receiptDownloadRecord{}, errors.New("changed receipt download retry")
		}
		return stored, nil
	}
	return receiptDownloadRecord{messageID: messageID, transferID: notice.Manifest.TransferID, manifest: append([]byte(nil), notice.ManifestRaw...), envelope: append([]byte(nil), notice.EnvelopeRaw...), outputPath: outputPath, manifestCommitment: commitment, state: receiptDownloadActive}, nil
}

func (j *Journal) receiptDownload(messageID string) (receiptDownloadRecord, bool, error) {
	var record receiptDownloadRecord
	var transfer, commitment []byte
	err := j.db.QueryRowContext(context.Background(), `SELECT transfer_id,manifest,envelope,output_path,manifest_commitment,state FROM controller_receipt_downloads WHERE punaro_message_id=?`, messageID).Scan(&transfer, &record.manifest, &record.envelope, &record.outputPath, &commitment, &record.state)
	if errors.Is(err, sql.ErrNoRows) {
		return receiptDownloadRecord{}, false, nil
	}
	if err != nil || len(transfer) != 16 || len(commitment) != 32 || len(record.manifest) == 0 || len(record.envelope) == 0 || !filepath.IsAbs(record.outputPath) || (record.state != receiptDownloadActive && record.state != receiptDownloadWritten) {
		return receiptDownloadRecord{}, false, errors.New("invalid durable receipt download")
	}
	record.messageID = messageID
	copy(record.transferID[:], transfer)
	copy(record.manifestCommitment[:], commitment)
	if blake3.Sum256(record.manifest) != record.manifestCommitment {
		return receiptDownloadRecord{}, false, errors.New("invalid durable receipt manifest")
	}
	return record, true, nil
}

func (j *Journal) ensureReceiptDownloadOperation(record receiptDownloadRecord, phase receiptDownloadPhase, chunk, maxBytes, maxChunks uint64, now time.Time, signer func(*attachmentv3.PermitRequest) error, newID func() ([16]byte, error), newKey func() ([32]byte, error)) (receiptDownloadOperation, error) {
	if j == nil || j.db == nil || record.messageID == "" || record.transferID == [16]byte{} || (phase != receiptDownloadBegin && phase != receiptDownloadChunk && phase != receiptDownloadComplete) || (phase == receiptDownloadChunk && maxBytes == 0) || maxBytes == 0 || maxChunks == 0 || signer == nil || newID == nil || newKey == nil || now.UTC().Unix() < 0 {
		return receiptDownloadOperation{}, errors.New("invalid receipt download operation intent")
	}
	if existing, found, err := j.receiptDownloadOperation(record.messageID, phase, chunk); err != nil || found {
		if err != nil || !found {
			return receiptDownloadOperation{}, errors.New("invalid durable receipt download operation")
		}
		return existing, nil
	}
	accepted, found, err := j.receiptAcceptance(record.messageID)
	if err != nil || !found || len(accepted.result) == 0 || accepted.transferID != record.transferID || accepted.manifestCommitment != record.manifestCommitment {
		return receiptDownloadOperation{}, errors.New("receipt download is not accepted")
	}
	requestID, err := newID()
	if err != nil || requestID == [16]byte{} {
		return receiptDownloadOperation{}, errors.New("generate receipt download request identity")
	}
	opID, err := newID()
	if err != nil || opID == [16]byte{} {
		return receiptDownloadOperation{}, errors.New("generate receipt download operation identity")
	}
	key, err := newKey()
	if err != nil || key == [32]byte{} {
		return receiptDownloadOperation{}, errors.New("generate receipt download idempotency identity")
	}
	var operation uint64
	switch phase {
	case receiptDownloadBegin:
		operation = attachmentv3.PermitOperationBegin
	case receiptDownloadChunk:
		operation = attachmentv3.PermitOperationDownload
	case receiptDownloadComplete:
		operation = attachmentv3.PermitOperationComplete
	default:
		return receiptDownloadOperation{}, errors.New("invalid receipt download phase")
	}
	expires := now.UTC().Add(20 * time.Second).Unix()
	manifest, err := attachmentv3.DecodeManifest(record.manifest)
	if err != nil || uint64(expires) > manifest.ExpiresAt {
		expires = int64(manifest.ExpiresAt)
	}
	if expires <= now.UTC().Unix() {
		return receiptDownloadOperation{}, errors.New("expired receipt download offer")
	}
	request := attachmentv3.PermitRequest{RequestID: requestID, HolderDeviceID: accepted.request.HolderDeviceID, HolderGeneration: accepted.request.HolderGeneration, HolderRole: attachmentv3.PermitHolderRecipient, TransferID: record.transferID, ConversationID: accepted.request.ConversationID, SenderDeviceID: accepted.request.SenderDeviceID, SenderGeneration: accepted.request.SenderGeneration, RecipientDeviceID: accepted.request.RecipientDeviceID, RecipientGeneration: accepted.request.RecipientGeneration, AttemptGeneration: 1, Operation: operation, MembershipCommitment: accepted.request.MembershipCommitment, StagedManifestCommitment: record.manifestCommitment, IssuedAt: uint64(now.UTC().Unix()), ExpiresAt: uint64(expires), MaxBytes: maxBytes, MaxChunks: maxChunks, MaxOperations: 1}
	if err := signer(&request); err != nil {
		return receiptDownloadOperation{}, err
	}
	rawRequest, err := attachmentv3.EncodePermitRequest(request)
	if err != nil {
		return receiptDownloadOperation{}, err
	}
	_, err = j.db.ExecContext(context.Background(), `INSERT INTO controller_receipt_download_operations(punaro_message_id,phase,chunk_index,permit_request,operation_id,idempotency_key)
		VALUES (?,?,?,?,?,?) ON CONFLICT(punaro_message_id,phase,chunk_index) DO NOTHING`, record.messageID, string(phase), int64(chunk), rawRequest, opID[:], key[:])
	if err != nil {
		return receiptDownloadOperation{}, err
	}
	stored, found, err := j.receiptDownloadOperation(record.messageID, phase, chunk)
	storedRaw, storedErr := attachmentv3.EncodePermitRequest(stored.request)
	if err != nil || !found || storedErr != nil || !bytes.Equal(storedRaw, rawRequest) || stored.operationID != opID || stored.idempotencyKey != key {
		return receiptDownloadOperation{}, errors.New("changed receipt download operation")
	}
	return stored, nil
}

func (j *Journal) receiptDownloadOperation(messageID string, phase receiptDownloadPhase, chunk uint64) (receiptDownloadOperation, bool, error) {
	var record receiptDownloadOperation
	var request, operationID, key []byte
	err := j.db.QueryRowContext(context.Background(), `SELECT permit_request,operation_id,idempotency_key,permit,operation,result FROM controller_receipt_download_operations WHERE punaro_message_id=? AND phase=? AND chunk_index=?`, messageID, string(phase), int64(chunk)).Scan(&request, &operationID, &key, &record.permit, &record.operation, &record.result)
	if errors.Is(err, sql.ErrNoRows) {
		return receiptDownloadOperation{}, false, nil
	}
	if err != nil || len(operationID) != 16 || len(key) != 32 {
		return receiptDownloadOperation{}, false, errors.New("invalid durable receipt download operation")
	}
	decoded, err := attachmentv3.DecodePermitRequest(request)
	if err != nil {
		return receiptDownloadOperation{}, false, errors.New("invalid durable receipt download request")
	}
	record.phase, record.chunk, record.request = phase, chunk, decoded
	copy(record.operationID[:], operationID)
	copy(record.idempotencyKey[:], key)
	return record, true, nil
}

func (j *Journal) newReceiptDownloadRetryOperation(record receiptDownloadRecord, previous receiptDownloadOperation, now time.Time, signer func(*attachmentv3.PermitRequest) error, newID func() ([16]byte, error), newKey func() ([32]byte, error)) (receiptDownloadOperation, error) {
	if record.messageID == "" || previous.attempt == ^uint64(0) || previous.phase != receiptDownloadChunk || previous.request.Operation != attachmentv3.PermitOperationDownload || now.UTC().Unix() < 0 || signer == nil || newID == nil || newKey == nil {
		return receiptDownloadOperation{}, errors.New("invalid receipt download retry intent")
	}
	requestID, err := newID()
	if err != nil || requestID == [16]byte{} {
		return receiptDownloadOperation{}, errors.New("generate receipt download retry request identity")
	}
	opID, err := newID()
	if err != nil || opID == [16]byte{} {
		return receiptDownloadOperation{}, errors.New("generate receipt download retry operation identity")
	}
	key, err := newKey()
	if err != nil || key == [32]byte{} {
		return receiptDownloadOperation{}, errors.New("generate receipt download retry idempotency identity")
	}
	manifest, err := attachmentv3.DecodeManifest(record.manifest)
	if err != nil || manifest.TransferID != record.transferID {
		return receiptDownloadOperation{}, errors.New("invalid receipt download retry manifest")
	}
	request := previous.request
	request.RequestID, request.IssuedAt = requestID, uint64(now.UTC().Unix())
	expires := now.UTC().Add(20 * time.Second).Unix()
	if uint64(expires) > manifest.ExpiresAt {
		expires = int64(manifest.ExpiresAt)
	}
	if expires <= now.UTC().Unix() {
		return receiptDownloadOperation{}, errors.New("expired receipt download retry offer")
	}
	request.ExpiresAt = uint64(expires)
	if err := signer(&request); err != nil {
		return receiptDownloadOperation{}, err
	}
	raw, err := attachmentv3.EncodePermitRequest(request)
	if err != nil {
		return receiptDownloadOperation{}, err
	}
	attempt := previous.attempt + 1
	_, err = j.db.ExecContext(context.Background(), `INSERT INTO controller_receipt_download_operation_retries(punaro_message_id,phase,chunk_index,attempt_index,permit_request,operation_id,idempotency_key) VALUES(?,?,?,?,?,?,?) ON CONFLICT(punaro_message_id,phase,chunk_index,attempt_index) DO NOTHING`, record.messageID, string(previous.phase), int64(previous.chunk), int64(attempt), raw, opID[:], key[:])
	if err != nil {
		return receiptDownloadOperation{}, err
	}
	stored, found, err := j.receiptDownloadRetryOperation(record.messageID, previous.phase, previous.chunk, attempt)
	if err != nil || !found || !sameReceiptDownloadRetryIntent(stored, previous) {
		return receiptDownloadOperation{}, errors.New("changed receipt download retry")
	}
	return stored, nil
}

func sameReceiptDownloadRetryIntent(stored, previous receiptDownloadOperation) bool {
	return stored.phase == previous.phase && stored.chunk == previous.chunk && stored.attempt == previous.attempt+1 && stored.request.Operation == attachmentv3.PermitOperationDownload && stored.request.HolderDeviceID == previous.request.HolderDeviceID && stored.request.HolderGeneration == previous.request.HolderGeneration && stored.request.HolderRole == previous.request.HolderRole && stored.request.TransferID == previous.request.TransferID && stored.request.ConversationID == previous.request.ConversationID && stored.request.SenderDeviceID == previous.request.SenderDeviceID && stored.request.SenderGeneration == previous.request.SenderGeneration && stored.request.RecipientDeviceID == previous.request.RecipientDeviceID && stored.request.RecipientGeneration == previous.request.RecipientGeneration && stored.request.AttemptGeneration == previous.request.AttemptGeneration && stored.request.MembershipCommitment == previous.request.MembershipCommitment && stored.request.StagedManifestCommitment == previous.request.StagedManifestCommitment && stored.request.MaxBytes == previous.request.MaxBytes && stored.request.MaxChunks == previous.request.MaxChunks && stored.request.MaxOperations == previous.request.MaxOperations
}

// storeReceiptDownloadPermit records an issuance receipt before an operation
// is built. An expired receipt is not usable as a capability, but its serial
// is the only safe correlation handle for the relay outcome after a crash.
func (j *Journal) storeReceiptDownloadPermit(record receiptDownloadRecord, operation receiptDownloadOperation, permit attachmentv3.Permit) (receiptDownloadOperation, error) {
	raw, err := attachmentv3.EncodePermit(permit)
	if err != nil {
		return receiptDownloadOperation{}, err
	}
	table, where := "controller_receipt_download_operations", "punaro_message_id=? AND phase=? AND chunk_index=?"
	args := []any{raw, record.messageID, string(operation.phase), int64(operation.chunk)}
	if operation.attempt != 0 {
		table, where = "controller_receipt_download_operation_retries", where+" AND attempt_index=?"
		args = append(args, int64(operation.attempt))
	}
	result, err := j.db.ExecContext(context.Background(), `UPDATE `+table+` SET permit=? WHERE `+where+` AND permit IS NULL`, args...)
	if err != nil {
		return receiptDownloadOperation{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return receiptDownloadOperation{}, err
	}
	stored, found, err := j.receiptDownloadOperationAt(record.messageID, operation.phase, operation.chunk, operation.attempt)
	if err != nil || !found || len(stored.permit) == 0 || (changed == 0 && !bytes.Equal(stored.permit, raw)) {
		return receiptDownloadOperation{}, errors.New("changed durable receipt download permit")
	}
	return stored, nil
}

func (j *Journal) storeReceiptDownloadOperationSignature(record receiptDownloadRecord, operation receiptDownloadOperation, signed attachmentv3.OperationRecord) (receiptDownloadOperation, error) {
	raw, err := attachmentv3.EncodeOperation(signed)
	if err != nil {
		return receiptDownloadOperation{}, err
	}
	table, where := "controller_receipt_download_operations", "punaro_message_id=? AND phase=? AND chunk_index=?"
	args := []any{raw, record.messageID, string(operation.phase), int64(operation.chunk)}
	if operation.attempt != 0 {
		table, where = "controller_receipt_download_operation_retries", where+" AND attempt_index=?"
		args = append(args, int64(operation.attempt))
	}
	result, err := j.db.ExecContext(context.Background(), `UPDATE `+table+` SET operation=? WHERE `+where+` AND operation IS NULL`, args...)
	if err != nil {
		return receiptDownloadOperation{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return receiptDownloadOperation{}, err
	}
	stored, found, err := j.receiptDownloadOperationAt(record.messageID, operation.phase, operation.chunk, operation.attempt)
	if err != nil || !found || len(stored.operation) == 0 || (changed == 0 && !bytes.Equal(stored.operation, raw)) {
		return receiptDownloadOperation{}, errors.New("changed durable receipt download operation signature")
	}
	return stored, nil
}

func (j *Journal) storeReceiptDownloadResult(record receiptDownloadRecord, operation receiptDownloadOperation, result []byte) error {
	if len(result) == 0 {
		return errors.New("invalid receipt download result")
	}
	table, where := "controller_receipt_download_operations", "punaro_message_id=? AND phase=? AND chunk_index=?"
	args := []any{result, record.messageID, string(operation.phase), int64(operation.chunk)}
	if operation.attempt != 0 {
		table, where = "controller_receipt_download_operation_retries", where+" AND attempt_index=?"
		args = append(args, int64(operation.attempt))
	}
	changed, err := j.db.ExecContext(context.Background(), `UPDATE `+table+` SET result=? WHERE `+where+` AND result IS NULL`, args...)
	if err != nil {
		return err
	}
	n, err := changed.RowsAffected()
	if err != nil {
		return err
	}
	if n == 1 {
		return nil
	}
	stored, found, err := j.receiptDownloadOperationAt(record.messageID, operation.phase, operation.chunk, operation.attempt)
	if err != nil || !found || !bytes.Equal(stored.result, result) {
		return errors.New("changed durable receipt download result")
	}
	return nil
}

func (j *Journal) receiptDownloadOperationAt(messageID string, phase receiptDownloadPhase, chunk, attempt uint64) (receiptDownloadOperation, bool, error) {
	if attempt == 0 {
		return j.receiptDownloadOperation(messageID, phase, chunk)
	}
	return j.receiptDownloadRetryOperation(messageID, phase, chunk, attempt)
}

func (j *Journal) storeReceiptDownloadChunk(record receiptDownloadRecord, index uint64, ciphertext []byte) error {
	if len(ciphertext) == 0 {
		return errors.New("invalid receipt ciphertext")
	}
	commitment := receiptCiphertextCommitment(ciphertext)
	_, err := j.db.ExecContext(context.Background(), `INSERT INTO controller_receipt_download_chunks(punaro_message_id,chunk_index,ciphertext,ciphertext_commitment) VALUES (?,?,?,?) ON CONFLICT(punaro_message_id,chunk_index) DO NOTHING`, record.messageID, int64(index), ciphertext, commitment[:])
	if err != nil {
		return err
	}
	var stored, storedCommitment []byte
	err = j.db.QueryRowContext(context.Background(), `SELECT ciphertext,ciphertext_commitment FROM controller_receipt_download_chunks WHERE punaro_message_id=? AND chunk_index=?`, record.messageID, int64(index)).Scan(&stored, &storedCommitment)
	if err != nil || len(storedCommitment) != 32 || !bytes.Equal(stored, ciphertext) || !bytes.Equal(storedCommitment, commitment[:]) {
		return errors.New("changed durable receipt ciphertext")
	}
	return nil
}

func (j *Journal) receiptDownloadChunk(record receiptDownloadRecord, index uint64) ([]byte, bool, error) {
	var ciphertext, commitment []byte
	err := j.db.QueryRowContext(context.Background(), `SELECT ciphertext,ciphertext_commitment FROM controller_receipt_download_chunks WHERE punaro_message_id=? AND chunk_index=?`, record.messageID, int64(index)).Scan(&ciphertext, &commitment)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil || len(ciphertext) == 0 || len(commitment) != 32 {
		return nil, false, errors.New("invalid durable receipt ciphertext")
	}
	calculated := receiptCiphertextCommitment(ciphertext)
	if !bytes.Equal(commitment, calculated[:]) {
		return nil, false, errors.New("invalid durable receipt ciphertext")
	}
	return append([]byte(nil), ciphertext...), true, nil
}

func (j *Journal) receiptDownloadChunks(record receiptDownloadRecord, count uint64) ([]attachmentv3.EncryptedChunk, error) {
	if count == 0 || count > 4096 {
		return nil, errors.New("invalid receipt chunk count")
	}
	rows, err := j.db.QueryContext(context.Background(), `SELECT chunk_index,ciphertext,ciphertext_commitment FROM controller_receipt_download_chunks WHERE punaro_message_id=? ORDER BY chunk_index`, record.messageID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	chunks := make([]attachmentv3.EncryptedChunk, 0, count)
	for rows.Next() {
		var index int64
		var ciphertext, commitment []byte
		if err := rows.Scan(&index, &ciphertext, &commitment); err != nil || index < 0 || uint64(index) != uint64(len(chunks)) || len(commitment) != 32 || len(ciphertext) == 0 {
			return nil, errors.New("invalid durable receipt ciphertext")
		}
		calculated := receiptCiphertextCommitment(ciphertext)
		if !bytes.Equal(commitment, calculated[:]) {
			return nil, errors.New("invalid durable receipt ciphertext")
		}
		var hash [32]byte
		copy(hash[:], commitment)
		chunks = append(chunks, attachmentv3.EncryptedChunk{Index: uint64(index), Ciphertext: append([]byte(nil), ciphertext...), CiphertextCommitment: hash})
	}
	if err := rows.Err(); err != nil || uint64(len(chunks)) != count {
		return nil, errors.New("incomplete durable receipt ciphertext")
	}
	return chunks, nil
}

func (j *Journal) clearReceiptDownloadChunks(record receiptDownloadRecord) error {
	if j == nil || j.db == nil || record.messageID == "" {
		return errors.New("invalid receipt ciphertext reset")
	}
	_, err := j.db.ExecContext(context.Background(), `DELETE FROM controller_receipt_download_chunks WHERE punaro_message_id=?`, record.messageID)
	return err
}

func receiptCiphertextCommitment(ciphertext []byte) [32]byte {
	return blake3.Sum256(append([]byte("punaro/attachment/ciphertext/v3\x00"), ciphertext...))
}

func (j *Journal) markReceiptDownloadWritten(record receiptDownloadRecord) error {
	result, err := j.db.ExecContext(context.Background(), `UPDATE controller_receipt_downloads SET state='written' WHERE punaro_message_id=? AND state='active'`, record.messageID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 1 {
		return nil
	}
	stored, found, err := j.receiptDownload(record.messageID)
	if err != nil || !found || stored.state != receiptDownloadWritten {
		return errors.New("receipt output state transition failed")
	}
	return nil
}
