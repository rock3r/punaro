package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
	"github.com/zeebo/blake3"
)

// SenderDeliveryAuthority is one root-verified directory snapshot for an
// outbound source transition. It intentionally combines source verification,
// permit verification and the holder key in one view, preventing a locally
// staged source from being sent under incompatible directory facts.
type SenderDeliveryAuthority interface {
	TransferBindingResolver
	attachmentv3.EnvelopeDirectoryKeyResolver
	attachmentv3.PermitAuthorityResolver
	attachmentv3.OperationHolderResolver
}

// SenderDeliveryAuthorityProvider returns a fresh root-verified authority view
// for one outbound sender transition.
type SenderDeliveryAuthorityProvider interface {
	ResolveSenderDeliveryAuthority(context.Context, time.Time) (SenderDeliveryAuthority, error)
}

// SenderOperationSigner is deliberately limited to sender permits and the
// three outbound lifecycle operations. It is not a generic signing oracle.
type SenderOperationSigner interface {
	SignSenderPermit(*attachmentv3.PermitRequest) error
	BuildSenderOperation(attachmentv3.Permit, string, string, []byte, [16]byte, [32]byte, uint64, uint64) (attachmentv3.OperationRecord, error)
}

// SenderEnvelopeSealer confines host-unwrapped file-key use to construction
// of the one recipient envelope for a fully staged source.
type SenderEnvelopeSealer interface {
	SealSenderEnvelope(attachmentv3.VerifiedSource, attachmentv3.EnvelopeDirectoryKeyResolver, [32]byte, time.Time) (attachmentv3.Envelope, error)
}

// SenderLocalOperationSigner is the complete sender capability set held by
// the local privileged implementation.
type SenderLocalOperationSigner interface {
	SenderOperationSigner
	SenderEnvelopeSealer
}

type localSenderOperationSigner struct {
	sender  SenderIdentity
	private ed25519.PrivateKey
}

// NewLocalSenderOperationSigner returns a sender-bound signer that keeps its
// private key in the local privileged process.
func NewLocalSenderOperationSigner(sender SenderIdentity, private ed25519.PrivateKey) SenderLocalOperationSigner {
	return &localSenderOperationSigner{sender: sender, private: append(ed25519.PrivateKey(nil), private...)}
}

func validSenderOperation(operation uint64) bool {
	return operation == attachmentv3.PermitOperationSourceInit || operation == attachmentv3.PermitOperationSourceUpload || operation == attachmentv3.PermitOperationOffer || operation == attachmentv3.PermitOperationOutcome
}

func (s *localSenderOperationSigner) SignSenderPermit(request *attachmentv3.PermitRequest) error {
	if s == nil || !s.sender.valid() || len(s.private) != ed25519.PrivateKeySize || request == nil || request.HolderDeviceID != s.sender.DeviceID || request.HolderGeneration != s.sender.Generation || request.HolderRole != attachmentv3.PermitHolderSender || request.AttemptGeneration != 0 || !validSenderOperation(request.Operation) {
		return errors.New("invalid local sender permit signing request")
	}
	return attachmentv3.SignPermitRequest(request, s.private)
}

func (s *localSenderOperationSigner) BuildSenderOperation(permit attachmentv3.Permit, method, path string, body []byte, operationID [16]byte, idempotencyKey [32]byte, issuedAt, expiresAt uint64) (attachmentv3.OperationRecord, error) {
	if s == nil || !s.sender.valid() || len(s.private) != ed25519.PrivateKeySize || permit.HolderDeviceID != s.sender.DeviceID || permit.HolderGeneration != s.sender.Generation || permit.HolderRole != attachmentv3.PermitHolderSender || permit.AttemptGeneration != 0 || !validSenderOperation(permit.Operation) {
		return attachmentv3.OperationRecord{}, errors.New("invalid local sender operation")
	}
	return attachmentv3.BuildSignedAttachmentOperation(permit, method, path, body, operationID, idempotencyKey, issuedAt, expiresAt, s.private)
}

func (s *localSenderOperationSigner) SealSenderEnvelope(source attachmentv3.VerifiedSource, directory attachmentv3.EnvelopeDirectoryKeyResolver, fileKey [32]byte, now time.Time) (attachmentv3.Envelope, error) {
	if s == nil || !s.sender.valid() || len(s.private) != ed25519.PrivateKeySize || directory == nil || fileKey == [32]byte{} {
		return attachmentv3.Envelope{}, errors.New("invalid local sender envelope request")
	}
	return attachmentv3.SealRecipientEnvelope(source, directory, fileKey, s.private, now)
}

// SenderSourceInitializerOptions configures durable source-init and upload
// processing for a sender-bound journal.
type SenderSourceInitializerOptions struct {
	Journal           *Journal
	AuthorityProvider SenderDeliveryAuthorityProvider
	Signer            SenderOperationSigner
	Transport         RecipientAttachmentTransport
	Now               func() time.Time
	NewID             func() ([16]byte, error)
	NewIdempotencyKey func() ([32]byte, error)
	// UploadWindow limits concurrent remote chunk mutations. It defaults to
	// 16 and is capped so one staged transfer cannot exhaust local resources.
	UploadWindow uint8
}

// SenderSourceInitializer advances a locally staged immutable source through
// the one bootstrap operation. It never handles plaintext and persists the
// exact holder-signed capability before the remote mutation is attempted.
type SenderSourceInitializer struct {
	options SenderSourceInitializerOptions
}

// SenderOfferWorkerOptions configures envelope sealing and durable outbound
// offer notification for an initialized sender source.
type SenderOfferWorkerOptions struct {
	Source              *SenderSourceInitializer
	FileKeyProtector    SenderFileKeyProtector
	NewAcceptanceNonce  func() ([32]byte, error)
	RelaySenderEndpoint string
	OfferNoticeQueue    OfferNoticeQueue
}

// OfferNoticeQueue durably reserves and activates the relay notice for one
// completed sender offer.
type OfferNoticeQueue interface {
	ReserveV3OfferNotice(context.Context, string, string, []byte, string) error
	ActivateV3OfferNotice(context.Context, string) error
}

// SenderOfferWorker exposes a complete encrypted source through the relay
// only after it has sealed and durably retained the recipient-specific offer.
type SenderOfferWorker struct {
	options SenderOfferWorkerOptions
	sealer  SenderEnvelopeSealer
}

// NewSenderOfferWorker constructs a worker that seals and queues relay offers.
func NewSenderOfferWorker(options SenderOfferWorkerOptions) (*SenderOfferWorker, error) {
	if options.Source == nil || options.Source.options.Journal == nil || options.FileKeyProtector == nil || options.NewAcceptanceNonce == nil || !validRelayIdentifier(options.RelaySenderEndpoint) || options.OfferNoticeQueue == nil {
		return nil, errors.New("invalid sender offer worker")
	}
	sealer, ok := options.Source.options.Signer.(SenderEnvelopeSealer)
	if !ok || sealer == nil {
		return nil, errors.New("sender operation signer cannot seal envelopes")
	}
	return &SenderOfferWorker{options: options, sealer: sealer}, nil
}

// NewSenderSourceInitializer constructs a worker for the sender source-init
// and upload lifecycle.
func NewSenderSourceInitializer(options SenderSourceInitializerOptions) (*SenderSourceInitializer, error) {
	if options.Journal == nil || options.Journal.db == nil || !options.Journal.sender.valid() || options.AuthorityProvider == nil || options.Signer == nil || options.Transport == nil || options.NewID == nil || options.NewIdempotencyKey == nil {
		return nil, errors.New("invalid sender source initializer")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.UploadWindow == 0 {
		options.UploadWindow = 16
	}
	if options.UploadWindow > 64 {
		return nil, errors.New("invalid sender upload window")
	}
	return &SenderSourceInitializer{options: options}, nil
}

// Initialize performs source-init exactly once for a staged transfer. If a
// prior submission is ambiguous and its capability has expired, it fails
// closed; a later outcome-reconciliation worker is the only valid recovery
// route and must not mint a different source-init operation.
func (w *SenderSourceInitializer) Initialize(ctx context.Context, transferID [16]byte) (attachmentv3.TransferResult, error) {
	if w == nil || transferID == [16]byte{} {
		return attachmentv3.TransferResult{}, errors.New("invalid sender source initialization")
	}
	w.options.Journal.senderMu.Lock()
	defer w.options.Journal.senderMu.Unlock()
	now := w.options.Now().UTC()
	if now.Unix() < 0 {
		return attachmentv3.TransferResult{}, errors.New("invalid sender source initialization clock")
	}
	authority, err := w.options.AuthorityProvider.ResolveSenderDeliveryAuthority(ctx, now)
	if err != nil || authority == nil {
		return attachmentv3.TransferResult{}, errors.New("fresh sender delivery authority is unavailable")
	}
	transfer, err := w.options.Journal.senderTransfer(transferID)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	mapping, found, err := w.options.Journal.mapping(transfer.relayConversationID)
	if err != nil || !found || !mapping.valid() || mapping.SenderDeviceID != w.options.Journal.sender.DeviceID || mapping.SenderGeneration != w.options.Journal.sender.Generation {
		return attachmentv3.TransferResult{}, errors.New("sender source mapping is unavailable")
	}
	binding, err := authority.ResolveTransferBinding(ctx, mapping.ConversationID, mapping.SenderDeviceID, mapping.SenderGeneration, mapping.RecipientDeviceID, mapping.RecipientGeneration, mapping.MembershipCommitment, now)
	if err != nil || !exactTransferBinding(mapping, binding, now) {
		return attachmentv3.TransferResult{}, errors.New("fresh sender source binding is unavailable")
	}
	verified, err := attachmentv3.DecodeAndVerifySourceInit(transfer.manifest, authority, now)
	manifest, manifestErr := attachmentv3.DecodeManifest(transfer.manifest)
	if err != nil || manifestErr != nil || verified.ManifestCommitment() != transfer.commitment || !exactStagedManifest(manifest, mapping, binding, now) {
		return attachmentv3.TransferResult{}, errors.New("invalid durable sender source")
	}
	record, err := w.options.Journal.ensureSenderOperation(transfer, senderPhaseSourceInit, 0, uint64(len(transfer.manifest)), now, w.options.Signer, w.options.NewID, w.options.NewIdempotencyKey)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	if len(record.result) != 0 {
		return exactSenderResult(record.result, transfer, attachmentv3.TransferStateSourceUploading)
	}
	permit, operation, err := w.credentials(ctx, transfer, senderPhaseSourceInit, 0, record, transfer.manifest, authority, now)
	if err != nil {
		if reconciled, reconcileErr := w.reconcileExpired(ctx, transfer.transferID, senderPhaseSourceInit, 0, record, now); reconcileErr == nil {
			return reconciled, nil
		}
		return attachmentv3.TransferResult{}, err
	}
	raw, err := w.options.Transport.DoV3Attachment(ctx, "POST", sourceInitPath(transfer.transferID), transfer.manifest, permit, operation)
	if err != nil {
		return attachmentv3.TransferResult{}, fmt.Errorf("submit sender source initialization: %w", err)
	}
	result, err := exactSenderResult(raw, transfer, attachmentv3.TransferStateSourceUploading)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	if err := w.options.Journal.storeSenderOperationResult(transfer.transferID, senderPhaseSourceInit, 0, raw); err != nil {
		return attachmentv3.TransferResult{}, err
	}
	return result, nil
}

// UploadAll sends each durable ciphertext frame through a separately
// persisted, exactly route-bound operation. The plaintext and file key stay
// out of this worker; it reads only immutable local ciphertext.
func (w *SenderSourceInitializer) UploadAll(ctx context.Context, transferID [16]byte) (attachmentv3.TransferResult, error) {
	initialized, err := w.Initialize(ctx, transferID)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	if initialized.State != attachmentv3.TransferStateSourceUploading {
		return initialized, nil
	}
	transfer, err := w.options.Journal.senderTransfer(transferID)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	manifest, err := attachmentv3.DecodeManifest(transfer.manifest)
	if err != nil || manifest.ChunkCount == 0 {
		return attachmentv3.TransferResult{}, errors.New("invalid durable sender source")
	}
	window := uint64(w.options.UploadWindow)
	if window > manifest.ChunkCount {
		window = manifest.ChunkCount
	}
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type uploadResult struct {
		result attachmentv3.TransferResult
		err    error
	}
	jobs := make(chan uint64)
	results := make(chan uploadResult, window)
	var workers sync.WaitGroup
	for worker := uint64(0); worker < window; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				result, err := w.uploadOne(workCtx, transferID, index)
				results <- uploadResult{result: result, err: err}
				if err != nil {
					cancel()
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for index := uint64(0); index < manifest.ChunkCount; index++ {
			select {
			case jobs <- index:
			case <-workCtx.Done():
				return
			}
		}
	}()
	go func() { workers.Wait(); close(results) }()
	var ready attachmentv3.TransferResult
	var terminal attachmentv3.TransferResult
	var firstErr error
	for item := range results {
		if item.err != nil && firstErr == nil {
			firstErr = item.err
			continue
		}
		switch item.result.State {
		case attachmentv3.TransferStateSourceReady:
			ready = item.result
		case attachmentv3.TransferStateCancelled, attachmentv3.TransferStateExpired, attachmentv3.TransferStateRevoked:
			cancel()
			terminal = item.result
		}
	}
	if firstErr != nil {
		return attachmentv3.TransferResult{}, firstErr
	}
	if terminal.TransferID != [16]byte{} {
		return terminal, nil
	}
	if ready.TransferID == [16]byte{} {
		return attachmentv3.TransferResult{}, errors.New("sender uploads did not reach source ready")
	}
	return ready, nil
}

func (w *SenderSourceInitializer) uploadOne(ctx context.Context, transferID [16]byte, index uint64) (attachmentv3.TransferResult, error) {
	now := w.options.Now().UTC()
	if now.Unix() < 0 {
		return attachmentv3.TransferResult{}, errors.New("invalid sender upload clock")
	}
	authority, err := w.options.AuthorityProvider.ResolveSenderDeliveryAuthority(ctx, now)
	if err != nil || authority == nil {
		return attachmentv3.TransferResult{}, errors.New("fresh sender delivery authority is unavailable")
	}
	transfer, manifest, err := w.freshSenderTransfer(ctx, transferID, authority, now)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	if index >= manifest.ChunkCount {
		return attachmentv3.TransferResult{}, errors.New("invalid sender upload index")
	}
	chunk, err := w.options.Journal.senderChunk(transfer.transferID, manifest, index)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	// Serialize local identity generation and the intent insert, but release
	// before permit issuance and HTTP so the bounded window is genuinely
	// concurrent on the network data plane.
	w.options.Journal.senderMu.Lock()
	record, err := w.options.Journal.ensureSenderOperation(transfer, senderPhaseSourceUpload, index, uint64(len(chunk)), now, w.options.Signer, w.options.NewID, w.options.NewIdempotencyKey)
	w.options.Journal.senderMu.Unlock()
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	if len(record.result) != 0 {
		return exactSenderUploadResult(record.result, transfer)
	}
	permit, operation, err := w.credentials(ctx, transfer, senderPhaseSourceUpload, index, record, chunk, authority, now)
	if err != nil {
		if reconciled, reconcileErr := w.reconcileExpired(ctx, transfer.transferID, senderPhaseSourceUpload, index, record, now); reconcileErr == nil {
			return reconciled, nil
		}
		return attachmentv3.TransferResult{}, err
	}
	_, _, path, err := senderOperationSpec(transfer.transferID, senderPhaseSourceUpload, index)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	raw, err := w.options.Transport.DoV3Attachment(ctx, "PUT", path, chunk, permit, operation)
	if err != nil {
		return attachmentv3.TransferResult{}, fmt.Errorf("submit sender source upload: %w", err)
	}
	result, err := exactSenderUploadResult(raw, transfer)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	if err := w.options.Journal.storeSenderOperationResult(transfer.transferID, senderPhaseSourceUpload, index, raw); err != nil {
		return attachmentv3.TransferResult{}, err
	}
	return result, nil
}

func (w *SenderSourceInitializer) freshSenderTransfer(ctx context.Context, transferID [16]byte, authority SenderDeliveryAuthority, now time.Time) (senderTransferRecord, attachmentv3.Manifest, error) {
	transfer, err := w.options.Journal.senderTransfer(transferID)
	if err != nil {
		return senderTransferRecord{}, attachmentv3.Manifest{}, err
	}
	mapping, found, err := w.options.Journal.mapping(transfer.relayConversationID)
	if err != nil || !found || !mapping.valid() || mapping.SenderDeviceID != w.options.Journal.sender.DeviceID || mapping.SenderGeneration != w.options.Journal.sender.Generation {
		return senderTransferRecord{}, attachmentv3.Manifest{}, errors.New("sender source mapping is unavailable")
	}
	binding, err := authority.ResolveTransferBinding(ctx, mapping.ConversationID, mapping.SenderDeviceID, mapping.SenderGeneration, mapping.RecipientDeviceID, mapping.RecipientGeneration, mapping.MembershipCommitment, now)
	if err != nil || !exactTransferBinding(mapping, binding, now) {
		return senderTransferRecord{}, attachmentv3.Manifest{}, errors.New("fresh sender source binding is unavailable")
	}
	verified, err := attachmentv3.DecodeAndVerifySourceInit(transfer.manifest, authority, now)
	manifest, decodeErr := attachmentv3.DecodeManifest(transfer.manifest)
	if err != nil || decodeErr != nil || verified.ManifestCommitment() != transfer.commitment || !exactStagedManifest(manifest, mapping, binding, now) {
		return senderTransferRecord{}, attachmentv3.Manifest{}, errors.New("invalid durable sender source")
	}
	return transfer, manifest, nil
}

// Offer publishes the recipient envelope and acceptance nonce only after the
// source has reached source-ready. Every retry re-verifies the exact durable
// offer against the current directory before reusing it.
func (w *SenderOfferWorker) Offer(ctx context.Context, transferID [16]byte) (attachmentv3.TransferResult, error) {
	if w == nil || transferID == [16]byte{} {
		return attachmentv3.TransferResult{}, errors.New("invalid sender offer request")
	}
	if _, err := w.options.Source.UploadAll(ctx, transferID); err != nil {
		return attachmentv3.TransferResult{}, err
	}
	sourceWorker := w.options.Source
	sourceWorker.options.Journal.senderMu.Lock()
	defer sourceWorker.options.Journal.senderMu.Unlock()
	now := sourceWorker.options.Now().UTC()
	if now.Unix() < 0 {
		return attachmentv3.TransferResult{}, errors.New("invalid sender offer clock")
	}
	authority, err := sourceWorker.options.AuthorityProvider.ResolveSenderDeliveryAuthority(ctx, now)
	if err != nil || authority == nil {
		return attachmentv3.TransferResult{}, errors.New("fresh sender delivery authority is unavailable")
	}
	transfer, manifest, err := sourceWorker.freshSenderTransfer(ctx, transferID, authority, now)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	verified, err := attachmentv3.DecodeAndVerifySourceInit(transfer.manifest, authority, now)
	if err != nil || verified.ManifestCommitment() != transfer.commitment {
		return attachmentv3.TransferResult{}, errors.New("invalid durable sender source")
	}
	offer, err := w.ensureOffer(ctx, transfer, manifest, verified, authority, now)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	if err := w.reserveOfferNotice(ctx, transfer, offer); err != nil {
		return attachmentv3.TransferResult{}, err
	}
	record, err := sourceWorker.options.Journal.ensureSenderOperation(transfer, senderPhaseOffer, 0, uint64(len(offer)), now, sourceWorker.options.Signer, sourceWorker.options.NewID, sourceWorker.options.NewIdempotencyKey)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	if len(record.result) != 0 {
		result, err := exactSenderResult(record.result, transfer, attachmentv3.TransferStateOffered)
		if err != nil {
			return attachmentv3.TransferResult{}, err
		}
		return result, w.activateOfferNotice(ctx, transfer)
	}
	permit, operation, err := sourceWorker.credentials(ctx, transfer, senderPhaseOffer, 0, record, offer, authority, now)
	if err != nil {
		if reconciled, reconcileErr := sourceWorker.reconcileExpired(ctx, transfer.transferID, senderPhaseOffer, 0, record, now); reconcileErr == nil {
			if reconciled.State == attachmentv3.TransferStateOffered {
				return reconciled, w.activateOfferNotice(ctx, transfer)
			}
			return reconciled, nil
		}
		return attachmentv3.TransferResult{}, err
	}
	_, _, path, err := senderOperationSpec(transfer.transferID, senderPhaseOffer, 0)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	raw, err := sourceWorker.options.Transport.DoV3Attachment(ctx, "POST", path, offer, permit, operation)
	if err != nil {
		return attachmentv3.TransferResult{}, fmt.Errorf("submit sender offer: %w", err)
	}
	result, err := exactSenderResult(raw, transfer, attachmentv3.TransferStateOffered)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	if err := sourceWorker.options.Journal.storeSenderOperationResult(transfer.transferID, senderPhaseOffer, 0, raw); err != nil {
		return attachmentv3.TransferResult{}, err
	}
	if err := w.activateOfferNotice(ctx, transfer); err != nil {
		return attachmentv3.TransferResult{}, err
	}
	return result, nil
}

func (w *SenderOfferWorker) reserveOfferNotice(ctx context.Context, transfer senderTransferRecord, offer []byte) error {
	if w == nil || w.options.OfferNoticeQueue == nil || !validRelayIdentifier(transfer.relayConversationID) || !validRelayIdentifier(w.options.RelaySenderEndpoint) || len(offer) == 0 {
		return errors.New("sender offer notice queue is unavailable")
	}
	// Pin the source before reserving the external outbox row. A crash between
	// these durable commits is conservative: the source remains recoverable and
	// no remote offer has yet been attempted.
	if err := w.options.Source.options.Journal.holdSenderOffer(transfer.transferID); err != nil {
		return err
	}
	if err := w.options.OfferNoticeQueue.ReserveV3OfferNotice(ctx, transfer.relayConversationID, w.options.RelaySenderEndpoint, offer, fmt.Sprintf("v3-offer-%x", transfer.transferID)); err != nil {
		return err
	}
	return nil
}

func (w *SenderOfferWorker) activateOfferNotice(ctx context.Context, transfer senderTransferRecord) error {
	if w == nil || w.options.OfferNoticeQueue == nil || transfer.transferID == [16]byte{} {
		return errors.New("sender offer notice queue is unavailable")
	}
	if err := w.options.OfferNoticeQueue.ActivateV3OfferNotice(ctx, fmt.Sprintf("v3-offer-%x", transfer.transferID)); err != nil {
		return err
	}
	return w.options.Source.options.Journal.releaseSenderOfferHold(transfer.transferID)
}

func (w *SenderOfferWorker) ensureOffer(ctx context.Context, transfer senderTransferRecord, manifest attachmentv3.Manifest, source attachmentv3.VerifiedSource, authority SenderDeliveryAuthority, now time.Time) ([]byte, error) {
	if existing, found, err := w.options.Source.options.Journal.senderOffer(transfer.transferID); err != nil || found {
		if err != nil || !found {
			return nil, errors.New("invalid durable sender offer")
		}
		noticeBody, err := attachmentv3.EncodeOfferNotice(existing.offer)
		notice, decodeErr := attachmentv3.DecodeOfferNotice(noticeBody)
		if err != nil || decodeErr != nil || !bytes.Equal(notice.ManifestRaw, transfer.manifest) || notice.Manifest.TransferID != transfer.transferID || blake3.Sum256(notice.ManifestRaw) != transfer.commitment {
			return nil, errors.New("invalid durable sender offer")
		}
		if _, _, err := attachmentv3.VerifyOfferNotice(notice, authority, now); err != nil {
			return nil, errors.New("invalid durable sender offer")
		}
		return existing.offer, nil
	}
	fileKey, err := w.options.FileKeyProtector.OpenSenderFileKey(ctx, transfer.wrappedFileKey, senderKeyAAD(transfer.transferID, transfer.commitment))
	if err != nil || fileKey == [32]byte{} {
		return nil, errors.New("open sender file key")
	}
	envelope, err := w.sealer.SealSenderEnvelope(source, authority, fileKey, now)
	if err != nil {
		return nil, errors.New("seal recipient envelope")
	}
	nonce, err := w.options.NewAcceptanceNonce()
	if err != nil || nonce == [32]byte{} {
		return nil, errors.New("generate sender acceptance nonce")
	}
	offer, err := attachmentv3.EncodeOfferPayload(manifest, envelope, nonce)
	if err != nil {
		return nil, err
	}
	stored, err := w.options.Source.options.Journal.storeSenderOffer(transfer.transferID, envelope, offer, nonce)
	if err != nil {
		return nil, err
	}
	return stored.offer, nil
}

type senderOfferRecord struct {
	envelope, offer []byte
	nonce           [32]byte
}

func (j *Journal) senderOffer(transferID [16]byte) (senderOfferRecord, bool, error) {
	var out senderOfferRecord
	var nonce []byte
	err := j.db.QueryRowContext(context.Background(), `SELECT envelope,offer,offer_nonce FROM controller_sender_transfers WHERE transfer_id=?`, transferID[:]).Scan(&out.envelope, &out.offer, &nonce)
	if err != nil || (out.envelope == nil && out.offer == nil && nonce == nil) {
		if errors.Is(err, sql.ErrNoRows) {
			return senderOfferRecord{}, false, nil
		}
		if err == nil {
			return senderOfferRecord{}, false, nil
		}
		return senderOfferRecord{}, false, errors.New("invalid durable sender offer")
	}
	if len(out.envelope) == 0 || len(out.offer) == 0 || len(nonce) != 32 {
		return senderOfferRecord{}, false, errors.New("invalid durable sender offer")
	}
	copy(out.nonce[:], nonce)
	return out, true, nil
}

func (j *Journal) storeSenderOffer(transferID [16]byte, envelope attachmentv3.Envelope, offer []byte, nonce [32]byte) (senderOfferRecord, error) {
	rawEnvelope, err := attachmentv3.EncodeEnvelope(envelope)
	if err != nil {
		return senderOfferRecord{}, err
	}
	if len(offer) == 0 || nonce == [32]byte{} {
		return senderOfferRecord{}, errors.New("invalid sender offer")
	}
	result, err := j.db.ExecContext(context.Background(), `UPDATE controller_sender_transfers SET envelope=?,offer=?,offer_nonce=? WHERE transfer_id=? AND envelope IS NULL AND offer IS NULL AND offer_nonce IS NULL`, rawEnvelope, offer, nonce[:], transferID[:])
	if err != nil {
		return senderOfferRecord{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return senderOfferRecord{}, err
	}
	stored, found, err := j.senderOffer(transferID)
	if err != nil || !found || (changed == 0 && (!bytes.Equal(stored.envelope, rawEnvelope) || !bytes.Equal(stored.offer, offer) || stored.nonce != nonce)) {
		return senderOfferRecord{}, errors.New("changed durable sender offer")
	}
	return stored, nil
}

type senderPhase string

const (
	// The protocol caps manifest/permit lifetimes at 30 seconds. Keep the
	// original operation and its outcome capability deliberately shorter so an
	// expired submission can be reconciled while the signed manifest remains
	// fresh; otherwise recovery would be mathematically unreachable.
	senderOperationLifetime = 15 * time.Second
	senderOutcomeLifetime   = 10 * time.Second
)

const (
	senderPhaseSourceInit   senderPhase = "source-init"
	senderPhaseSourceUpload senderPhase = "source-upload"
	senderPhaseOffer        senderPhase = "offer"
)

type senderTransferRecord struct {
	transferID          [16]byte
	relayConversationID string
	manifest            []byte
	commitment          [32]byte
	wrappedFileKey      []byte
}

func (j *Journal) senderTransfer(transferID [16]byte) (senderTransferRecord, error) {
	var out senderTransferRecord
	var id, commitment []byte
	err := j.db.QueryRowContext(context.Background(), `SELECT transfer_id,relay_conversation_id,manifest,manifest_commitment,wrapped_file_key FROM controller_sender_transfers WHERE transfer_id=?`, transferID[:]).Scan(&id, &out.relayConversationID, &out.manifest, &commitment, &out.wrappedFileKey)
	if err != nil || len(id) != 16 || !bytes.Equal(id, transferID[:]) || !validRelayIdentifier(out.relayConversationID) || len(out.manifest) == 0 || len(commitment) != 32 || len(out.wrappedFileKey) == 0 {
		return senderTransferRecord{}, errors.New("durable sender transfer is unavailable")
	}
	copy(out.transferID[:], id)
	copy(out.commitment[:], commitment)
	if blake3.Sum256(out.manifest) != out.commitment {
		return senderTransferRecord{}, errors.New("invalid durable sender transfer")
	}
	return out, nil
}

func (j *Journal) senderChunk(transferID [16]byte, manifest attachmentv3.Manifest, index uint64) ([]byte, error) {
	var ciphertext, commitment []byte
	err := j.db.QueryRowContext(context.Background(), `SELECT ciphertext,ciphertext_commitment FROM controller_sender_chunks WHERE transfer_id=? AND chunk_index=?`, transferID[:], index).Scan(&ciphertext, &commitment)
	if err != nil || len(commitment) != 32 || len(ciphertext) == 0 || senderCiphertextCommitment(ciphertext) != bytesTo32(commitment) {
		return nil, errors.New("invalid durable sender ciphertext")
	}
	plaintextLength := manifest.ChunkSize
	if index+1 == manifest.ChunkCount {
		plaintextLength = manifest.PlaintextSize - index*manifest.ChunkSize
	}
	if plaintextLength == 0 || uint64(len(ciphertext)) != plaintextLength+16 {
		return nil, errors.New("invalid durable sender ciphertext")
	}
	return append([]byte(nil), ciphertext...), nil
}

func bytesTo32(raw []byte) [32]byte { var out [32]byte; copy(out[:], raw); return out }

func senderCiphertextCommitment(ciphertext []byte) [32]byte {
	return blake3.Sum256(append([]byte("punaro/attachment/ciphertext/v3\x00"), ciphertext...))
}

type senderOperationRecord struct {
	request           attachmentv3.PermitRequest
	operationID       [16]byte
	idempotencyKey    [32]byte
	permit, operation []byte
	result            []byte
}

// SenderOutcomeWorker resolves an expired, ambiguous outbound operation. It
// never replays the expired capability. The relay returns the exact original
// result when it committed, or atomically cancels the transfer before
// returning a terminal result when it did not.
type SenderOutcomeWorker struct{ source *SenderSourceInitializer }

// NewSenderOutcomeWorker constructs the recovery worker for ambiguous expired
// sender operations.
func NewSenderOutcomeWorker(source *SenderSourceInitializer) (*SenderOutcomeWorker, error) {
	if source == nil || source.options.Journal == nil || source.options.AuthorityProvider == nil || source.options.Signer == nil || source.options.Transport == nil || source.options.NewID == nil || source.options.NewIdempotencyKey == nil {
		return nil, errors.New("invalid sender outcome worker")
	}
	return &SenderOutcomeWorker{source: source}, nil
}

// Reconcile resolves an ambiguous sender operation without replaying its
// expired capability.
func (w *SenderOutcomeWorker) Reconcile(ctx context.Context, transferID [16]byte, phase senderPhase, chunk uint64) (attachmentv3.TransferResult, error) {
	if w == nil || transferID == [16]byte{} {
		return attachmentv3.TransferResult{}, errors.New("invalid sender outcome request")
	}
	now := w.source.options.Now().UTC()
	if now.Unix() < 0 {
		return attachmentv3.TransferResult{}, errors.New("invalid sender outcome clock")
	}
	authority, err := w.source.options.AuthorityProvider.ResolveSenderDeliveryAuthority(ctx, now)
	if err != nil || authority == nil {
		return attachmentv3.TransferResult{}, errors.New("fresh sender outcome authority is unavailable")
	}
	transfer, _, err := w.source.freshSenderTransfer(ctx, transferID, authority, now)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	original, found, err := w.source.options.Journal.senderOperation(transferID, phase, chunk)
	if err != nil || !found || len(original.result) != 0 || len(original.permit) == 0 {
		return attachmentv3.TransferResult{}, errors.New("sender operation is not reconcilable")
	}
	originalPermit, err := attachmentv3.DecodePermit(original.permit)
	if err != nil || originalPermit.ExpiresAt > uint64(now.Unix()) { // #nosec G115 -- the surrounding v3 validation bounds this conversion and fails closed.
		return attachmentv3.TransferResult{}, errors.New("sender operation has not expired")
	}
	attempt, found, err := w.source.options.Journal.latestSenderOutcomeAttempt(transferID, phase, chunk)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	if !found || senderOutcomeAttemptExpired(attempt, now) {
		attempt, err = w.source.options.Journal.newSenderOutcomeAttempt(transfer, phase, chunk, original, attempt, found, now, w.source.options.Signer, w.source.options.NewID, w.source.options.NewIdempotencyKey)
		if err != nil {
			return attachmentv3.TransferResult{}, err
		}
	}
	request, err := attachmentv3.DecodePermitRequest(attempt.request)
	if err != nil || !exactSenderOutcomeRequest(request, original, transfer, now) {
		return attachmentv3.TransferResult{}, errors.New("invalid durable sender outcome request")
	}
	permit, operation, err := w.senderOutcomeCredentials(ctx, transfer, phase, chunk, original, attempt, request, authority, now)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	raw, err := w.source.options.Transport.DoV3Attachment(ctx, "GET", outcomePath(transferID), nil, permit, operation)
	if err != nil {
		return attachmentv3.TransferResult{}, fmt.Errorf("query sender operation outcome: %w", err)
	}
	attempt, err = w.source.options.Journal.storeSenderOutcomeResult(transferID, phase, chunk, attempt.index, raw)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	result, err := attachmentv3.DecodeTransferResult(attempt.result)
	if err != nil || result.TransferID != transferID || result.ManifestCommitment != transfer.commitment || !senderOutcomeStateForPhase(result.State, phase) {
		return attachmentv3.TransferResult{}, errors.New("invalid sender operation outcome result")
	}
	if err := w.source.options.Journal.storeSenderOperationResult(transferID, phase, chunk, attempt.result); err != nil {
		return attachmentv3.TransferResult{}, err
	}
	return result, nil
}

func senderOutcomeStateForPhase(state attachmentv3.TransferState, phase senderPhase) bool {
	if state == attachmentv3.TransferStateCancelled || state == attachmentv3.TransferStateExpired || state == attachmentv3.TransferStateRevoked {
		return true
	}
	switch phase {
	case senderPhaseSourceInit:
		return state == attachmentv3.TransferStateSourceUploading
	case senderPhaseSourceUpload:
		return state == attachmentv3.TransferStateSourceUploading || state == attachmentv3.TransferStateSourceReady
	case senderPhaseOffer:
		return state == attachmentv3.TransferStateOffered
	default:
		return false
	}
}

type senderOutcomeAttempt struct {
	index          uint64
	request        []byte
	operationID    [16]byte
	idempotencyKey [32]byte
	permit         []byte
	operation      []byte
	result         []byte
}

func senderOutcomeAttemptExpired(attempt senderOutcomeAttempt, now time.Time) bool {
	request, err := attachmentv3.DecodePermitRequest(attempt.request)
	if err != nil || now.Unix() < 0 {
		return true
	}
	if len(attempt.permit) != 0 {
		permit, err := attachmentv3.DecodePermit(attempt.permit)
		return err != nil || permit.ExpiresAt <= uint64(now.Unix()) // #nosec G115 -- the surrounding v3 validation bounds this conversion and fails closed.
	}
	return request.ExpiresAt <= uint64(now.Unix()) // #nosec G115 -- the surrounding v3 validation bounds this conversion and fails closed.
}

func senderOperationPath(transfer [16]byte, phase senderPhase, chunk uint64) (string, string, error) {
	switch phase {
	case senderPhaseSourceInit:
		if chunk == 0 {
			return "POST", sourceInitPath(transfer), nil
		}
	case senderPhaseSourceUpload:
		return "PUT", fmt.Sprintf("/v3/attachments/%x/source/chunks/%d", transfer, chunk), nil
	case senderPhaseOffer:
		if chunk == 0 {
			return "POST", fmt.Sprintf("/v3/attachments/%x/offer", transfer), nil
		}
	}
	return "", "", errors.New("invalid sender operation phase")
}

func sourceInitPath(transfer [16]byte) string {
	return fmt.Sprintf("/v3/attachments/%x/source", transfer)
}

func (j *Journal) ensureSenderOperation(transfer senderTransferRecord, phase senderPhase, chunk, bodyBytes uint64, now time.Time, signer SenderOperationSigner, newID func() ([16]byte, error), newKey func() ([32]byte, error)) (senderOperationRecord, error) {
	if j == nil || j.db == nil || signer == nil || transfer.transferID == [16]byte{} || transfer.commitment == [32]byte{} || now.Unix() < 0 {
		return senderOperationRecord{}, errors.New("invalid sender operation intent")
	}
	if existing, found, err := j.senderOperation(transfer.transferID, phase, chunk); err != nil || found {
		if err != nil || !found {
			return senderOperationRecord{}, errors.New("invalid durable sender operation")
		}
		return existing, nil
	}
	requestID, err := newID()
	if err != nil || requestID == [16]byte{} {
		return senderOperationRecord{}, errors.New("generate sender permit request identity")
	}
	opID, err := newID()
	if err != nil || opID == [16]byte{} {
		return senderOperationRecord{}, errors.New("generate sender operation identity")
	}
	idempotency, err := newKey()
	if err != nil || idempotency == [32]byte{} {
		return senderOperationRecord{}, errors.New("generate sender idempotency identity")
	}
	manifest, err := attachmentv3.DecodeManifest(transfer.manifest)
	if err != nil {
		return senderOperationRecord{}, errors.New("invalid durable sender manifest")
	}
	expires := now.Add(senderOperationLifetime).Unix()
	if uint64(expires) > manifest.ExpiresAt { // #nosec G115 -- the surrounding v3 validation bounds this conversion and fails closed.
		expires = int64(manifest.ExpiresAt) // #nosec G115 -- the surrounding v3 validation bounds this conversion and fails closed.
	}
	if expires <= now.Unix() {
		return senderOperationRecord{}, errors.New("expired sender source")
	}
	operation, _, _, err := senderOperationSpec(transfer.transferID, phase, chunk)
	if err != nil {
		return senderOperationRecord{}, err
	}
	maxBytes, maxChunks := senderPermitBounds(manifest, phase, bodyBytes)
	if maxBytes == 0 || maxChunks == 0 {
		return senderOperationRecord{}, errors.New("invalid sender source size")
	}
	record := senderOperationRecord{operationID: opID, idempotencyKey: idempotency}
	record.request = attachmentv3.PermitRequest{RequestID: requestID, HolderDeviceID: manifest.SenderDeviceID, HolderGeneration: manifest.SenderGeneration, HolderRole: attachmentv3.PermitHolderSender, TransferID: manifest.TransferID, ConversationID: manifest.ConversationID, SenderDeviceID: manifest.SenderDeviceID, SenderGeneration: manifest.SenderGeneration, RecipientDeviceID: manifest.RecipientDeviceID, RecipientGeneration: manifest.RecipientGeneration, Operation: operation, MembershipCommitment: manifest.MembershipCommitment, StagedManifestCommitment: transfer.commitment, IssuedAt: uint64(now.Unix()), ExpiresAt: uint64(expires), MaxBytes: maxBytes, MaxChunks: maxChunks, MaxOperations: 1} // #nosec G115 -- the surrounding v3 validation bounds this conversion and fails closed.
	if err := signer.SignSenderPermit(&record.request); err != nil {
		return senderOperationRecord{}, err
	}
	rawRequest, err := attachmentv3.EncodePermitRequest(record.request)
	if err != nil {
		return senderOperationRecord{}, err
	}
	result, err := j.db.ExecContext(context.Background(), `INSERT INTO controller_sender_operations(transfer_id,phase,chunk_index,permit_request,operation_id,idempotency_key) VALUES (?,?,?,?,?,?) ON CONFLICT(transfer_id,phase,chunk_index) DO NOTHING`, transfer.transferID[:], string(phase), chunk, rawRequest, opID[:], idempotency[:])
	if err != nil {
		return senderOperationRecord{}, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return senderOperationRecord{}, err
	}
	stored, found, err := j.senderOperation(transfer.transferID, phase, chunk)
	if err != nil || !found || (inserted == 1 && (stored.operationID != opID || stored.idempotencyKey != idempotency)) {
		return senderOperationRecord{}, errors.New("changed durable sender operation")
	}
	return stored, nil
}

func (j *Journal) senderOperation(transferID [16]byte, phase senderPhase, chunk uint64) (senderOperationRecord, bool, error) {
	var out senderOperationRecord
	var opID, key, request []byte
	err := j.db.QueryRowContext(context.Background(), `SELECT permit_request,operation_id,idempotency_key,permit,operation,result FROM controller_sender_operations WHERE transfer_id=? AND phase=? AND chunk_index=?`, transferID[:], string(phase), chunk).Scan(&request, &opID, &key, &out.permit, &out.operation, &out.result)
	if errors.Is(err, sql.ErrNoRows) {
		return senderOperationRecord{}, false, nil
	}
	if err != nil || len(opID) != 16 || len(key) != 32 {
		return senderOperationRecord{}, false, errors.New("invalid durable sender operation")
	}
	var decodeErr error
	out.request, decodeErr = attachmentv3.DecodePermitRequest(request)
	if decodeErr != nil {
		return senderOperationRecord{}, false, errors.New("invalid durable sender permit request")
	}
	copy(out.operationID[:], opID)
	copy(out.idempotencyKey[:], key)
	return out, true, nil
}

func (j *Journal) latestSenderOutcomeAttempt(transferID [16]byte, phase senderPhase, chunk uint64) (senderOutcomeAttempt, bool, error) {
	var out senderOutcomeAttempt
	var index uint64
	var opID, key []byte
	err := j.db.QueryRowContext(context.Background(), `SELECT attempt_index,permit_request,operation_id,idempotency_key,permit,operation,result FROM controller_sender_outcome_attempts WHERE transfer_id=? AND phase=? AND chunk_index=? ORDER BY attempt_index DESC LIMIT 1`, transferID[:], string(phase), chunk).Scan(&index, &out.request, &opID, &key, &out.permit, &out.operation, &out.result)
	if errors.Is(err, sql.ErrNoRows) {
		return senderOutcomeAttempt{}, false, nil
	}
	if err != nil || len(opID) != 16 || len(key) != 32 {
		return senderOutcomeAttempt{}, false, errors.New("invalid durable sender outcome attempt")
	}
	out.index = index
	copy(out.operationID[:], opID)
	copy(out.idempotencyKey[:], key)
	return out, true, nil
}

func (j *Journal) newSenderOutcomeAttempt(transfer senderTransferRecord, phase senderPhase, chunk uint64, original senderOperationRecord, previous senderOutcomeAttempt, found bool, now time.Time, signer SenderOperationSigner, newID func() ([16]byte, error), newKey func() ([32]byte, error)) (senderOutcomeAttempt, error) {
	if now.Unix() < 0 || signer == nil || (found && previous.index == ^uint64(0)) {
		return senderOutcomeAttempt{}, errors.New("cannot create sender outcome attempt")
	}
	originalPermit, err := attachmentv3.DecodePermit(original.permit)
	if err != nil || originalPermit.Serial == [16]byte{} || originalPermit.Operation == attachmentv3.PermitOperationOutcome {
		return senderOutcomeAttempt{}, errors.New("invalid sender outcome origin")
	}
	requestID, err := newID()
	if err != nil || requestID == [16]byte{} {
		return senderOutcomeAttempt{}, errors.New("generate sender outcome request identity")
	}
	opID, err := newID()
	if err != nil || opID == [16]byte{} {
		return senderOutcomeAttempt{}, errors.New("generate sender outcome operation identity")
	}
	key, err := newKey()
	if err != nil || key == [32]byte{} {
		return senderOutcomeAttempt{}, errors.New("generate sender outcome idempotency identity")
	}
	request := original.request
	request.RequestID, request.Operation, request.AttemptGeneration, request.OutcomeOfSerial = requestID, attachmentv3.PermitOperationOutcome, 0, originalPermit.Serial
	request.MaxOperations = 1
	request.IssuedAt, request.ExpiresAt = uint64(now.Unix()), uint64(now.Add(senderOutcomeLifetime).Unix()) // #nosec G115 -- the surrounding v3 validation bounds this conversion and fails closed.
	manifest, err := attachmentv3.DecodeManifest(transfer.manifest)
	if err != nil {
		return senderOutcomeAttempt{}, errors.New("invalid sender outcome source")
	}
	if request.ExpiresAt > manifest.ExpiresAt {
		request.ExpiresAt = manifest.ExpiresAt
	}
	if request.ExpiresAt <= request.IssuedAt {
		return senderOutcomeAttempt{}, errors.New("expired sender outcome source")
	}
	if err := signer.SignSenderPermit(&request); err != nil {
		return senderOutcomeAttempt{}, err
	}
	raw, err := attachmentv3.EncodePermitRequest(request)
	if err != nil {
		return senderOutcomeAttempt{}, err
	}
	index := uint64(0)
	if found {
		index = previous.index + 1
	}
	result, err := j.db.ExecContext(context.Background(), `INSERT INTO controller_sender_outcome_attempts(transfer_id,phase,chunk_index,attempt_index,permit_request,operation_id,idempotency_key) VALUES(?,?,?,?,?,?,?) ON CONFLICT(transfer_id,phase,chunk_index,attempt_index) DO NOTHING`, transfer.transferID[:], string(phase), chunk, index, raw, opID[:], key[:])
	if err != nil {
		return senderOutcomeAttempt{}, err
	}
	if _, err := result.RowsAffected(); err != nil {
		return senderOutcomeAttempt{}, errors.New("record sender outcome attempt")
	}
	stored, storedFound, err := j.latestSenderOutcomeAttempt(transfer.transferID, phase, chunk)
	if err != nil || !storedFound || stored.index != index || stored.operationID != opID || stored.idempotencyKey != key {
		return senderOutcomeAttempt{}, errors.New("changed durable sender outcome attempt")
	}
	return stored, nil
}

func (w *SenderOutcomeWorker) senderOutcomeCredentials(ctx context.Context, transfer senderTransferRecord, phase senderPhase, chunk uint64, original senderOperationRecord, attempt senderOutcomeAttempt, request attachmentv3.PermitRequest, authority SenderDeliveryAuthority, now time.Time) (attachmentv3.Permit, attachmentv3.OperationRecord, error) {
	if len(attempt.permit) != 0 || len(attempt.operation) != 0 {
		if len(attempt.permit) == 0 || len(attempt.operation) == 0 {
			return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("incomplete durable sender outcome credentials")
		}
		permit, err := attachmentv3.DecodePermit(attempt.permit)
		if err != nil || !exactSenderOutcomePermit(permit, request, original, transfer, now) || attachmentv3.VerifyPermit(permit, authority, now) != nil {
			return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("invalid durable sender outcome permit")
		}
		op, err := attachmentv3.DecodeOperation(attempt.operation)
		if err != nil || op.OperationID != attempt.operationID || op.IdempotencyKey != attempt.idempotencyKey || verifySenderOperation(op, permit, "GET", outcomePath(transfer.transferID), nil, authority, now) != nil {
			return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("invalid durable sender outcome operation")
		}
		return permit, op, nil
	}
	permit, err := w.source.options.Transport.IssueV3Permit(ctx, request)
	if err != nil || !exactSenderOutcomePermit(permit, request, original, transfer, now) || attachmentv3.VerifyPermit(permit, authority, now) != nil {
		return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("sender outcome permit is unavailable")
	}
	issued := uint64(now.Unix()) // #nosec G115 -- the surrounding v3 validation bounds this conversion and fails closed.
	if issued < permit.IssuedAt {
		issued = permit.IssuedAt
	}
	op, err := w.source.options.Signer.BuildSenderOperation(permit, "GET", outcomePath(transfer.transferID), nil, attempt.operationID, attempt.idempotencyKey, issued, permit.ExpiresAt)
	if err != nil || verifySenderOperation(op, permit, "GET", outcomePath(transfer.transferID), nil, authority, now) != nil {
		return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("sender outcome operation is unavailable")
	}
	stored, err := w.source.options.Journal.storeSenderOutcomeCredentials(transfer.transferID, phase, chunk, attempt.index, permit, op)
	if err != nil {
		return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, err
	}
	return w.senderOutcomeCredentials(ctx, transfer, phase, chunk, original, stored, request, authority, now)
}

func (j *Journal) storeSenderOutcomeCredentials(transferID [16]byte, phase senderPhase, chunk, index uint64, permit attachmentv3.Permit, operation attachmentv3.OperationRecord) (senderOutcomeAttempt, error) {
	rawPermit, err := attachmentv3.EncodePermit(permit)
	if err != nil {
		return senderOutcomeAttempt{}, err
	}
	rawOperation, err := attachmentv3.EncodeOperation(operation)
	if err != nil {
		return senderOutcomeAttempt{}, err
	}
	result, err := j.db.ExecContext(context.Background(), `UPDATE controller_sender_outcome_attempts SET permit=?,operation=? WHERE transfer_id=? AND phase=? AND chunk_index=? AND attempt_index=? AND permit IS NULL AND operation IS NULL`, rawPermit, rawOperation, transferID[:], string(phase), chunk, index)
	if err != nil {
		return senderOutcomeAttempt{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return senderOutcomeAttempt{}, err
	}
	stored, found, err := j.latestSenderOutcomeAttempt(transferID, phase, chunk)
	if err != nil || !found || stored.index != index || len(stored.permit) == 0 || len(stored.operation) == 0 || (changed == 0 && (!bytes.Equal(stored.permit, rawPermit) || !bytes.Equal(stored.operation, rawOperation))) {
		return senderOutcomeAttempt{}, errors.New("changed durable sender outcome credentials")
	}
	return stored, nil
}

func (j *Journal) storeSenderOutcomeResult(transferID [16]byte, phase senderPhase, chunk, index uint64, raw []byte) (senderOutcomeAttempt, error) {
	result, err := j.db.ExecContext(context.Background(), `UPDATE controller_sender_outcome_attempts SET result=? WHERE transfer_id=? AND phase=? AND chunk_index=? AND attempt_index=? AND result IS NULL`, raw, transferID[:], string(phase), chunk, index)
	if err != nil {
		return senderOutcomeAttempt{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return senderOutcomeAttempt{}, err
	}
	stored, found, err := j.latestSenderOutcomeAttempt(transferID, phase, chunk)
	if err != nil || !found || stored.index != index || len(stored.result) == 0 || (changed == 0 && !bytes.Equal(stored.result, raw)) {
		return senderOutcomeAttempt{}, errors.New("changed durable sender outcome result")
	}
	return stored, nil
}

func (w *SenderSourceInitializer) credentials(ctx context.Context, transfer senderTransferRecord, phase senderPhase, chunk uint64, record senderOperationRecord, body []byte, authority SenderDeliveryAuthority, now time.Time) (attachmentv3.Permit, attachmentv3.OperationRecord, error) {
	operationKind, method, path, err := senderOperationSpec(transfer.transferID, phase, chunk)
	if err != nil || record.request.Operation != operationKind {
		return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("invalid sender operation phase")
	}
	if len(record.permit) != 0 || len(record.operation) != 0 {
		if len(record.permit) == 0 || len(record.operation) == 0 {
			return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("incomplete durable sender credentials")
		}
		permit, err := attachmentv3.DecodePermit(record.permit)
		if err != nil || !exactSenderPermit(permit, record.request, transfer, operationKind, now) || attachmentv3.VerifyPermit(permit, authority, now) != nil {
			return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("invalid durable sender permit")
		}
		op, err := attachmentv3.DecodeOperation(record.operation)
		if err != nil || op.OperationID != record.operationID || op.IdempotencyKey != record.idempotencyKey || verifySenderOperation(op, permit, method, path, body, authority, now) != nil {
			return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("invalid durable sender operation")
		}
		return permit, op, nil
	}
	permit, err := w.options.Transport.IssueV3Permit(ctx, record.request)
	if err != nil || !exactSenderPermitFields(permit, record.request, transfer, operationKind) {
		return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("sender source permit is unavailable")
	}
	if attachmentv3.VerifyPermit(permit, authority, now) != nil {
		if permit.ExpiresAt <= uint64(now.Unix()) { // #nosec G115 -- the surrounding v3 validation bounds this conversion and fails closed.
			if _, storeErr := w.options.Journal.storeSenderPermit(transfer.transferID, phase, chunk, permit); storeErr != nil {
				return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, storeErr
			}
			return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("sender source permit expired before local persistence")
		}
		return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("sender source permit is unavailable")
	}
	issued := uint64(now.Unix()) // #nosec G115 -- the surrounding v3 validation bounds this conversion and fails closed.
	if issued < permit.IssuedAt {
		issued = permit.IssuedAt
	}
	op, err := w.options.Signer.BuildSenderOperation(permit, method, path, body, record.operationID, record.idempotencyKey, issued, permit.ExpiresAt)
	if err != nil || verifySenderOperation(op, permit, method, path, body, authority, now) != nil {
		return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, errors.New("sender source operation is unavailable")
	}
	stored, err := w.options.Journal.storeSenderCredentials(transfer.transferID, phase, chunk, permit, op)
	if err != nil {
		return attachmentv3.Permit{}, attachmentv3.OperationRecord{}, err
	}
	return w.credentials(ctx, transfer, phase, chunk, stored, body, authority, now)
}

func (w *SenderSourceInitializer) reconcileExpired(ctx context.Context, transferID [16]byte, phase senderPhase, chunk uint64, record senderOperationRecord, now time.Time) (attachmentv3.TransferResult, error) {
	if len(record.permit) == 0 || now.Unix() < 0 {
		return attachmentv3.TransferResult{}, errors.New("sender operation has no expired durable credentials")
	}
	permit, err := attachmentv3.DecodePermit(record.permit)
	if err != nil || permit.ExpiresAt > uint64(now.Unix()) { // #nosec G115 -- the surrounding v3 validation bounds this conversion and fails closed.
		return attachmentv3.TransferResult{}, errors.New("sender operation is not expired")
	}
	outcomes, err := NewSenderOutcomeWorker(w)
	if err != nil {
		return attachmentv3.TransferResult{}, err
	}
	return outcomes.Reconcile(ctx, transferID, phase, chunk)
}

func (j *Journal) storeSenderCredentials(transfer [16]byte, phase senderPhase, chunk uint64, permit attachmentv3.Permit, operation attachmentv3.OperationRecord) (senderOperationRecord, error) {
	p, err := attachmentv3.EncodePermit(permit)
	if err != nil {
		return senderOperationRecord{}, err
	}
	o, err := attachmentv3.EncodeOperation(operation)
	if err != nil {
		return senderOperationRecord{}, err
	}
	result, err := j.db.ExecContext(context.Background(), `UPDATE controller_sender_operations SET permit=?,operation=? WHERE transfer_id=? AND phase=? AND chunk_index=? AND permit IS NULL AND operation IS NULL`, p, o, transfer[:], string(phase), chunk)
	if err != nil {
		return senderOperationRecord{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return senderOperationRecord{}, err
	}
	stored, found, err := j.senderOperation(transfer, phase, chunk)
	if err != nil || !found || len(stored.permit) == 0 || len(stored.operation) == 0 || (changed == 0 && (!bytes.Equal(stored.permit, p) || !bytes.Equal(stored.operation, o))) {
		return senderOperationRecord{}, errors.New("changed durable sender credentials")
	}
	return stored, nil
}

func (j *Journal) storeSenderPermit(transfer [16]byte, phase senderPhase, chunk uint64, permit attachmentv3.Permit) (senderOperationRecord, error) {
	raw, err := attachmentv3.EncodePermit(permit)
	if err != nil {
		return senderOperationRecord{}, err
	}
	result, err := j.db.ExecContext(context.Background(), `UPDATE controller_sender_operations SET permit=? WHERE transfer_id=? AND phase=? AND chunk_index=? AND permit IS NULL`, raw, transfer[:], string(phase), chunk)
	if err != nil {
		return senderOperationRecord{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return senderOperationRecord{}, err
	}
	stored, found, err := j.senderOperation(transfer, phase, chunk)
	if err != nil || !found || len(stored.permit) == 0 || (changed == 0 && !bytes.Equal(stored.permit, raw)) {
		return senderOperationRecord{}, errors.New("changed durable sender permit")
	}
	return stored, nil
}

func (j *Journal) storeSenderOperationResult(transfer [16]byte, phase senderPhase, chunk uint64, raw []byte) error {
	result, err := j.db.ExecContext(context.Background(), `UPDATE controller_sender_operations SET result=? WHERE transfer_id=? AND phase=? AND chunk_index=? AND result IS NULL`, raw, transfer[:], string(phase), chunk)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	stored, found, err := j.senderOperation(transfer, phase, chunk)
	if err != nil || !found || len(stored.result) == 0 || (changed == 0 && !bytes.Equal(stored.result, raw)) {
		return errors.New("changed durable sender operation result")
	}
	return nil
}

func exactSenderPermit(permit attachmentv3.Permit, request attachmentv3.PermitRequest, transfer senderTransferRecord, operation uint64, now time.Time) bool {
	if !exactSenderPermitFields(permit, request, transfer, operation) {
		return false
	}
	return now.Unix() >= 0 && permit.IssuedAt >= request.IssuedAt && permit.ExpiresAt <= request.ExpiresAt && permit.IssuedAt <= uint64(now.Unix()) && permit.ExpiresAt > uint64(now.Unix()) // #nosec G115 -- the surrounding v3 validation bounds this conversion and fails closed.
}

func exactSenderPermitFields(permit attachmentv3.Permit, request attachmentv3.PermitRequest, transfer senderTransferRecord, operation uint64) bool {
	if _, err := attachmentv3.DecodePermit(mustEncodePermit(permit)); err != nil || request.Operation != operation || permit.HolderDeviceID != request.HolderDeviceID || permit.HolderGeneration != request.HolderGeneration || permit.HolderRole != attachmentv3.PermitHolderSender || permit.TransferID != transfer.transferID || permit.ConversationID != request.ConversationID || permit.SenderDeviceID != request.SenderDeviceID || permit.SenderGeneration != request.SenderGeneration || permit.RecipientDeviceID != request.RecipientDeviceID || permit.RecipientGeneration != request.RecipientGeneration || permit.AttemptGeneration != 0 || permit.Operation != operation || permit.MembershipCommitment != request.MembershipCommitment || permit.StagedManifestCommitment != transfer.commitment || permit.MaxBytes != request.MaxBytes || permit.MaxChunks != request.MaxChunks || permit.MaxOperations != 1 {
		return false
	}
	return permit.IssuedAt >= request.IssuedAt && permit.ExpiresAt <= request.ExpiresAt
}

func exactSenderOutcomeRequest(request attachmentv3.PermitRequest, original senderOperationRecord, transfer senderTransferRecord, now time.Time) bool {
	originalPermit, err := attachmentv3.DecodePermit(original.permit)
	if err != nil || now.Unix() < 0 || request.RequestID == [16]byte{} || request.HolderDeviceID != original.request.HolderDeviceID || request.HolderGeneration != original.request.HolderGeneration || request.HolderRole != attachmentv3.PermitHolderSender || request.TransferID != transfer.transferID || request.ConversationID != original.request.ConversationID || request.SenderDeviceID != original.request.SenderDeviceID || request.SenderGeneration != original.request.SenderGeneration || request.RecipientDeviceID != original.request.RecipientDeviceID || request.RecipientGeneration != original.request.RecipientGeneration || request.AttemptGeneration != 0 || request.Operation != attachmentv3.PermitOperationOutcome || request.OutcomeOfSerial != originalPermit.Serial || request.MembershipCommitment != original.request.MembershipCommitment || request.StagedManifestCommitment != transfer.commitment || request.MaxBytes != original.request.MaxBytes || request.MaxChunks != original.request.MaxChunks || request.MaxOperations != 1 {
		return false
	}
	return request.IssuedAt <= uint64(now.Unix()) && request.ExpiresAt > uint64(now.Unix()) // #nosec G115 -- the surrounding v3 validation bounds this conversion and fails closed.
}

func exactSenderOutcomePermit(permit attachmentv3.Permit, request attachmentv3.PermitRequest, original senderOperationRecord, transfer senderTransferRecord, now time.Time) bool {
	if !exactSenderOutcomeRequest(request, original, transfer, now) {
		return false
	}
	if _, err := attachmentv3.DecodePermit(mustEncodePermit(permit)); err != nil {
		return false
	}
	if permit.HolderDeviceID != request.HolderDeviceID || permit.HolderGeneration != request.HolderGeneration || permit.HolderRole != attachmentv3.PermitHolderSender || permit.TransferID != transfer.transferID || permit.ConversationID != request.ConversationID || permit.SenderDeviceID != request.SenderDeviceID || permit.SenderGeneration != request.SenderGeneration || permit.RecipientDeviceID != request.RecipientDeviceID || permit.RecipientGeneration != request.RecipientGeneration || permit.AttemptGeneration != 0 || permit.Operation != attachmentv3.PermitOperationOutcome || permit.OutcomeOfSerial != request.OutcomeOfSerial || permit.MembershipCommitment != request.MembershipCommitment || permit.StagedManifestCommitment != transfer.commitment || permit.MaxBytes != request.MaxBytes || permit.MaxChunks != request.MaxChunks || permit.MaxOperations != 1 {
		return false
	}
	return permit.IssuedAt >= request.IssuedAt && permit.ExpiresAt <= request.ExpiresAt && permit.IssuedAt <= uint64(now.Unix()) && permit.ExpiresAt > uint64(now.Unix()) // #nosec G115 -- the surrounding v3 validation bounds this conversion and fails closed.
}

func verifySenderOperation(operation attachmentv3.OperationRecord, permit attachmentv3.Permit, method, path string, body []byte, authority SenderDeliveryAuthority, now time.Time) error {
	route, request, err := attachmentv3.NewAttachmentOperationRequest(method, path, body, nil)
	if err != nil {
		return errors.New("invalid sender operation")
	}
	if _, _, err := attachmentv3.VerifyAttachmentOperationRequest(operation, permit, authority, route, request, now); err != nil {
		return errors.New("invalid sender operation")
	}
	return nil
}

func senderOperationSpec(transfer [16]byte, phase senderPhase, chunk uint64) (uint64, string, string, error) {
	method, path, err := senderOperationPath(transfer, phase, chunk)
	if err != nil {
		return 0, "", "", err
	}
	switch phase {
	case senderPhaseSourceInit:
		return attachmentv3.PermitOperationSourceInit, method, path, nil
	case senderPhaseSourceUpload:
		return attachmentv3.PermitOperationSourceUpload, method, path, nil
	case senderPhaseOffer:
		return attachmentv3.PermitOperationOffer, method, path, nil
	default:
		return 0, "", "", errors.New("invalid sender operation phase")
	}
}

func senderPermitBounds(manifest attachmentv3.Manifest, phase senderPhase, bodyBytes uint64) (uint64, uint64) {
	switch phase {
	case senderPhaseSourceInit:
		bytes := manifest.PlaintextSize + manifest.ChunkCount*16
		if bytes < manifest.PlaintextSize {
			return 0, 0
		}
		return bytes, manifest.ChunkCount
	case senderPhaseSourceUpload:
		if bodyBytes == 0 || bodyBytes > 256<<10+16 {
			return 0, 0
		}
		return bodyBytes, 1
	case senderPhaseOffer:
		if bodyBytes == 0 || bodyBytes > 24555 {
			return 0, 0
		}
		return bodyBytes, 1
	default:
		return 0, 0
	}
}

func exactSenderResult(raw []byte, transfer senderTransferRecord, state attachmentv3.TransferState) (attachmentv3.TransferResult, error) {
	result, err := attachmentv3.DecodeTransferResult(raw)
	if err != nil || result.TransferID != transfer.transferID || result.ManifestCommitment != transfer.commitment || result.State != state || result.AttemptGeneration != 0 {
		return attachmentv3.TransferResult{}, errors.New("invalid sender source result")
	}
	return result, nil
}

func exactSenderUploadResult(raw []byte, transfer senderTransferRecord) (attachmentv3.TransferResult, error) {
	result, err := attachmentv3.DecodeTransferResult(raw)
	if err != nil || result.TransferID != transfer.transferID || result.ManifestCommitment != transfer.commitment || result.AttemptGeneration != 0 || (result.State != attachmentv3.TransferStateSourceUploading && result.State != attachmentv3.TransferStateSourceReady) {
		return attachmentv3.TransferResult{}, errors.New("invalid sender upload result")
	}
	return result, nil
}
