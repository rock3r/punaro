// Package cutover coordinates Punaro's one irreversible SQLite-to-PostgreSQL
// mail authority transition without introducing a dual-write state.
package cutover

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/rock3r/punaro/internal/operator"
	"github.com/rock3r/punaro/internal/postgres"
	"github.com/rock3r/punaro/internal/relay"
)

var tables = []string{
	"mail_endpoints", "mail_conversations", "mail_memberships", "mail_messages", "mail_deliveries",
	"mail_recipient_cursors", "mail_message_idempotency", "mail_conversation_idempotency", "mail_request_nonces",
}

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Source is the privileged, service-owned SQLite cutover surface.
type Source interface {
	Inspect(context.Context) (relay.MigrationSourceManifest, error)
	Prepare(context.Context, string, string, string, time.Time) (relay.MigrationSourceManifest, error)
	ReadBatch(context.Context, string, string, int) (relay.MigrationSourceBatch, error)
	Abort(context.Context, string, string, string) (relay.MigrationSourceManifest, error)
	Retire(context.Context, string, string, string) (relay.MigrationSourceManifest, error)
}

// Destination is the schema-owner PostgreSQL cutover surface.
type Destination interface {
	Identity(context.Context) (string, error)
	BeginMailCutover(context.Context, string, postgres.MailCutoverRequest) (postgres.MailCutoverEpoch, error)
	MailCutoverStatus(context.Context, string, string) (postgres.MailCutoverEpoch, error)
	ReserveMailCutoverAbort(context.Context, string, postgres.MailCutoverRequest) (postgres.MailCutoverEpoch, error)
	MailCutoverCheckpoint(context.Context, string, string, string) (postgres.MailCutoverCheckpoint, error)
	StageMailCutoverBatch(context.Context, string, postgres.MailCutoverBatch) (postgres.MailCutoverCheckpoint, error)
	VerifyMailCutover(context.Context, string, string, string) (postgres.MailCutoverEpoch, error)
	ActivateMailCutover(context.Context, string, string, string, relay.MigrationSourceManifest) (postgres.MailCutoverEpoch, error)
	AbortMailCutover(context.Context, string, string, string) error
}

// Publisher makes the already-active database selection visible locally.
type Publisher func(context.Context, operator.MailCutoverPublication) error

// Executor composes independently durable source, destination, and publication
// boundaries. BatchSize is clamped to the supported 1-256 range.
type Executor struct {
	Source      Source
	Destination Destination
	Publish     Publisher
	BatchSize   int
}

// Request is the explicit irreversible execution authorization.
type Request struct {
	ActorPrincipalID          string
	EpochID                   string
	ExpectedSourceFingerprint string
	Cutoff                    time.Time
}

// Plan is a read-only dry-run view.
type Plan struct {
	SourceID          string                      `json:"source_id"`
	SourcePhase       relay.MigrationSourcePhase  `json:"source_phase"`
	SourceFingerprint string                      `json:"source_fingerprint"`
	TargetIdentity    string                      `json:"target_identity"`
	Counts            relay.MigrationSourceCounts `json:"counts"`
}

// Result is the durable final authority binding.
type Result struct {
	EpochID           string                     `json:"epoch_id"`
	SourceFingerprint string                     `json:"source_fingerprint"`
	SourcePhase       relay.MigrationSourcePhase `json:"source_phase"`
	Phase             postgres.MailCutoverPhase  `json:"phase"`
}

// DryRun inspects both authorities without fencing or mutating either one.
func (e Executor) DryRun(ctx context.Context) (Plan, error) {
	if e.Source == nil || e.Destination == nil {
		return Plan{}, errors.New("mail cutover executor is incomplete")
	}
	target, err := e.Destination.Identity(ctx)
	if err != nil {
		return Plan{}, errors.New("mail cutover target identity is unavailable")
	}
	manifest, err := e.Source.Inspect(ctx)
	if err != nil {
		return Plan{}, err
	}
	return Plan{SourceID: manifest.SourceID, SourcePhase: manifest.Phase, SourceFingerprint: manifest.Fingerprint, TargetIdentity: target, Counts: manifest.Counts}, nil
}

// Execute resumes from every durable boundary. It retires SQLite only after
// PostgreSQL verification, activates PostgreSQL only after retirement, and
// publishes the runtime marker only after database activation.
func (e Executor) Execute(ctx context.Context, request Request) (Result, error) {
	if e.Source == nil || e.Destination == nil || e.Publish == nil || uuid.Validate(request.ActorPrincipalID) != nil || uuid.Validate(request.EpochID) != nil || !digestPattern.MatchString(request.ExpectedSourceFingerprint) || request.Cutoff.IsZero() {
		return Result{}, errors.New("mail cutover execution request is invalid")
	}
	batchSize := e.BatchSize
	if batchSize < 1 || batchSize > 256 {
		batchSize = 128
	}
	target, err := e.Destination.Identity(ctx)
	if err != nil {
		return Result{}, errors.New("mail cutover target identity is unavailable")
	}
	manifest, err := e.Source.Inspect(ctx)
	if err != nil {
		return Result{}, err
	}
	switch manifest.Phase {
	case relay.MigrationSourceActive:
		if manifest.Fingerprint != request.ExpectedSourceFingerprint {
			return Result{}, errors.New("mail cutover source changed after dry-run")
		}
		manifest, err = e.Source.Prepare(ctx, request.EpochID, target, request.ExpectedSourceFingerprint, request.Cutoff)
		if err != nil {
			return Result{}, err
		}
	case relay.MigrationSourcePrepared, relay.MigrationSourceRetired:
		if manifest.EpochID != request.EpochID || manifest.TargetIdentity != target || manifest.ExpectedFingerprint != request.ExpectedSourceFingerprint {
			return Result{}, errors.New("mail cutover source is bound to another execution")
		}
	default:
		return Result{}, errors.New("mail cutover source phase is invalid")
	}
	prepared := manifest
	prepared.Phase = relay.MigrationSourcePrepared
	cutoverRequest, err := destinationRequest(prepared, request.EpochID, target)
	if err != nil {
		return Result{}, err
	}
	epoch, err := e.Destination.BeginMailCutover(ctx, request.ActorPrincipalID, cutoverRequest)
	if err != nil {
		return Result{}, err
	}
	if epoch.Phase == postgres.MailCutoverImporting {
		if manifest.Phase != relay.MigrationSourcePrepared {
			return Result{}, errors.New("retired source has an incomplete destination import")
		}
		for _, table := range tables {
			checkpoint, err := e.Destination.MailCutoverCheckpoint(ctx, request.ActorPrincipalID, request.EpochID, table)
			if err != nil {
				return Result{}, err
			}
			expected, _ := tableEvidence(prepared, table)
			if checkpoint.RowCount > expected {
				return Result{}, errors.New("mail cutover checkpoint exceeds the source manifest")
			}
			if checkpoint.RowCount == expected && (expected > 0 || !checkpoint.UpdatedAt.IsZero()) {
				continue
			}
			after := ""
			if checkpoint.LastKey.Valid {
				after = checkpoint.LastKey.String
			}
			for {
				batch, err := e.Source.ReadBatch(ctx, table, after, batchSize)
				if err != nil {
					return Result{}, err
				}
				checkpoint, err = e.Destination.StageMailCutoverBatch(ctx, request.ActorPrincipalID, postgres.MailCutoverBatch{EpochID: request.EpochID, Table: table, AfterKey: after, Rows: batch.Rows, Done: batch.Done})
				if err != nil {
					return Result{}, err
				}
				if batch.Done {
					break
				}
				if batch.NextKey == "" || batch.NextKey == after {
					return Result{}, errors.New("mail cutover source pagination did not advance")
				}
				after = batch.NextKey
			}
			if checkpoint.RowCount != expected {
				return Result{}, errors.New("mail cutover checkpoint does not reach the source manifest")
			}
		}
		epoch, err = e.Destination.VerifyMailCutover(ctx, request.ActorPrincipalID, request.EpochID, prepared.Fingerprint)
		if err != nil {
			return Result{}, err
		}
	}
	if epoch.Phase == postgres.MailCutoverVerified {
		if manifest.Phase == relay.MigrationSourcePrepared {
			manifest, err = e.Source.Retire(ctx, request.EpochID, target, prepared.Fingerprint)
			if err != nil {
				return Result{}, err
			}
		}
		if manifest.Phase != relay.MigrationSourceRetired {
			return Result{}, errors.New("mail cutover source is not retired")
		}
		epoch, err = e.Destination.ActivateMailCutover(ctx, request.ActorPrincipalID, request.EpochID, prepared.Fingerprint, manifest)
		if err != nil {
			return Result{}, err
		}
	}
	if epoch.Phase != postgres.MailCutoverActive || manifest.Phase != relay.MigrationSourceRetired {
		return Result{}, errors.New("mail cutover did not reach the active authority boundary")
	}
	publication := operator.MailCutoverPublication{Version: 1, EpochID: request.EpochID, TargetIdentity: target, SourceFingerprint: prepared.Fingerprint}
	if err := e.Publish(ctx, publication); err != nil {
		return Result{}, err
	}
	return Result{EpochID: request.EpochID, SourceFingerprint: prepared.Fingerprint, SourcePhase: manifest.Phase, Phase: epoch.Phase}, nil
}

// Abort reopens the prepared SQLite source and leaves the destination dark. It
// rechecks the destination before touching SQLite and can never cross or undo
// the source-retirement/active-PostgreSQL barrier.
func (e Executor) Abort(ctx context.Context, actorPrincipalID, epochID string) (Result, error) {
	if e.Source == nil || e.Destination == nil || uuid.Validate(actorPrincipalID) != nil || uuid.Validate(epochID) != nil {
		return Result{}, errors.New("mail cutover abort request is invalid")
	}
	target, err := e.Destination.Identity(ctx)
	if err != nil {
		return Result{}, errors.New("mail cutover target identity is unavailable")
	}
	manifest, err := e.Source.Inspect(ctx)
	if err != nil {
		return Result{}, err
	}
	if manifest.Phase == relay.MigrationSourceRetired {
		return Result{}, errors.New("retired mail cutover cannot be aborted")
	}
	status, err := e.Destination.MailCutoverStatus(ctx, actorPrincipalID, epochID)
	destinationAbsent := errors.Is(err, postgres.ErrNotFound)
	if err != nil && !destinationAbsent {
		return Result{}, err
	}
	if !destinationAbsent && status.Phase == postgres.MailCutoverActive {
		return Result{}, errors.New("active mail cutover cannot be aborted")
	}
	fingerprint := status.SourceFingerprint
	if destinationAbsent {
		if manifest.Phase != relay.MigrationSourcePrepared || manifest.EpochID != epochID || manifest.TargetIdentity != target {
			return Result{}, errors.New("mail cutover source cannot prove an abort binding")
		}
		fingerprint = manifest.Fingerprint
		cutoverRequest, requestErr := destinationRequest(manifest, epochID, target)
		if requestErr != nil {
			return Result{}, requestErr
		}
		status, err = e.Destination.ReserveMailCutoverAbort(ctx, actorPrincipalID, cutoverRequest)
		if err != nil || status.Phase != postgres.MailCutoverAborted || status.SourceFingerprint != fingerprint {
			if err != nil {
				return Result{}, err
			}
			return Result{}, errors.New("mail cutover abort reservation is unavailable")
		}
	}
	if manifest.Phase == relay.MigrationSourcePrepared && (manifest.EpochID != epochID || manifest.TargetIdentity != target || manifest.Fingerprint != fingerprint) {
		return Result{}, errors.New("mail cutover source binding does not match")
	}
	manifest, err = e.Source.Abort(ctx, epochID, target, fingerprint)
	if err != nil {
		return Result{}, err
	}
	if err := e.Destination.AbortMailCutover(ctx, actorPrincipalID, epochID, fingerprint); err != nil {
		return Result{}, err
	}
	return Result{EpochID: epochID, SourceFingerprint: fingerprint, SourcePhase: manifest.Phase, Phase: postgres.MailCutoverAborted}, nil
}

func destinationRequest(manifest relay.MigrationSourceManifest, epochID, target string) (postgres.MailCutoverRequest, error) {
	prepared := manifest
	prepared.Phase, prepared.EpochID, prepared.TargetIdentity = relay.MigrationSourcePrepared, epochID, target
	manifestBody, err := json.Marshal(prepared)
	if err != nil {
		return postgres.MailCutoverRequest{}, errors.New("mail cutover manifest cannot be encoded")
	}
	manifestDigest := sha256.Sum256(manifestBody)
	return postgres.MailCutoverRequest{
		EpochID: epochID, SourceID: prepared.SourceID, TargetIdentity: target, SourceFingerprint: prepared.Fingerprint,
		Manifest: manifestBody, ManifestSHA256: hex.EncodeToString(manifestDigest[:]),
	}, nil
}

func tableEvidence(manifest relay.MigrationSourceManifest, table string) (int64, string) {
	switch table {
	case "mail_endpoints":
		return manifest.Counts.Endpoints, manifest.TableSHA256.Endpoints
	case "mail_conversations":
		return manifest.Counts.Conversations, manifest.TableSHA256.Conversations
	case "mail_memberships":
		return manifest.Counts.Memberships, manifest.TableSHA256.Memberships
	case "mail_messages":
		return manifest.Counts.Messages, manifest.TableSHA256.Messages
	case "mail_deliveries":
		return manifest.Counts.Deliveries, manifest.TableSHA256.Deliveries
	case "mail_recipient_cursors":
		return manifest.Counts.RecipientCursors, manifest.TableSHA256.RecipientCursors
	case "mail_message_idempotency":
		return manifest.Counts.MessageIdempotency, manifest.TableSHA256.MessageIdempotency
	case "mail_conversation_idempotency":
		return manifest.Counts.ConversationIdempotency, manifest.TableSHA256.ConversationIdempotency
	case "mail_request_nonces":
		return manifest.Counts.RequestNonces, manifest.TableSHA256.RequestNonces
	default:
		return -1, ""
	}
}

// FileSource binds the executor to one explicit canonical service-owned file.
type FileSource struct{ Path string }

// Inspect returns the current durable SQLite source manifest.
func (s FileSource) Inspect(ctx context.Context) (relay.MigrationSourceManifest, error) {
	return relay.InspectMigrationSource(ctx, s.Path)
}

// Prepare installs the exact SQLite write barrier.
func (s FileSource) Prepare(ctx context.Context, epoch, target, expected string, cutoff time.Time) (relay.MigrationSourceManifest, error) {
	return relay.PrepareMigrationSource(ctx, s.Path, epoch, target, expected, cutoff)
}

// ReadBatch exports one bounded canonical source page.
func (s FileSource) ReadBatch(ctx context.Context, table, after string, limit int) (relay.MigrationSourceBatch, error) {
	return relay.ReadMigrationSourceBatch(ctx, s.Path, table, after, limit)
}

// Abort reopens the exact prepared source before retirement.
func (s FileSource) Abort(ctx context.Context, epoch, target, fingerprint string) (relay.MigrationSourceManifest, error) {
	return relay.AbortPreparedMigrationSource(ctx, s.Path, epoch, target, fingerprint)
}

// Retire permanently seals the exact prepared source.
func (s FileSource) Retire(ctx context.Context, epoch, target, fingerprint string) (relay.MigrationSourceManifest, error) {
	return relay.RetirePreparedMigrationSource(ctx, s.Path, epoch, target, fingerprint)
}
