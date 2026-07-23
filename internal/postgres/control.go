package postgres

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/google/uuid"
)

const (
	maxIdempotencyRequestBytes = 1 << 20
	maxIdempotencyResultBytes  = 64 << 10
	maxJobPayloadBytes         = 256 << 10
	maxJobAttempts             = 25
	maxJobClaimBatch           = 100
	maxJobLeaseDuration        = 15 * time.Minute
	minJobLeaseDuration        = time.Second
)

var boundedTokenPattern = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,127}$`)

// Capability is a bounded server-understood authority token.
type Capability string

// Capabilities are intentionally explicit and friendly values never imply one.
const (
	CapabilityProjectDiscover        Capability = "project.discover"
	CapabilityProjectCreate          Capability = "project.create"
	CapabilityProjectRead            Capability = "project.read"
	CapabilityProjectWrite           Capability = "project.write"
	CapabilityProjectAttachUnclaimed Capability = "project.identity.attach-unclaimed"
	CapabilityProjectAdminister      Capability = "project.administer"
	CapabilityConversationSend       Capability = "conversation.send"
	CapabilityConversationReceive    Capability = "conversation.receive"
	CapabilityConversationAdminister Capability = "conversation.administer"
	CapabilityMemorySearch           Capability = "memory.search"
	CapabilityMemoryRead             Capability = "memory.read"
	CapabilityMemoryPropose          Capability = "memory.propose"
	CapabilityMemoryWrite            Capability = "memory.write"
	CapabilityMemoryAdminister       Capability = "memory.administer"
	CapabilityMemoryPurge            Capability = "memory.purge"
	CapabilityAttachmentUpload       Capability = "attachment.upload"
	CapabilityAttachmentDownload     Capability = "attachment.download"
	CapabilityAttachmentDelete       Capability = "attachment.delete"
)

type capabilityScope uint8

const (
	allowInstallation capabilityScope = 1 << iota
	allowProject
	allowAllProjects
)

var capabilityScopes = map[Capability]capabilityScope{
	CapabilityProjectDiscover:        allowProject | allowAllProjects,
	CapabilityProjectCreate:          allowInstallation,
	CapabilityProjectRead:            allowProject | allowAllProjects,
	CapabilityProjectWrite:           allowProject | allowAllProjects,
	CapabilityProjectAttachUnclaimed: allowProject | allowAllProjects,
	CapabilityProjectAdminister:      allowProject | allowAllProjects,
	CapabilityConversationSend:       allowProject | allowAllProjects,
	CapabilityConversationReceive:    allowProject | allowAllProjects,
	CapabilityConversationAdminister: allowProject | allowAllProjects,
	CapabilityMemorySearch:           allowProject | allowAllProjects,
	CapabilityMemoryRead:             allowProject | allowAllProjects,
	CapabilityMemoryPropose:          allowProject | allowAllProjects,
	CapabilityMemoryWrite:            allowProject | allowAllProjects,
	CapabilityMemoryAdminister:       allowProject | allowAllProjects,
	CapabilityMemoryPurge:            allowProject | allowAllProjects,
	CapabilityAttachmentUpload:       allowProject | allowAllProjects,
	CapabilityAttachmentDownload:     allowProject | allowAllProjects,
	CapabilityAttachmentDelete:       allowProject | allowAllProjects,
}

// GrantScope distinguishes installation authority, one opaque project, and a
// dynamic grant over all current and future projects.
type GrantScope string

// Supported explicit grant scopes.
const (
	ScopeInstallation GrantScope = "installation"
	ScopeProject      GrantScope = "project"
	ScopeAllProjects  GrantScope = "all_projects"
)

// Grant binds one principal and capability to an explicit scope.
type Grant struct {
	PrincipalID string
	Scope       GrantScope
	ProjectID   string
	Capability  Capability
}

// Validate fails closed on malformed identifiers, capabilities, or scope shape.
func (g Grant) Validate() error {
	if !validOpaqueID(g.PrincipalID) {
		return errors.New("invalid grant principal")
	}
	allowed, ok := capabilityScopes[g.Capability]
	if !ok {
		return errors.New("invalid grant capability")
	}
	switch g.Scope {
	case ScopeInstallation:
		if g.ProjectID != "" || allowed&allowInstallation == 0 {
			return errors.New("invalid installation grant")
		}
	case ScopeProject:
		if !validOpaqueID(g.ProjectID) || allowed&allowProject == 0 {
			return errors.New("invalid project grant")
		}
	case ScopeAllProjects:
		if g.ProjectID != "" || allowed&allowAllProjects == 0 {
			return errors.New("invalid all-projects grant")
		}
	default:
		return errors.New("invalid grant scope")
	}
	return nil
}

// IdempotencyRequest identifies one globally unique mutation attempt. The body
// is hashed but never persisted by the idempotency layer.
type IdempotencyRequest struct {
	PrincipalID string
	Operation   string
	Key         string
	Body        []byte
}

// Validate enforces opaque UUID keys so a key cannot silently change principal
// or operation without conflicting with the original record.
func (r IdempotencyRequest) Validate() error {
	if !validOpaqueID(r.PrincipalID) || !boundedTokenPattern.MatchString(r.Operation) || !validOpaqueID(r.Key) || len(r.Body) > maxIdempotencyRequestBytes {
		return errors.New("invalid idempotency request")
	}
	return nil
}

func requestDigest(body []byte) [sha256.Size]byte { return sha256.Sum256(body) }

// OutcomeStatus is a closed terminal mutation status.
type OutcomeStatus string

// Supported immutable idempotency outcome statuses.
const (
	OutcomeSucceeded OutcomeStatus = "succeeded"
	OutcomeRejected  OutcomeStatus = "rejected"
)

// IdempotencyOutcome is the bounded immutable result returned to exact retries.
type IdempotencyOutcome struct {
	Status     OutcomeStatus
	ResourceID string
	Result     json.RawMessage
}

// Validate rejects free-form statuses, malformed IDs, and oversized/non-JSON results.
func (o IdempotencyOutcome) Validate() error {
	if o.Status != OutcomeSucceeded && o.Status != OutcomeRejected {
		return errors.New("invalid idempotency outcome status")
	}
	if o.ResourceID != "" && !validOpaqueID(o.ResourceID) {
		return errors.New("invalid idempotency outcome resource")
	}
	if len(o.Result) == 0 || len(o.Result) > maxIdempotencyResultBytes || !json.Valid(o.Result) {
		return errors.New("invalid idempotency outcome result")
	}
	return nil
}

// AuditAction is a closed content-free security or administrative event class.
type AuditAction string

// Supported content-free audit actions.
const (
	AuditPrincipalCreate             AuditAction = "principal.create"
	AuditProjectCreate               AuditAction = "project.create"
	AuditGrantCreate                 AuditAction = "grant.create"
	AuditGrantDelete                 AuditAction = "grant.delete"
	AuditJobEnqueue                  AuditAction = "job.enqueue"
	AuditJobComplete                 AuditAction = "job.complete"
	AuditJobRetry                    AuditAction = "job.retry"
	AuditJobFail                     AuditAction = "job.fail"
	AuditOwnerBootstrap              AuditAction = "owner.bootstrap"
	AuditEnrollmentCreate            AuditAction = "enrollment.create"
	AuditEnrollmentRedeem            AuditAction = "enrollment.redeem"
	AuditCredentialRotate            AuditAction = "credential.rotate" // #nosec G101 -- content-free audit action, not a credential.
	AuditCredentialRevoke            AuditAction = "credential.revoke" // #nosec G101 -- content-free audit action, not a credential.
	AuditLegacyRegister              AuditAction = "legacy.register"
	AuditLegacyExchange              AuditAction = "legacy.exchange"
	AuditLegacyRetire                AuditAction = "legacy.retire"
	AuditLegacyDisable               AuditAction = "legacy.disable"
	AuditProjectIdentityAttach       AuditAction = "project.identity.attach"
	AuditProjectMergePreview         AuditAction = "project.merge.preview"
	AuditProjectMerge                AuditAction = "project.merge"
	AuditMemoryCreate                AuditAction = "memory.create"
	AuditMemoryEvidenceCreate        AuditAction = "memory.evidence_create"
	AuditMemoryUpdate                AuditAction = "memory.update"
	AuditMemoryArchive               AuditAction = "memory.archive"
	AuditMemoryRestore               AuditAction = "memory.restore"
	AuditMemoryDelete                AuditAction = "memory.delete"
	AuditMemorySecretExceptionCreate AuditAction = "memory.secret_exception.create"
	AuditMemorySecretExceptionRevoke AuditAction = "memory.secret_exception.revoke"
	AuditMemorySecretRescan          AuditAction = "memory.secret_rescan"
	AuditMemoryQuarantine            AuditAction = "memory.quarantine"
	AuditMemoryQuarantineRelease     AuditAction = "memory.quarantine_release"
	AuditMemoryProposalCreate        AuditAction = "memory.proposal.create"
	AuditMemoryProposalApprove       AuditAction = "memory.proposal.approve"
	AuditMemoryProposalReject        AuditAction = "memory.proposal.reject"
	AuditMemoryProposalExpire        AuditAction = "memory.proposal.expire"
	AuditMemoryProposalPrune         AuditAction = "memory.proposal.prune"
	AuditMemoryReconcile             AuditAction = "memory.reconcile"
)

// AuditOutcome is a closed content-free result class.
type AuditOutcome string

// Supported content-free audit outcomes.
const (
	AuditSucceeded AuditOutcome = "succeeded"
	AuditRejected  AuditOutcome = "rejected"
)

// AuditTargetKind is a closed content-free target class.
type AuditTargetKind string

// Supported content-free audit target kinds.
const (
	AuditTargetPrincipal       AuditTargetKind = "principal"
	AuditTargetProject         AuditTargetKind = "project"
	AuditTargetGrant           AuditTargetKind = "grant"
	AuditTargetJob             AuditTargetKind = "job"
	AuditTargetEnrollment      AuditTargetKind = "enrollment"
	AuditTargetCredential      AuditTargetKind = "credential"
	AuditTargetLegacyMachine   AuditTargetKind = "legacy_machine"
	AuditTargetProjectIdentity AuditTargetKind = "project_identity"
	AuditTargetProjectMerge    AuditTargetKind = "project_merge"
	AuditTargetMemoryItem      AuditTargetKind = "memory_item"
	AuditTargetMemoryProposal  AuditTargetKind = "memory_proposal"
)

var validAuditActions = map[AuditAction]struct{}{
	AuditPrincipalCreate: {}, AuditProjectCreate: {}, AuditGrantCreate: {}, AuditGrantDelete: {}, AuditJobEnqueue: {}, AuditJobComplete: {}, AuditJobRetry: {}, AuditJobFail: {}, AuditOwnerBootstrap: {}, AuditEnrollmentCreate: {}, AuditEnrollmentRedeem: {}, AuditCredentialRotate: {}, AuditCredentialRevoke: {}, AuditLegacyRegister: {}, AuditLegacyExchange: {}, AuditLegacyRetire: {}, AuditLegacyDisable: {}, AuditProjectIdentityAttach: {}, AuditProjectMergePreview: {}, AuditProjectMerge: {}, AuditMemoryCreate: {}, AuditMemoryEvidenceCreate: {}, AuditMemoryUpdate: {}, AuditMemoryArchive: {}, AuditMemoryRestore: {}, AuditMemoryDelete: {}, AuditMemorySecretExceptionCreate: {}, AuditMemorySecretExceptionRevoke: {}, AuditMemorySecretRescan: {}, AuditMemoryQuarantine: {}, AuditMemoryQuarantineRelease: {}, AuditMemoryProposalCreate: {}, AuditMemoryProposalApprove: {}, AuditMemoryProposalReject: {}, AuditMemoryProposalExpire: {}, AuditMemoryProposalPrune: {}, AuditMemoryReconcile: {},
}

// AuditEvent contains identifiers and closed classification values only.
type AuditEvent struct {
	PrincipalID string
	ProjectID   string
	Action      AuditAction
	Outcome     AuditOutcome
	TargetKind  AuditTargetKind
	TargetID    string
}

// Validate prevents request bodies, labels, paths, or other free-form content
// from entering the audit primitive.
func (e AuditEvent) Validate() error {
	if e.PrincipalID != "" && !validOpaqueID(e.PrincipalID) {
		return errors.New("invalid audit principal")
	}
	if e.ProjectID != "" && !validOpaqueID(e.ProjectID) {
		return errors.New("invalid audit project")
	}
	if e.TargetID != "" && !validOpaqueID(e.TargetID) {
		return errors.New("invalid audit target")
	}
	if _, ok := validAuditActions[e.Action]; !ok {
		return errors.New("invalid audit classification")
	}
	if (e.Outcome != AuditSucceeded && e.Outcome != AuditRejected) || (e.TargetKind != AuditTargetPrincipal && e.TargetKind != AuditTargetProject && e.TargetKind != AuditTargetGrant && e.TargetKind != AuditTargetJob && e.TargetKind != AuditTargetEnrollment && e.TargetKind != AuditTargetCredential && e.TargetKind != AuditTargetLegacyMachine && e.TargetKind != AuditTargetProjectIdentity && e.TargetKind != AuditTargetProjectMerge && e.TargetKind != AuditTargetMemoryItem && e.TargetKind != AuditTargetMemoryProposal) {
		return errors.New("invalid audit classification")
	}
	return nil
}

// EnqueueJob is one bounded transactional outbox entry.
type EnqueueJob struct {
	ActorPrincipalID string
	Kind             string
	ProjectID        string
	Payload          json.RawMessage
	MaxAttempts      int
	Delay            time.Duration
}

// Validate enforces queue storage and retry ceilings before a transaction starts.
func (j EnqueueJob) Validate() error {
	_, knownKind := jobClaimCapability(j.Kind)
	if !validOpaqueID(j.ActorPrincipalID) || !knownKind || !validOpaqueID(j.ProjectID) || len(j.Payload) == 0 || len(j.Payload) > maxJobPayloadBytes || !json.Valid(j.Payload) || j.MaxAttempts < 1 || j.MaxAttempts > maxJobAttempts || j.Delay < 0 || j.Delay > maxJobDelay {
		return errors.New("invalid job")
	}
	return nil
}

// ClaimJobs bounds one worker claim operation.
type ClaimJobs struct {
	Kind          string
	Holder        string
	Limit         int
	LeaseDuration time.Duration
}

// Validate enforces bounded batches and leases.
func (c ClaimJobs) Validate() error {
	if !boundedTokenPattern.MatchString(c.Kind) || !validOpaqueID(c.Holder) || c.Limit < 1 || c.Limit > maxJobClaimBatch || c.LeaseDuration < minJobLeaseDuration || c.LeaseDuration > maxJobLeaseDuration {
		return errors.New("invalid job claim")
	}
	return nil
}

func validOpaqueID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}
