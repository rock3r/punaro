package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"strconv"

	"github.com/google/uuid"
)

// MemoryConsolidationPlanner turns one bounded, lease-fenced source page into
// zero or more proposal bodies. It cannot choose an authorization principal,
// project, or idempotency identity; the executor owns those control fields.
type MemoryConsolidationPlanner interface {
	Propose(context.Context, MemoryConsolidationInput) ([]MemoryConsolidationProposal, error)
}

// MemoryConsolidationProposal is untrusted planner output. It deliberately
// excludes principal, project, and idempotency fields so it cannot gain
// proposal authority by choosing those values.
type MemoryConsolidationProposal struct {
	Action   MemoryProposalAction
	Steps    []MemoryProposalStepInput
	Evidence []MemoryProposalEvidenceInput
}

func (proposal MemoryConsolidationProposal) normalized() (MemoryConsolidationProposal, error) {
	validated, err := (MemoryProposalCreateRequest{
		PrincipalID:    "00000000-0000-4000-8000-000000000001",
		ProjectID:      "00000000-0000-4000-8000-000000000002",
		IdempotencyKey: "00000000-0000-4000-8000-000000000003",
		Action:         proposal.Action,
		Steps:          proposal.Steps,
		Evidence:       proposal.Evidence,
	}).normalized()
	if err != nil {
		return MemoryConsolidationProposal{}, err
	}
	return MemoryConsolidationProposal{Action: validated.Action, Steps: validated.Steps, Evidence: validated.Evidence}, nil
}

// MemoryConsolidationExecutionRequest binds one pass to the caller-selected
// authorized proposer and direct canonical project. The planner never sees or
// controls these fields.
type MemoryConsolidationExecutionRequest struct {
	Lease       MemoryConsolidationLease
	PrincipalID string
	ProjectID   string
}

func (request MemoryConsolidationExecutionRequest) valid() bool {
	return request.Lease.valid() && validOpaqueID(request.PrincipalID) && validOpaqueID(request.ProjectID)
}

type memoryConsolidationExecutorStore interface {
	ReadMemoryConsolidationInput(context.Context, MemoryConsolidationLease) (MemoryConsolidationInput, error)
	StageMemoryConsolidationProposal(context.Context, MemoryConsolidationProposalRequest) (MemoryProposalResult, error)
	AdvanceMemoryConsolidationCheckpoint(context.Context, MemoryConsolidationLease, string, int64) error
}

// MemoryConsolidationExecutor runs one bounded proposal-only pass. Its only
// durable effects are staged proposals and, after all staging succeeds, an
// exact fenced checkpoint advance.
type MemoryConsolidationExecutor struct {
	store   memoryConsolidationExecutorStore
	planner MemoryConsolidationPlanner
	policy  MemoryConsolidationPolicy
}

// MemoryConsolidationExecutionResult reports one completed bounded pass.
type MemoryConsolidationExecutionResult struct {
	Sources  int
	Staged   int
	Advanced bool
}

// NewMemoryConsolidationExecutor constructs a provider-agnostic, bounded
// proposal orchestrator. A concrete model client belongs in a later adapter.
func NewMemoryConsolidationExecutor(store memoryConsolidationExecutorStore, planner MemoryConsolidationPlanner, policy MemoryConsolidationPolicy) (*MemoryConsolidationExecutor, error) {
	if store == nil || planner == nil || policy.Validate() != nil {
		return nil, errors.New("memory consolidation executor is invalid")
	}
	return &MemoryConsolidationExecutor{store: store, planner: planner, policy: policy}, nil
}

// Execute reads one live page, stages every validated output, and only then
// advances the exact checkpoint. Any failure leaves the checkpoint leased for
// expiry/reclaim, so a later worker can safely replay the page.
func (e *MemoryConsolidationExecutor) Execute(ctx context.Context, request MemoryConsolidationExecutionRequest) (MemoryConsolidationExecutionResult, error) {
	if !request.valid() {
		return MemoryConsolidationExecutionResult{}, errors.New("invalid consolidation lease")
	}
	lease := request.Lease
	passCtx, cancel := context.WithTimeout(ctx, e.policy.PassTimeout)
	defer cancel()
	input, err := e.store.ReadMemoryConsolidationInput(passCtx, lease)
	if err != nil {
		return MemoryConsolidationExecutionResult{}, err
	}
	if input.Lease != lease || input.TimelineID != lease.TimelineID || !input.valid() || len(input.Sources) > e.policy.MaxChanges {
		return MemoryConsolidationExecutionResult{}, errors.New("consolidation input is invalid")
	}
	proposals, err := e.planner.Propose(passCtx, input)
	if err != nil {
		return MemoryConsolidationExecutionResult{}, err
	}
	if len(proposals) > e.policy.MaxProposals {
		return MemoryConsolidationExecutionResult{}, errors.New("consolidation output exceeds policy")
	}
	normalized := make([]MemoryConsolidationProposal, 0, len(proposals))
	keys := make([]string, 0, len(proposals))
	seen := make(map[string]struct{}, len(proposals))
	for _, raw := range proposals {
		proposal, err := raw.normalized()
		if err != nil || len(proposal.Evidence) > e.policy.MaxEvidencePerProposal {
			return MemoryConsolidationExecutionResult{}, errors.New("consolidation output is invalid")
		}
		key := memoryConsolidationProposalIdempotencyKey(input, request.PrincipalID, request.ProjectID, proposal)
		if _, duplicate := seen[key]; duplicate {
			return MemoryConsolidationExecutionResult{}, errors.New("consolidation output is invalid")
		}
		seen[key] = struct{}{}
		normalized = append(normalized, proposal)
		keys = append(keys, key)
	}
	for ordinal, proposal := range normalized {
		staged := MemoryProposalCreateRequest{PrincipalID: request.PrincipalID, ProjectID: request.ProjectID, IdempotencyKey: keys[ordinal], Action: proposal.Action, Steps: proposal.Steps, Evidence: proposal.Evidence}
		if _, err := e.store.StageMemoryConsolidationProposal(passCtx, MemoryConsolidationProposalRequest{Input: input, Proposal: staged}); err != nil {
			return MemoryConsolidationExecutionResult{}, err
		}
	}
	if err := e.store.AdvanceMemoryConsolidationCheckpoint(passCtx, lease, input.TimelineID, input.NextSequence); err != nil {
		return MemoryConsolidationExecutionResult{}, err
	}
	return MemoryConsolidationExecutionResult{Sources: len(input.Sources), Staged: len(proposals), Advanced: true}, nil
}

func memoryConsolidationProposalIdempotencyKey(input MemoryConsolidationInput, principalID, projectID string, proposal MemoryConsolidationProposal) string {
	_, payloadSHA := memoryProposalPayloadSHA(projectID, proposal.Action, proposal.Steps, proposal.Evidence)
	digest := sha256.Sum256([]byte(input.Lease.ScopeID + "\x00" + input.TimelineID + "\x00" + strconv.FormatInt(input.Lease.Sequence, 10) + "\x00" + strconv.FormatInt(input.NextSequence, 10) + "\x00" + principalID + "\x00" + projectID + "\x00" + string(payloadSHA)))
	return uuid.NewSHA1(uuid.NameSpaceOID, digest[:]).String()
}
