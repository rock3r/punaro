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
	readMemoryConsolidationInput(context.Context, MemoryConsolidationLease, int) (MemoryConsolidationInput, error)
	LoadMemoryConsolidationPass(context.Context, MemoryConsolidationLease, MemoryConsolidationExecutionRequest) (MemoryConsolidationInput, MemoryConsolidationExecutionRequest, []MemoryConsolidationProposal, bool, error)
	ReserveMemoryConsolidationPass(context.Context, MemoryConsolidationInput, MemoryConsolidationExecutionRequest, []MemoryConsolidationProposal) (MemoryConsolidationInput, MemoryConsolidationExecutionRequest, []MemoryConsolidationProposal, error)
	StageMemoryConsolidationProposal(context.Context, MemoryConsolidationProposalRequest) (MemoryProposalResult, error)
	AbandonMemoryConsolidationPass(context.Context, MemoryConsolidationInput, MemoryConsolidationExecutionRequest) error
	CompleteMemoryConsolidationPass(context.Context, MemoryConsolidationInput, MemoryConsolidationExecutionRequest) error
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

// Execute reads one live page, durably fixes its validated planner output,
// stages every entry, and only then completes the exact checkpoint. Any
// failure leaves that immutable pass available for a later worker to replay
// without asking a planner to produce a replacement proposal set.
func (e *MemoryConsolidationExecutor) Execute(ctx context.Context, request MemoryConsolidationExecutionRequest) (MemoryConsolidationExecutionResult, error) {
	if !request.valid() {
		return MemoryConsolidationExecutionResult{}, errors.New("invalid consolidation lease")
	}
	lease := request.Lease
	passCtx, cancel := context.WithTimeout(ctx, e.policy.PassTimeout)
	defer cancel()
	input, effectiveRequest, proposals, found, err := e.store.LoadMemoryConsolidationPass(passCtx, lease, request)
	if err != nil {
		return MemoryConsolidationExecutionResult{}, err
	}
	if !found {
		effectiveRequest = request
		input, err = e.store.readMemoryConsolidationInput(passCtx, lease, e.policy.MaxChanges)
		if err != nil {
			return MemoryConsolidationExecutionResult{}, err
		}
	}
	if input.Lease != lease || input.TimelineID != lease.TimelineID || !input.valid() || len(input.Sources) > e.policy.MaxChanges {
		return MemoryConsolidationExecutionResult{}, errors.New("consolidation input is invalid")
	}
	if !found {
		proposals, err = e.planner.Propose(passCtx, input)
		if err != nil {
			return MemoryConsolidationExecutionResult{}, err
		}
		proposals, err = e.normalizeMemoryConsolidationProposals(proposals)
		if err != nil {
			return MemoryConsolidationExecutionResult{}, err
		}
		if len(input.Sources) == 0 && len(proposals) != 0 {
			return MemoryConsolidationExecutionResult{}, errors.New("consolidation output requires source documents")
		}
		input, effectiveRequest, proposals, err = e.store.ReserveMemoryConsolidationPass(passCtx, input, request, proposals)
		if err != nil {
			return MemoryConsolidationExecutionResult{}, err
		}
	}
	proposals, err = e.normalizeMemoryConsolidationProposals(proposals)
	if err != nil {
		return MemoryConsolidationExecutionResult{}, err
	}
	for ordinal, proposal := range proposals {
		staged := MemoryProposalCreateRequest{PrincipalID: effectiveRequest.PrincipalID, ProjectID: effectiveRequest.ProjectID, IdempotencyKey: memoryConsolidationProposalIdempotencyKey(input, effectiveRequest.PrincipalID, effectiveRequest.ProjectID, ordinal), Action: proposal.Action, Steps: proposal.Steps, Evidence: proposal.Evidence}
		if _, err := e.store.StageMemoryConsolidationProposal(passCtx, MemoryConsolidationProposalRequest{Input: input, Proposal: staged}); err != nil {
			if errors.Is(err, errMemoryConsolidationSourceStale) {
				if abandonErr := e.store.AbandonMemoryConsolidationPass(passCtx, input, effectiveRequest); abandonErr != nil {
					return MemoryConsolidationExecutionResult{}, abandonErr
				}
				return MemoryConsolidationExecutionResult{}, ErrStaleMemoryConsolidationLease
			}
			return MemoryConsolidationExecutionResult{}, err
		}
	}
	if err := e.store.CompleteMemoryConsolidationPass(passCtx, input, effectiveRequest); err != nil {
		return MemoryConsolidationExecutionResult{}, err
	}
	return MemoryConsolidationExecutionResult{Sources: len(input.Sources), Staged: len(proposals), Advanced: true}, nil
}

func (e *MemoryConsolidationExecutor) normalizeMemoryConsolidationProposals(raw []MemoryConsolidationProposal) ([]MemoryConsolidationProposal, error) {
	if len(raw) > e.policy.MaxProposals {
		return nil, errors.New("consolidation output exceeds policy")
	}
	normalized := make([]MemoryConsolidationProposal, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, value := range raw {
		proposal, err := value.normalized()
		if err != nil || len(proposal.Evidence) > e.policy.MaxEvidencePerProposal {
			return nil, errors.New("consolidation output is invalid")
		}
		_, payloadSHA := memoryProposalPayloadSHA("00000000-0000-4000-8000-000000000001", proposal.Action, proposal.Steps, proposal.Evidence)
		if _, duplicate := seen[string(payloadSHA)]; duplicate {
			return nil, errors.New("consolidation output is invalid")
		}
		seen[string(payloadSHA)] = struct{}{}
		normalized = append(normalized, proposal)
	}
	return normalized, nil
}

func memoryConsolidationProposalIdempotencyKey(input MemoryConsolidationInput, principalID, projectID string, ordinal int) string {
	digest := sha256.Sum256([]byte(input.Lease.ScopeID + "\x00" + input.TimelineID + "\x00" + strconv.FormatInt(input.Lease.Sequence, 10) + "\x00" + strconv.FormatInt(input.NextSequence, 10) + "\x00" + principalID + "\x00" + projectID + "\x00" + strconv.Itoa(ordinal)))
	return uuid.NewSHA1(uuid.NameSpaceOID, digest[:]).String()
}
