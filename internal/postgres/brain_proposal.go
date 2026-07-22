package postgres

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"
)

const (
	maxMemoryProposalSteps              = 8
	maxMemoryProposalEvidence           = 16
	maxLiveMemoryProposalsPrincipal     = 16
	maxLiveMemoryProposalsScope         = 64
	maxRetainedMemoryProposalsPrincipal = 128
	maxRetainedMemoryProposalsScope     = 512
	memoryProposalMaintenanceBatch      = 64
	memoryProposalRetention             = 30 * 24 * time.Hour
)

// MemoryProposalAction is the closed user-visible intent of one staged action.
type MemoryProposalAction string

const (
	// MemoryProposalCreate stages creation of one curated item.
	MemoryProposalCreate MemoryProposalAction = "create"
	// MemoryProposalUpdate stages replacement of one curated revision.
	MemoryProposalUpdate MemoryProposalAction = "update"
	// MemoryProposalArchive stages archival of one curated item.
	MemoryProposalArchive MemoryProposalAction = "archive"
	// MemoryProposalMerge stages one update followed by bounded archival steps.
	MemoryProposalMerge MemoryProposalAction = "merge"
	// MemoryProposalSplit stages one archive followed by bounded create steps.
	MemoryProposalSplit MemoryProposalAction = "split"
)

// MemoryProposalStepOperation is one primitive applied atomically at approval.
type MemoryProposalStepOperation string

const (
	// MemoryProposalStepCreate creates one curated item during approval.
	MemoryProposalStepCreate MemoryProposalStepOperation = "create"
	// MemoryProposalStepUpdate replaces one exact curated revision during approval.
	MemoryProposalStepUpdate MemoryProposalStepOperation = "update"
	// MemoryProposalStepArchive archives one exact curated revision during approval.
	MemoryProposalStepArchive MemoryProposalStepOperation = "archive"
)

// MemoryProposalState is the closed durable proposal lifecycle.
type MemoryProposalState string

const (
	// MemoryProposalPending is the only proposal state that can be decided.
	MemoryProposalPending MemoryProposalState = "pending"
	// MemoryProposalApproved records a successfully and atomically applied proposal.
	MemoryProposalApproved MemoryProposalState = "approved"
	// MemoryProposalRejected records an explicitly closed proposal with no canonical mutation.
	MemoryProposalRejected MemoryProposalState = "rejected"
	// MemoryProposalExpired records a deterministic timeout with no canonical mutation.
	MemoryProposalExpired MemoryProposalState = "expired"
)

var (
	// ErrStaleMemoryProposal reports proposal or bound-revision CAS failure.
	ErrStaleMemoryProposal = errors.New("memory proposal is stale")
	// ErrMemoryProposalCapacity reports a hard live or retained proposal quota.
	ErrMemoryProposalCapacity = errors.New("memory proposal capacity is full")
	// ErrMemoryProposalAlreadySatisfied rejects a staged state transition that is already true.
	ErrMemoryProposalAlreadySatisfied = errors.New("memory proposal state transition is already satisfied")
)

// MemoryProposalStepInput is a typed create, update, or archive primitive.
type MemoryProposalStepInput struct {
	Operation    MemoryProposalStepOperation `json:"operation"`
	ItemID       string                      `json:"item_id,omitempty"`
	ExpectedETag string                      `json:"expected_etag,omitempty"`
	LogicalKey   string                      `json:"logical_key,omitempty"`
	Kind         string                      `json:"kind,omitempty"`
	Trust        string                      `json:"trust,omitempty"`
	Document     json.RawMessage             `json:"document,omitempty"`
	Archived     bool                        `json:"archived,omitempty"`
}

// MemoryProposalEvidenceInput binds approval to one exact evidence revision.
type MemoryProposalEvidenceInput struct {
	ItemID   string `json:"item_id"`
	Revision int64  `json:"revision"`
}

// MemoryProposalCreateRequest stages one immutable bounded action.
type MemoryProposalCreateRequest struct {
	PrincipalID    string
	ProjectID      string
	IdempotencyKey string
	Action         MemoryProposalAction
	Steps          []MemoryProposalStepInput
	Evidence       []MemoryProposalEvidenceInput
}

// MemoryProposalDecisionRequest approves or rejects one exact pending proposal.
type MemoryProposalDecisionRequest struct {
	PrincipalID    string
	ProjectID      string
	ProposalID     string
	IdempotencyKey string
	ExpectedETag   string
}

// MemoryProposalStep is one immutable ordered staged primitive.
type MemoryProposalStep struct {
	Ordinal int `json:"ordinal"`
	MemoryProposalStepInput
	targetRevision int64
}

// MemoryProposalEvidence is one immutable ordered exact evidence binding.
type MemoryProposalEvidence struct {
	Ordinal int `json:"ordinal"`
	MemoryProposalEvidenceInput
}

// MemoryProposalAppliedStep durably links one approved primitive to its canonical revision.
type MemoryProposalAppliedStep struct {
	Ordinal  int    `json:"ordinal"`
	ItemID   string `json:"item_id"`
	Revision int64  `json:"revision"`
}

// MemoryProposal is one authorized proposal and its immutable payload.
type MemoryProposal struct {
	ProposalID string                      `json:"proposal_id"`
	ScopeID    string                      `json:"scope_id"`
	ProjectID  string                      `json:"project_id"`
	Action     MemoryProposalAction        `json:"action"`
	State      MemoryProposalState         `json:"state"`
	ETag       string                      `json:"etag"`
	ProposedBy string                      `json:"proposed_by"`
	DecidedBy  string                      `json:"decided_by,omitempty"`
	CreatedAt  time.Time                   `json:"created_at"`
	ExpiresAt  time.Time                   `json:"expires_at"`
	DecidedAt  *time.Time                  `json:"decided_at,omitempty"`
	Steps      []MemoryProposalStep        `json:"steps"`
	Evidence   []MemoryProposalEvidence    `json:"evidence"`
	Results    []MemoryProposalAppliedStep `json:"results,omitempty"`
	payloadSHA []byte
	payload    []byte
}

// MemoryProposalResult is content-free and safe for durable idempotency.
type MemoryProposalResult struct {
	ProposalID string                 `json:"proposal_id"`
	State      MemoryProposalState    `json:"state"`
	ETag       string                 `json:"etag"`
	Mutations  []MemoryMutationResult `json:"mutations,omitempty"`
}

func (r MemoryProposalCreateRequest) normalized() (MemoryProposalCreateRequest, error) {
	if !validOpaqueID(r.PrincipalID) || !validOpaqueID(r.ProjectID) || !validOpaqueID(r.IdempotencyKey) ||
		len(r.Steps) < 1 || len(r.Steps) > maxMemoryProposalSteps || len(r.Evidence) > maxMemoryProposalEvidence {
		return MemoryProposalCreateRequest{}, errors.New("invalid memory proposal")
	}
	result := r
	result.Steps = append([]MemoryProposalStepInput(nil), r.Steps...)
	result.Evidence = append([]MemoryProposalEvidenceInput(nil), r.Evidence...)
	targets := make(map[string]struct{}, len(result.Steps))
	createKeys := make(map[string]struct{}, len(result.Steps))
	for index := range result.Steps {
		step := &result.Steps[index]
		switch step.Operation {
		case MemoryProposalStepCreate:
			if step.ItemID != "" || step.ExpectedETag != "" || step.Archived || !validMemoryLogicalKey(step.LogicalKey) || !validMemoryToken(step.Kind) || !validMemoryToken(step.Trust) {
				return MemoryProposalCreateRequest{}, errors.New("invalid memory proposal create step")
			}
			document, err := canonicalMemoryDocument(step.Document)
			if err != nil {
				return MemoryProposalCreateRequest{}, err
			}
			step.Document = document
		case MemoryProposalStepUpdate:
			if !validOpaqueID(step.ItemID) || !validMemoryETagShape(step.ExpectedETag) || step.Archived || !validMemoryLogicalKey(step.LogicalKey) || !validMemoryToken(step.Kind) || !validMemoryToken(step.Trust) {
				return MemoryProposalCreateRequest{}, errors.New("invalid memory proposal update step")
			}
			document, err := canonicalMemoryDocument(step.Document)
			if err != nil {
				return MemoryProposalCreateRequest{}, err
			}
			step.Document = document
		case MemoryProposalStepArchive:
			if !validOpaqueID(step.ItemID) || !validMemoryETagShape(step.ExpectedETag) || step.LogicalKey != "" || step.Kind != "" || step.Trust != "" || len(step.Document) != 0 {
				return MemoryProposalCreateRequest{}, errors.New("invalid memory proposal archive step")
			}
		default:
			return MemoryProposalCreateRequest{}, errors.New("invalid memory proposal step")
		}
		if step.ItemID != "" {
			if _, duplicate := targets[step.ItemID]; duplicate {
				return MemoryProposalCreateRequest{}, errors.New("duplicate memory proposal target")
			}
			targets[step.ItemID] = struct{}{}
		}
		if step.Operation == MemoryProposalStepCreate && step.LogicalKey != "" {
			if _, duplicate := createKeys[step.LogicalKey]; duplicate {
				return MemoryProposalCreateRequest{}, errors.New("duplicate memory proposal create key")
			}
			createKeys[step.LogicalKey] = struct{}{}
		}
	}
	if !validMemoryProposalShape(result.Action, result.Steps) {
		return MemoryProposalCreateRequest{}, errors.New("invalid memory proposal action shape")
	}
	evidenceItems := make(map[string]struct{}, len(result.Evidence))
	for _, evidence := range result.Evidence {
		if !validOpaqueID(evidence.ItemID) || evidence.Revision < 1 {
			return MemoryProposalCreateRequest{}, errors.New("invalid memory proposal evidence")
		}
		if _, duplicate := evidenceItems[evidence.ItemID]; duplicate {
			return MemoryProposalCreateRequest{}, errors.New("duplicate memory proposal evidence")
		}
		evidenceItems[evidence.ItemID] = struct{}{}
	}
	payload, _ := memoryProposalPayloadSHA(result.ProjectID, result.Action, result.Steps, result.Evidence)
	if len(payload) > maxIdempotencyRequestBytes {
		return MemoryProposalCreateRequest{}, errors.New("memory proposal payload is too large")
	}
	return result, nil
}

func validMemoryProposalShape(action MemoryProposalAction, steps []MemoryProposalStepInput) bool {
	switch action {
	case MemoryProposalCreate:
		return len(steps) == 1 && steps[0].Operation == MemoryProposalStepCreate
	case MemoryProposalUpdate:
		return len(steps) == 1 && steps[0].Operation == MemoryProposalStepUpdate
	case MemoryProposalArchive:
		return len(steps) == 1 && steps[0].Operation == MemoryProposalStepArchive && steps[0].Archived
	case MemoryProposalMerge:
		if len(steps) < 2 || steps[0].Operation != MemoryProposalStepUpdate {
			return false
		}
		for _, step := range steps[1:] {
			if step.Operation != MemoryProposalStepArchive || !step.Archived {
				return false
			}
		}
		return true
	case MemoryProposalSplit:
		if len(steps) < 3 || steps[0].Operation != MemoryProposalStepArchive || !steps[0].Archived {
			return false
		}
		for _, step := range steps[1:] {
			if step.Operation != MemoryProposalStepCreate {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func (r MemoryProposalDecisionRequest) validate() error {
	if !validOpaqueID(r.PrincipalID) || !validOpaqueID(r.ProjectID) || !validOpaqueID(r.ProposalID) || !validOpaqueID(r.IdempotencyKey) ||
		!validMemoryProposalETagShape(r.ExpectedETag) {
		return errors.New("invalid memory proposal decision")
	}
	return nil
}

func memoryProposalETag(proposalID string, state MemoryProposalState, payloadSHA []byte) string {
	digest := sha256.Sum256([]byte("punaro-memory-proposal-v1\x00" + proposalID + "\x00" + string(state) + "\x00" + hex.EncodeToString(payloadSHA)))
	return `"p1-` + hex.EncodeToString(digest[:]) + `"`
}

func memoryProposalETagMatches(candidate, proposalID string, state MemoryProposalState, payloadSHA []byte) bool {
	expected := memoryProposalETag(proposalID, state, payloadSHA)
	return len(candidate) == len(expected) && subtle.ConstantTimeCompare([]byte(candidate), []byte(expected)) == 1
}

func validMemoryProposalETagShape(value string) bool {
	if len(value) != len(`"p1-`)+64+1 || value[:4] != `"p1-` || value[len(value)-1] != '"' {
		return false
	}
	_, err := hex.DecodeString(value[4 : len(value)-1])
	return err == nil
}

func memoryProposalPayloadSHA(projectID string, action MemoryProposalAction, steps []MemoryProposalStepInput, evidence []MemoryProposalEvidenceInput) ([]byte, []byte) {
	body, _ := json.Marshal(struct {
		ProjectID string                        `json:"project_id"`
		Action    MemoryProposalAction          `json:"action"`
		Steps     []MemoryProposalStepInput     `json:"steps"`
		Evidence  []MemoryProposalEvidenceInput `json:"evidence,omitempty"`
	}{projectID, action, steps, evidence})
	digest := sha256.Sum256(body)
	return body, digest[:]
}

func sortedMemoryProposalItemIDs(steps []MemoryProposalStepInput, evidence []MemoryProposalEvidenceInput) []string {
	seen := make(map[string]struct{}, len(steps)+len(evidence))
	for _, step := range steps {
		if step.ItemID != "" {
			seen[step.ItemID] = struct{}{}
		}
	}
	for _, source := range evidence {
		seen[source.ItemID] = struct{}{}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
