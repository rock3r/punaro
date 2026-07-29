package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestMemoryConsolidationExecutorStagesWholePageBeforeAdvancing(t *testing.T) {
	lease := MemoryConsolidationLease{
		ScopeID: "11111111-1111-4111-8111-111111111111", TimelineID: "22222222-2222-4222-8222-222222222222", Sequence: 4,
		Holder: "33333333-3333-4333-8333-333333333333", Token: "44444444-4444-4444-8444-444444444444", Generation: 1, Until: time.Now().Add(time.Minute),
	}
	input := MemoryConsolidationInput{Lease: lease, TimelineID: lease.TimelineID, NextSequence: 5, Sources: []MemoryConsolidationSource{{
		ItemID: "55555555-5555-4555-8555-555555555555", Revision: 1, ChangeSequence: 5, Document: json.RawMessage(`{"source":true}`),
	}}}
	store := &fakeMemoryConsolidationExecutorStore{input: input}
	planner := fakeMemoryConsolidationPlanner{proposals: []MemoryConsolidationProposal{{
		Action: MemoryProposalCreate, Steps: []MemoryProposalStepInput{{Operation: MemoryProposalStepCreate, LogicalKey: "consolidation.current", Kind: "brief", Trust: "proposed", Document: json.RawMessage(`{"summary":true}`)}},
	}}}
	executor, err := NewMemoryConsolidationExecutor(store, planner, MemoryConsolidationPolicy{MaxChanges: 1, MaxProposals: 1, MaxEvidencePerProposal: 1, PassTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	result, err := executor.Execute(context.Background(), testMemoryConsolidationExecutionRequest(lease))
	if err != nil {
		t.Fatal(err)
	}
	if result.Sources != 1 || result.Staged != 1 || !result.Advanced || len(store.staged) != 1 || store.advanced != input.NextSequence {
		t.Fatalf("result=%#v staged=%#v advanced=%d", result, store.staged, store.advanced)
	}
	if got := store.staged[0]; !reflect.DeepEqual(got.Input, input) || got.Proposal.PrincipalID != "66666666-6666-4666-8666-666666666666" || got.Proposal.ProjectID != "77777777-7777-4777-8777-777777777777" || got.Proposal.IdempotencyKey == "" {
		t.Fatalf("staged request=%#v", got)
	}
}

func TestMemoryConsolidationExecutorDoesNotAdvancePartialOrInvalidPass(t *testing.T) {
	lease := MemoryConsolidationLease{
		ScopeID: "11111111-1111-4111-8111-111111111111", TimelineID: "22222222-2222-4222-8222-222222222222", Sequence: 4,
		Holder: "33333333-3333-4333-8333-333333333333", Token: "44444444-4444-4444-8444-444444444444", Generation: 1, Until: time.Now().Add(time.Minute),
	}
	input := MemoryConsolidationInput{Lease: lease, TimelineID: lease.TimelineID, NextSequence: 5, Sources: []MemoryConsolidationSource{{
		ItemID: "55555555-5555-4555-8555-555555555555", Revision: 1, ChangeSequence: 5, Document: json.RawMessage(`{"source":true}`),
	}}}
	for name, planner := range map[string]fakeMemoryConsolidationPlanner{
		"planner failure": {err: errors.New("provider unavailable")},
		"over budget":     {proposals: []MemoryConsolidationProposal{{}, {}}},
	} {
		t.Run(name, func(t *testing.T) {
			store := &fakeMemoryConsolidationExecutorStore{input: input}
			executor, err := NewMemoryConsolidationExecutor(store, planner, MemoryConsolidationPolicy{MaxChanges: 1, MaxProposals: 1, MaxEvidencePerProposal: 1, PassTimeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := executor.Execute(context.Background(), testMemoryConsolidationExecutionRequest(lease)); err == nil || store.advanced != 0 || len(store.staged) != 0 {
				t.Fatalf("err=%v staged=%#v advanced=%d", err, store.staged, store.advanced)
			}
		})
	}
}

func TestMemoryConsolidationExecutorDoesNotAdvanceAfterPartialStageFailure(t *testing.T) {
	lease := MemoryConsolidationLease{
		ScopeID: "11111111-1111-4111-8111-111111111111", TimelineID: "22222222-2222-4222-8222-222222222222", Sequence: 4,
		Holder: "33333333-3333-4333-8333-333333333333", Token: "44444444-4444-4444-8444-444444444444", Generation: 1, Until: time.Now().Add(time.Minute),
	}
	input := MemoryConsolidationInput{Lease: lease, TimelineID: lease.TimelineID, NextSequence: 5, Sources: []MemoryConsolidationSource{{
		ItemID: "55555555-5555-4555-8555-555555555555", Revision: 1, ChangeSequence: 5, Document: json.RawMessage(`{"source":true}`),
	}}}
	proposal := func(logicalKey string) MemoryConsolidationProposal {
		return MemoryConsolidationProposal{Action: MemoryProposalCreate, Steps: []MemoryProposalStepInput{{Operation: MemoryProposalStepCreate, LogicalKey: logicalKey, Kind: "brief", Trust: "proposed", Document: json.RawMessage(`{"summary":true}`)}}}
	}
	store := &fakeMemoryConsolidationExecutorStore{input: input, stageFailures: 1, stageErr: errors.New("stage unavailable")}
	executor, err := NewMemoryConsolidationExecutor(store, fakeMemoryConsolidationPlanner{proposals: []MemoryConsolidationProposal{
		proposal("consolidation.a"), proposal("consolidation.b"),
	}}, MemoryConsolidationPolicy{MaxChanges: 1, MaxProposals: 2, MaxEvidencePerProposal: 1, PassTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Execute(context.Background(), testMemoryConsolidationExecutionRequest(lease)); err == nil || len(store.staged) != 1 || store.advanced != 0 {
		t.Fatalf("err=%v staged=%#v advanced=%d", err, store.staged, store.advanced)
	}
	if result, err := executor.Execute(context.Background(), testMemoryConsolidationExecutionRequest(lease)); err != nil || len(store.staged) != 2 || !result.Advanced || store.advanced != input.NextSequence {
		t.Fatalf("replay result=%#v err=%v staged=%#v advanced=%d", result, err, store.staged, store.advanced)
	}
}

func TestMemoryConsolidationExecutorReplaysDurablePassWhenPlannerOutputChanges(t *testing.T) {
	lease := MemoryConsolidationLease{
		ScopeID: "11111111-1111-4111-8111-111111111111", TimelineID: "22222222-2222-4222-8222-222222222222", Sequence: 4,
		Holder: "33333333-3333-4333-8333-333333333333", Token: "44444444-4444-4444-8444-444444444444", Generation: 1, Until: time.Now().Add(time.Minute),
	}
	input := MemoryConsolidationInput{Lease: lease, TimelineID: lease.TimelineID, NextSequence: 5, Sources: []MemoryConsolidationSource{{
		ItemID: "55555555-5555-4555-8555-555555555555", Revision: 1, ChangeSequence: 5, Document: json.RawMessage(`{"source":true}`),
	}}}
	proposal := func(logicalKey string) MemoryConsolidationProposal {
		return MemoryConsolidationProposal{Action: MemoryProposalCreate, Steps: []MemoryProposalStepInput{{Operation: MemoryProposalStepCreate, LogicalKey: logicalKey, Kind: "brief", Trust: "proposed", Document: json.RawMessage(`{"summary":true}`)}}}
	}
	store := &fakeMemoryConsolidationExecutorStore{input: input, stageFailures: 1, stageErr: errors.New("stage unavailable")}
	planner := &changingMemoryConsolidationPlanner{outputs: [][]MemoryConsolidationProposal{{proposal("consolidation.original-a"), proposal("consolidation.original-b")}, {proposal("consolidation.replacement")}}}
	executor, err := NewMemoryConsolidationExecutor(store, planner, MemoryConsolidationPolicy{MaxChanges: 1, MaxProposals: 2, MaxEvidencePerProposal: 1, PassTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Execute(context.Background(), testMemoryConsolidationExecutionRequest(lease)); err == nil {
		t.Fatal("first pass unexpectedly completed")
	}
	store.input.NextSequence = 6
	store.input.Sources = append(store.input.Sources, MemoryConsolidationSource{ItemID: "88888888-8888-4888-8888-888888888888", Revision: 1, ChangeSequence: 6, Document: json.RawMessage(`{"new":true}`)})
	if result, err := executor.Execute(context.Background(), testMemoryConsolidationExecutionRequest(lease)); err != nil || !result.Advanced {
		t.Fatalf("replay result=%#v err=%v", result, err)
	}
	if planner.calls != 1 || len(store.staged) != 2 || store.staged[0].Proposal.Steps[0].LogicalKey != "consolidation.original-a" || store.staged[1].Proposal.Steps[0].LogicalKey != "consolidation.original-b" {
		t.Fatalf("planner calls=%d staged=%#v", planner.calls, store.staged)
	}
}

func TestMemoryConsolidationExecutorAdvancesNoProposalPageButRejectsDuplicateOutput(t *testing.T) {
	lease := MemoryConsolidationLease{
		ScopeID: "11111111-1111-4111-8111-111111111111", TimelineID: "22222222-2222-4222-8222-222222222222", Sequence: 4,
		Holder: "33333333-3333-4333-8333-333333333333", Token: "44444444-4444-4444-8444-444444444444", Generation: 1, Until: time.Now().Add(time.Minute),
	}
	input := MemoryConsolidationInput{Lease: lease, TimelineID: lease.TimelineID, NextSequence: 5, Sources: []MemoryConsolidationSource{{
		ItemID: "55555555-5555-4555-8555-555555555555", Revision: 1, ChangeSequence: 5, Document: json.RawMessage(`{"source":true}`),
	}}}
	policy := MemoryConsolidationPolicy{MaxChanges: 1, MaxProposals: 2, MaxEvidencePerProposal: 1, PassTimeout: time.Second}
	store := &fakeMemoryConsolidationExecutorStore{input: input}
	executor, err := NewMemoryConsolidationExecutor(store, fakeMemoryConsolidationPlanner{}, policy)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := executor.Execute(context.Background(), testMemoryConsolidationExecutionRequest(lease)); err != nil || result.Staged != 0 || !result.Advanced || store.advanced != input.NextSequence {
		t.Fatalf("no proposal result=%#v err=%v advanced=%d", result, err, store.advanced)
	}
	proposal := MemoryConsolidationProposal{Action: MemoryProposalCreate, Steps: []MemoryProposalStepInput{{Operation: MemoryProposalStepCreate, LogicalKey: "consolidation.duplicate", Kind: "brief", Trust: "proposed", Document: json.RawMessage(`{"summary":true}`)}}}
	store = &fakeMemoryConsolidationExecutorStore{input: input}
	executor, err = NewMemoryConsolidationExecutor(store, fakeMemoryConsolidationPlanner{proposals: []MemoryConsolidationProposal{proposal, proposal}}, policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Execute(context.Background(), testMemoryConsolidationExecutionRequest(lease)); err == nil || len(store.staged) != 0 || store.advanced != 0 {
		t.Fatalf("duplicate bodies error=%v staged=%#v advanced=%d", err, store.staged, store.advanced)
	}
}

type fakeMemoryConsolidationExecutorStore struct {
	input         MemoryConsolidationInput
	staged        []MemoryConsolidationProposalRequest
	advanced      int64
	stageFailures int
	stageErr      error
	stagedKeys    map[string]struct{}
	pass          []MemoryConsolidationProposal
	passInput     MemoryConsolidationInput
}

func (s *fakeMemoryConsolidationExecutorStore) ReadMemoryConsolidationInput(context.Context, MemoryConsolidationLease) (MemoryConsolidationInput, error) {
	return s.input, nil
}
func (s *fakeMemoryConsolidationExecutorStore) LoadMemoryConsolidationPass(_ context.Context, lease MemoryConsolidationLease, _ MemoryConsolidationExecutionRequest) (MemoryConsolidationInput, []MemoryConsolidationProposal, bool, error) {
	if s.pass == nil {
		return MemoryConsolidationInput{}, nil, false, nil
	}
	input := s.passInput
	input.Lease = lease
	return input, s.pass, true, nil
}
func (s *fakeMemoryConsolidationExecutorStore) ReserveMemoryConsolidationPass(_ context.Context, input MemoryConsolidationInput, _ MemoryConsolidationExecutionRequest, proposals []MemoryConsolidationProposal) (MemoryConsolidationInput, []MemoryConsolidationProposal, error) {
	if s.pass == nil {
		s.pass = proposals
		s.passInput = input
	}
	return s.passInput, s.pass, nil
}
func (s *fakeMemoryConsolidationExecutorStore) StageMemoryConsolidationProposal(_ context.Context, request MemoryConsolidationProposalRequest) (MemoryProposalResult, error) {
	if s.stageFailures > 0 && len(s.staged) == 1 && s.stageErr != nil {
		s.stageFailures--
		return MemoryProposalResult{}, s.stageErr
	}
	if s.stagedKeys == nil {
		s.stagedKeys = make(map[string]struct{})
	}
	if _, exists := s.stagedKeys[request.Proposal.IdempotencyKey]; exists {
		return MemoryProposalResult{ProposalID: "99999999-9999-4999-8999-999999999999"}, nil
	}
	s.stagedKeys[request.Proposal.IdempotencyKey] = struct{}{}
	s.staged = append(s.staged, request)
	return MemoryProposalResult{ProposalID: "99999999-9999-4999-8999-999999999999"}, nil
}
func (s *fakeMemoryConsolidationExecutorStore) CompleteMemoryConsolidationPass(_ context.Context, input MemoryConsolidationInput, _ MemoryConsolidationExecutionRequest) error {
	s.advanced = input.NextSequence
	s.pass = nil
	return nil
}

type fakeMemoryConsolidationPlanner struct {
	proposals []MemoryConsolidationProposal
	err       error
}

func (p fakeMemoryConsolidationPlanner) Propose(context.Context, MemoryConsolidationInput) ([]MemoryConsolidationProposal, error) {
	return p.proposals, p.err
}

type changingMemoryConsolidationPlanner struct {
	outputs [][]MemoryConsolidationProposal
	calls   int
}

func (p *changingMemoryConsolidationPlanner) Propose(context.Context, MemoryConsolidationInput) ([]MemoryConsolidationProposal, error) {
	output := p.outputs[p.calls]
	p.calls++
	return output, nil
}

func testMemoryConsolidationExecutionRequest(lease MemoryConsolidationLease) MemoryConsolidationExecutionRequest {
	return MemoryConsolidationExecutionRequest{Lease: lease, PrincipalID: "66666666-6666-4666-8666-666666666666", ProjectID: "77777777-7777-4777-8777-777777777777"}
}
