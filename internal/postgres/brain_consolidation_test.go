package postgres

import (
	"encoding/json"
	"testing"
	"time"
)

func TestMemoryConsolidationLeaseRejectsUnfencedCoordinates(t *testing.T) {
	valid := MemoryConsolidationLease{ScopeID: "11111111-1111-4111-8111-111111111111", Holder: "22222222-2222-4222-8222-222222222222", Token: "33333333-3333-4333-8333-333333333333", Generation: 1, Until: time.Now().Add(time.Minute)}
	if !valid.valid() {
		t.Fatal("valid consolidation lease rejected")
	}
	valid.Token = ""
	if valid.valid() {
		t.Fatal("unfenced consolidation lease accepted")
	}
}

func TestMemoryConsolidationPolicyRejectsUnboundedOrMutatingPlans(t *testing.T) {
	valid := MemoryConsolidationPolicy{MaxChanges: 128, MaxProposals: 8, MaxEvidencePerProposal: 16, PassTimeout: 30 * time.Second}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	for name, policy := range map[string]MemoryConsolidationPolicy{
		"no changes":         {MaxProposals: 8, MaxEvidencePerProposal: 16, PassTimeout: 30 * time.Second},
		"too many changes":   {MaxChanges: 129, MaxProposals: 8, MaxEvidencePerProposal: 16, PassTimeout: 30 * time.Second},
		"no proposals":       {MaxChanges: 128, MaxEvidencePerProposal: 16, PassTimeout: 30 * time.Second},
		"too many proposals": {MaxChanges: 128, MaxProposals: 9, MaxEvidencePerProposal: 16, PassTimeout: 30 * time.Second},
		"no evidence":        {MaxChanges: 128, MaxProposals: 8, PassTimeout: 30 * time.Second},
		"too much evidence":  {MaxChanges: 128, MaxProposals: 8, MaxEvidencePerProposal: 17, PassTimeout: 30 * time.Second},
		"no deadline":        {MaxChanges: 128, MaxProposals: 8, MaxEvidencePerProposal: 16},
		"excessive deadline": {MaxChanges: 128, MaxProposals: 8, MaxEvidencePerProposal: 16, PassTimeout: 31 * time.Second},
	} {
		t.Run(name, func(t *testing.T) {
			if err := policy.Validate(); err == nil {
				t.Fatalf("invalid policy accepted: %#v", policy)
			}
		})
	}
}

func TestMemoryConsolidationInputRejectsUnfencedOrUnboundedPages(t *testing.T) {
	lease := MemoryConsolidationLease{ScopeID: "11111111-1111-4111-8111-111111111111", Holder: "22222222-2222-4222-8222-222222222222", Token: "33333333-3333-4333-8333-333333333333", Generation: 1, Until: time.Now().Add(time.Minute)}
	valid := MemoryConsolidationInput{Lease: lease, TimelineID: "44444444-4444-4444-8444-444444444444", NextSequence: 2, Sources: []MemoryConsolidationSource{{ItemID: "55555555-5555-4555-8555-555555555555", Revision: 1, ChangeSequence: 2, Document: json.RawMessage(`{"source":true}`)}}}
	if !valid.valid() {
		t.Fatal("valid consolidation input rejected")
	}
	for name, input := range map[string]MemoryConsolidationInput{
		"missing lease":    func() MemoryConsolidationInput { value := valid; value.Lease.Token = ""; return value }(),
		"foreign timeline": func() MemoryConsolidationInput { value := valid; value.TimelineID = ""; return value }(),
		"unfenced source":  func() MemoryConsolidationInput { value := valid; value.Sources[0].Revision = 0; return value }(),
		"missing document": func() MemoryConsolidationInput { value := valid; value.Sources[0].Document = nil; return value }(),
		"cursor replay": func() MemoryConsolidationInput {
			value := valid
			value.Sources[0].ChangeSequence = value.Lease.Sequence
			return value
		}(),
		"too many sources": func() MemoryConsolidationInput {
			value := valid
			value.Sources = make([]MemoryConsolidationSource, maxMemoryConsolidationChanges+1)
			return value
		}(),
	} {
		if input.valid() {
			t.Fatalf("%s input accepted", name)
		}
	}
}
