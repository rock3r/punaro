package postgres

import (
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
