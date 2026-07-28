package postgres

import (
	"testing"
	"time"
)

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
