package postgres

import (
	"errors"
	"time"
)

const (
	maxMemoryConsolidationChanges     = 128
	maxMemoryConsolidationProposals   = 8
	maxMemoryConsolidationEvidence    = maxMemoryProposalEvidence
	minMemoryConsolidationPassTimeout = time.Second
	maxMemoryConsolidationPassTimeout = 30 * time.Second
)

// MemoryConsolidationPolicy bounds one proposal-only consolidation pass. Its
// output must still be staged through ProposeMemory and approved separately;
// no consolidation policy can directly mutate canonical memory.
type MemoryConsolidationPolicy struct {
	MaxChanges             int
	MaxProposals           int
	MaxEvidencePerProposal int
	PassTimeout            time.Duration
}

// Validate rejects unbounded provider input, proposal output, and execution
// time before a policy is passed to a consolidator.
func (policy MemoryConsolidationPolicy) Validate() error {
	if policy.MaxChanges < 1 || policy.MaxChanges > maxMemoryConsolidationChanges ||
		policy.MaxProposals < 1 || policy.MaxProposals > maxMemoryConsolidationProposals ||
		policy.MaxEvidencePerProposal < 1 || policy.MaxEvidencePerProposal > maxMemoryConsolidationEvidence ||
		policy.PassTimeout < minMemoryConsolidationPassTimeout || policy.PassTimeout > maxMemoryConsolidationPassTimeout {
		return errors.New("invalid memory consolidation policy")
	}
	return nil
}
