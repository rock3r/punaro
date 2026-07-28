package postgres

import (
	"context"
	"database/sql"
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

// MemoryConsolidationLease fences one scope-local consolidation pass. The
// durable store will advance Generation whenever this lease is reclaimed.
type MemoryConsolidationLease struct {
	ScopeID    string
	Holder     string
	Token      string
	Generation int64
	Until      time.Time
}

func (lease MemoryConsolidationLease) valid() bool {
	return validOpaqueID(lease.ScopeID) && validOpaqueID(lease.Holder) &&
		validOpaqueID(lease.Token) && lease.Generation > 0 && !lease.Until.IsZero()
}

// ClaimMemoryConsolidationCheckpoint claims one expired-or-unleased scope fence.
func (d *Database) ClaimMemoryConsolidationCheckpoint(ctx context.Context, scopeID, holder string, leaseDuration time.Duration) (MemoryConsolidationLease, bool, error) {
	if !validOpaqueID(scopeID) || !validOpaqueID(holder) || leaseDuration < memoryEmbeddingMinLease || leaseDuration > memoryEmbeddingMaxLease {
		return MemoryConsolidationLease{}, false, errors.New("invalid consolidation claim")
	}
	var lease MemoryConsolidationLease
	err := d.db.QueryRowContext(ctx, `SELECT scope_id::text,lease_holder::text,lease_token::text,lease_generation,lease_until FROM brain.claim_memory_consolidation_checkpoint($1,$2,$3)`, scopeID, holder, leaseDuration.Microseconds()).Scan(&lease.ScopeID, &lease.Holder, &lease.Token, &lease.Generation, &lease.Until)
	if errors.Is(err, sql.ErrNoRows) {
		return MemoryConsolidationLease{}, false, nil
	}
	if err != nil || !lease.valid() {
		return MemoryConsolidationLease{}, false, errors.New("consolidation checkpoint could not be claimed")
	}
	return lease, true, nil
}

func (d *Database) AdvanceMemoryConsolidationCheckpoint(ctx context.Context, lease MemoryConsolidationLease, timelineID string, sequence int64) error {
	if !lease.valid() || !validOpaqueID(timelineID) || sequence < 0 {
		return errors.New("invalid consolidation checkpoint")
	}
	var changed bool
	err := d.db.QueryRowContext(ctx, `SELECT brain.advance_memory_consolidation_checkpoint($1,$2,$3,$4,$5)`, lease.ScopeID, lease.Token, lease.Generation, timelineID, sequence).Scan(&changed)
	if err != nil {
		return errors.New("consolidation checkpoint could not advance")
	}
	if !changed {
		return ErrStaleEmbeddingLease
	}
	return nil
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
