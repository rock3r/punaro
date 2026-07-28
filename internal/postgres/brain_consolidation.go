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
	TimelineID string
	Sequence   int64
	Holder     string
	Token      string
	Generation int64
	Until      time.Time
}

// MemoryConsolidationSource identifies one exact revision selected under a
// live consolidation lease. Its document is intentionally deferred until a
// later provider boundary; this selection record cannot itself create output.
type MemoryConsolidationSource struct {
	ItemID         string
	Revision       int64
	ChangeSequence int64
}

// MemoryConsolidationInput is the bounded, lease-fenced source coordinate
// page consumed by a later proposal-only consolidator.
type MemoryConsolidationInput struct {
	Lease        MemoryConsolidationLease
	TimelineID   string
	NextSequence int64
	Sources      []MemoryConsolidationSource
}

// ErrStaleMemoryConsolidationLease reports a failed consolidation fence.
var ErrStaleMemoryConsolidationLease = errors.New("consolidation lease is stale")

func (lease MemoryConsolidationLease) valid() bool {
	return validOpaqueID(lease.ScopeID) && validOpaqueID(lease.Holder) &&
		validOpaqueID(lease.Token) && lease.Generation > 0 && !lease.Until.IsZero()
}

func (input MemoryConsolidationInput) valid() bool {
	if !input.Lease.valid() || !validOpaqueID(input.TimelineID) || input.NextSequence < input.Lease.Sequence || len(input.Sources) > maxMemoryConsolidationChanges {
		return false
	}
	for _, source := range input.Sources {
		if !validOpaqueID(source.ItemID) || source.Revision < 1 || source.ChangeSequence <= input.Lease.Sequence || source.ChangeSequence > input.NextSequence {
			return false
		}
	}
	return true
}

// ReadMemoryConsolidationInput returns at most one bounded page of exact
// source-revision coordinates after a live lease cursor. It is deliberately
// read-only: advancing the cursor and staging proposals remain separate,
// independently fenced operations.
func (d *Database) ReadMemoryConsolidationInput(ctx context.Context, lease MemoryConsolidationLease) (MemoryConsolidationInput, error) {
	if !lease.valid() {
		return MemoryConsolidationInput{}, errors.New("invalid consolidation lease")
	}
	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return MemoryConsolidationInput{}, errors.New("consolidation input snapshot cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	var timelineID string
	var live bool
	err = tx.QueryRowContext(ctx, `SELECT state.timeline_id::text,
  EXISTS (SELECT 1 FROM brain.memory_consolidation_checkpoints AS checkpoint
          WHERE checkpoint.scope_id=$1 AND checkpoint.lease_token=$2 AND checkpoint.lease_generation=$3
            AND checkpoint.lease_until > statement_timestamp())
FROM jobs.server_state AS state WHERE state.singleton`, lease.ScopeID, lease.Token, lease.Generation).Scan(&timelineID, &live)
	if err != nil {
		return MemoryConsolidationInput{}, errors.New("consolidation fence is unavailable")
	}
	if !live || timelineID != lease.TimelineID {
		return MemoryConsolidationInput{}, ErrStaleMemoryConsolidationLease
	}
	rows, err := tx.QueryContext(ctx, `SELECT item_id::text,revision,change_sequence
FROM brain.memory_changes
WHERE scope_id=$1 AND timeline_id=$2 AND change_sequence>$3
ORDER BY change_sequence,item_id LIMIT $4`, lease.ScopeID, lease.TimelineID, lease.Sequence, maxMemoryConsolidationChanges)
	if err != nil {
		return MemoryConsolidationInput{}, errors.New("consolidation sources are unavailable")
	}
	defer func() { _ = rows.Close() }()
	input := MemoryConsolidationInput{Lease: lease, TimelineID: timelineID, NextSequence: lease.Sequence, Sources: make([]MemoryConsolidationSource, 0, maxMemoryConsolidationChanges)}
	for rows.Next() {
		var source MemoryConsolidationSource
		if err := rows.Scan(&source.ItemID, &source.Revision, &source.ChangeSequence); err != nil {
			return MemoryConsolidationInput{}, errors.New("consolidation source is malformed")
		}
		input.Sources = append(input.Sources, source)
		input.NextSequence = source.ChangeSequence
	}
	if err := rows.Err(); err != nil || !input.valid() {
		return MemoryConsolidationInput{}, errors.New("consolidation sources are unavailable")
	}
	if err := tx.Commit(); err != nil {
		return MemoryConsolidationInput{}, errors.New("consolidation input snapshot cannot commit")
	}
	return input, nil
}

// ClaimMemoryConsolidationCheckpoint claims one expired-or-unleased scope fence.
func (d *Database) ClaimMemoryConsolidationCheckpoint(ctx context.Context, scopeID, holder string, leaseDuration time.Duration) (MemoryConsolidationLease, bool, error) {
	if !validOpaqueID(scopeID) || !validOpaqueID(holder) || leaseDuration < memoryEmbeddingMinLease || leaseDuration > memoryEmbeddingMaxLease {
		return MemoryConsolidationLease{}, false, errors.New("invalid consolidation claim")
	}
	var lease MemoryConsolidationLease
	err := d.db.QueryRowContext(ctx, `SELECT scope_id::text,timeline_id::text,change_sequence,lease_holder::text,lease_token::text,lease_generation,lease_until FROM brain.claim_memory_consolidation_checkpoint($1,$2,$3)`, scopeID, holder, leaseDuration.Microseconds()).Scan(&lease.ScopeID, &lease.TimelineID, &lease.Sequence, &lease.Holder, &lease.Token, &lease.Generation, &lease.Until)
	if errors.Is(err, sql.ErrNoRows) {
		return MemoryConsolidationLease{}, false, nil
	}
	if err != nil || !lease.valid() {
		return MemoryConsolidationLease{}, false, errors.New("consolidation checkpoint could not be claimed")
	}
	return lease, true, nil
}

// AdvanceMemoryConsolidationCheckpoint atomically advances and releases one lease.
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
		return ErrStaleMemoryConsolidationLease
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
