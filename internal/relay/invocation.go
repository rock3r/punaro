package relay

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	maxInvocationAttempts = 3
	maxInvocationBackoff  = time.Minute
	// Invocation records include their idempotency and body-free audit trail.
	// Retain terminal records long enough for a client retry, then reclaim them
	// with the same transaction that accepts later invoke traffic.
	invocationTerminalRetention = 24 * time.Hour
)

var _ InvocationBackend = (*Store)(nil)

// RequestInvocation authorizes a distinct invoke capability and queues one
// content-free handoff only when the target has pending work and is offline.
func (s *Store) RequestInvocation(input InvokeInput) (Invocation, bool, error) {
	if strings.TrimSpace(input.ConversationID) == "" || !ValidMachineID(input.SenderMachineID) || !ValidEndpoint(input.FromEndpoint) || !ValidEndpoint(input.TargetEndpoint) || !ValidRequestToken(input.IdempotencyKey) {
		return Invocation{}, false, fmt.Errorf("invalid invocation request")
	}
	// Do the inexpensive authority and pending-work checks before creating the
	// optional control-plane tables. An unauthorized request must remain a
	// read-only rejection, including for cutover-compatible stores.
	if err := s.AssertEndpointOwnership(input.SenderMachineID, input.FromEndpoint, input.Now); err != nil {
		return Invocation{}, false, err
	}
	var sourceCapabilities, targetCapabilities Capability
	if err := s.db.QueryRowContext(context.Background(), `SELECT capabilities FROM memberships WHERE conversation_id=? AND endpoint=?`, input.ConversationID, input.FromEndpoint).Scan(&sourceCapabilities); errors.Is(err, sql.ErrNoRows) || sourceCapabilities&CapInvoke == 0 {
		return Invocation{}, false, ErrForbidden
	} else if err != nil {
		return Invocation{}, false, fmt.Errorf("authorize invocation sender: %w", err)
	}
	if err := s.db.QueryRowContext(context.Background(), `SELECT capabilities FROM memberships WHERE conversation_id=? AND endpoint=?`, input.ConversationID, input.TargetEndpoint).Scan(&targetCapabilities); errors.Is(err, sql.ErrNoRows) || targetCapabilities&CapReceive == 0 {
		return Invocation{}, false, ErrForbidden
	} else if err != nil {
		return Invocation{}, false, fmt.Errorf("authorize invocation target: %w", err)
	}
	requestHash := stableHash(input.ConversationID, input.FromEndpoint, input.TargetEndpoint)
	invocationSchemaExists, err := s.invocationSchemaExists()
	if err != nil {
		return Invocation{}, false, err
	}
	if invocationSchemaExists {
		// The transaction rechecks authority, prunes expired terminal records,
		// then resolves idempotency. This lets an expired key be reclaimed before
		// it can reject a later valid request as a stale hash conflict.
		return s.requestInvocationWithSchema(input, requestHash)
	}
	var pending bool
	if err := s.db.QueryRowContext(context.Background(), `SELECT EXISTS(SELECT 1 FROM deliveries AS delivery JOIN messages AS message ON message.id=delivery.message_id WHERE delivery.recipient_endpoint=? AND delivery.acked_at IS NULL AND message.conversation_id=?)`, input.TargetEndpoint, input.ConversationID).Scan(&pending); err != nil {
		return Invocation{}, false, fmt.Errorf("inspect pending invocation work: %w", err)
	}
	if !pending {
		return Invocation{}, false, ErrConflict
	}
	if err := s.ensureInvocationSchema(); err != nil {
		return Invocation{}, false, err
	}
	return s.requestInvocationWithSchema(input, requestHash)
}

func (s *Store) requestInvocationWithSchema(input InvokeInput, requestHash string) (Invocation, bool, error) {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return Invocation{}, false, err
	}
	defer rollback(tx)
	var sourceCapabilities, targetCapabilities Capability
	var pending bool
	if err := endpointOwnedBy(tx, input.FromEndpoint, input.SenderMachineID, input.Now); err != nil {
		return Invocation{}, false, err
	}
	err = tx.QueryRowContext(context.Background(), `SELECT capabilities FROM memberships WHERE conversation_id=? AND endpoint=?`, input.ConversationID, input.FromEndpoint).Scan(&sourceCapabilities)
	if errors.Is(err, sql.ErrNoRows) || sourceCapabilities&CapInvoke == 0 {
		return Invocation{}, false, ErrForbidden
	}
	if err != nil {
		return Invocation{}, false, fmt.Errorf("authorize invocation sender: %w", err)
	}
	if err := pruneExpiredTerminalInvocations(tx, input.Now); err != nil {
		return Invocation{}, false, err
	}
	var existingID, existingHash string
	err = tx.QueryRowContext(context.Background(), `SELECT invocation_id,request_hash FROM invocation_idempotency WHERE machine_id=? AND key=?`, input.SenderMachineID, input.IdempotencyKey).Scan(&existingID, &existingHash)
	if err == nil {
		if existingHash != requestHash {
			return Invocation{}, false, ErrConflict
		}
		invocation, err := invocationByID(tx, existingID)
		if err != nil {
			return Invocation{}, false, err
		}
		if err := tx.Commit(); err != nil {
			return Invocation{}, false, err
		}
		return invocationForCaller(invocation, input), true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Invocation{}, false, fmt.Errorf("read invocation idempotency: %w", err)
	}
	err = tx.QueryRowContext(context.Background(), `SELECT capabilities FROM memberships WHERE conversation_id=? AND endpoint=?`, input.ConversationID, input.TargetEndpoint).Scan(&targetCapabilities)
	if errors.Is(err, sql.ErrNoRows) || targetCapabilities&CapReceive == 0 {
		return Invocation{}, false, ErrForbidden
	}
	if err != nil {
		return Invocation{}, false, fmt.Errorf("authorize invocation target: %w", err)
	}
	var targetMachine string
	var targetLeaseUntil int64
	var targetOwnershipGeneration int64
	err = tx.QueryRowContext(context.Background(), `SELECT machine_id,lease_until,ownership_generation FROM endpoints WHERE endpoint=?`, input.TargetEndpoint).Scan(&targetMachine, &targetLeaseUntil, &targetOwnershipGeneration)
	if errors.Is(err, sql.ErrNoRows) {
		return Invocation{}, false, ErrForbidden
	}
	if err != nil {
		return Invocation{}, false, fmt.Errorf("resolve invocation target: %w", err)
	}
	if err := tx.QueryRowContext(context.Background(), `SELECT EXISTS(SELECT 1 FROM deliveries AS delivery JOIN messages AS message ON message.id=delivery.message_id WHERE delivery.recipient_endpoint=? AND delivery.acked_at IS NULL AND message.conversation_id=?)`, input.TargetEndpoint, input.ConversationID).Scan(&pending); err != nil {
		return Invocation{}, false, fmt.Errorf("inspect pending invocation work: %w", err)
	}
	if !pending {
		return Invocation{}, false, ErrConflict
	}
	if targetLeaseUntil > input.Now.UnixMilli() {
		// Persist this no-op result in the caller's idempotency domain. Otherwise
		// retrying the same key after the endpoint detached could unexpectedly
		// become a new start request.
		invocation := Invocation{ID: uuid.NewString(), ConversationID: input.ConversationID, TargetEndpoint: input.TargetEndpoint, TargetMachineID: targetMachine, Fence: uuid.NewString(), Status: InvocationAlreadyRunning}
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO invocations(id,conversation_id,from_endpoint,target_endpoint,target_machine_id,target_ownership_generation,fence,status,not_before,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, invocation.ID, invocation.ConversationID, input.FromEndpoint, invocation.TargetEndpoint, invocation.TargetMachineID, targetOwnershipGeneration, invocation.Fence, invocation.Status, input.Now.UnixMilli(), input.Now.UnixMilli()); err != nil {
			return Invocation{}, false, fmt.Errorf("record already-running invocation: %w", err)
		}
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO invocation_idempotency(machine_id,key,request_hash,invocation_id) VALUES(?,?,?,?)`, input.SenderMachineID, input.IdempotencyKey, requestHash, invocation.ID); err != nil {
			return Invocation{}, false, fmt.Errorf("record invocation idempotency: %w", err)
		}
		if err := recordInvocationAudit(tx, invocation.ID, "already_running", input.Now); err != nil {
			return Invocation{}, false, err
		}
		if err := tx.Commit(); err != nil {
			return Invocation{}, false, err
		}
		return invocation, false, nil
	}
	// Different authorized callers can legitimately race to wake the same
	// offline role. They must converge on one durable fence, rather than start
	// separate runtime processes merely because their idempotency domains differ.
	var pendingID string
	err = tx.QueryRowContext(context.Background(), `SELECT id FROM invocations WHERE target_endpoint=? AND target_machine_id=? AND target_ownership_generation=? AND (status=? OR (status=? AND not_before>?)) ORDER BY created_at,id LIMIT 1`, input.TargetEndpoint, targetMachine, targetOwnershipGeneration, InvocationPending, InvocationSucceeded, input.Now.UnixMilli()).Scan(&pendingID)
	if err == nil {
		invocation, err := invocationByID(tx, pendingID)
		if err != nil {
			return Invocation{}, false, err
		}
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO invocation_idempotency(machine_id,key,request_hash,invocation_id) VALUES(?,?,?,?)`, input.SenderMachineID, input.IdempotencyKey, requestHash, invocation.ID); err != nil {
			return Invocation{}, false, fmt.Errorf("record coalesced invocation idempotency: %w", err)
		}
		if err := recordInvocationAudit(tx, invocation.ID, "coalesced", input.Now); err != nil {
			return Invocation{}, false, err
		}
		if err := tx.Commit(); err != nil {
			return Invocation{}, false, err
		}
		return invocationForCaller(invocation, input), true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Invocation{}, false, fmt.Errorf("find pending invocation: %w", err)
	}
	invocation := Invocation{ID: uuid.NewString(), ConversationID: input.ConversationID, TargetEndpoint: input.TargetEndpoint, TargetMachineID: targetMachine, Fence: uuid.NewString(), Status: InvocationPending}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO invocations(id,conversation_id,from_endpoint,target_endpoint,target_machine_id,target_ownership_generation,fence,status,not_before,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, invocation.ID, invocation.ConversationID, input.FromEndpoint, invocation.TargetEndpoint, invocation.TargetMachineID, targetOwnershipGeneration, invocation.Fence, invocation.Status, input.Now.UnixMilli(), input.Now.UnixMilli()); err != nil {
		return Invocation{}, false, fmt.Errorf("queue invocation: %w", err)
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO invocation_idempotency(machine_id,key,request_hash,invocation_id) VALUES(?,?,?,?)`, input.SenderMachineID, input.IdempotencyKey, requestHash, invocation.ID); err != nil {
		return Invocation{}, false, fmt.Errorf("record invocation idempotency: %w", err)
	}
	if err := recordInvocationAudit(tx, invocation.ID, "requested", input.Now); err != nil {
		return Invocation{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return Invocation{}, false, err
	}
	return invocation, false, nil
}

func pruneExpiredTerminalInvocations(tx *sql.Tx, now time.Time) error {
	if _, err := tx.ExecContext(context.Background(), `DELETE FROM invocations WHERE status IN (?,?,?) AND created_at<?`, InvocationAlreadyRunning, InvocationSucceeded, InvocationFailed, now.Add(-invocationTerminalRetention).UnixMilli()); err != nil {
		return fmt.Errorf("prune terminal invocations: %w", err)
	}
	return nil
}

func invocationForCaller(invocation Invocation, input InvokeInput) Invocation {
	if invocation.ConversationID == input.ConversationID {
		return invocation
	}
	// A shared endpoint-level start fence is deliberately opaque to callers in
	// other conversations. They learn only that their request converged on a
	// pending start, not the original conversation, machine, ID, or fence.
	return Invocation{ConversationID: input.ConversationID, TargetEndpoint: input.TargetEndpoint, Status: invocation.Status}
}

// LeaseInvocations gives an enrolled adapter bounded content-free start work.
// The stable fence survives a lost response and every later lease generation.
func (s *Store) LeaseInvocations(machineID, consumerID string, now time.Time, ttl time.Duration, limit int) ([]Invocation, error) {
	exists, err := s.invocationSchemaExists()
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}
	if err := s.ensureInvocationSchema(); err != nil {
		return nil, err
	}
	if !ValidMachineID(machineID) || !ValidRequestToken(consumerID) || ttl <= 0 || limit < 1 || limit > 100 {
		return nil, fmt.Errorf("invalid invocation lease request")
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	// An invocation carries the endpoint ownership generation observed at
	// authorization. A later detach or reassignment must not grant its old
	// machine a process-start lease, even if the endpoint is offline again.
	staleOwnerRows, err := tx.QueryContext(context.Background(), `SELECT invocation.id FROM invocations AS invocation
		LEFT JOIN endpoints AS endpoint ON endpoint.endpoint=invocation.target_endpoint
		WHERE invocation.target_machine_id=? AND invocation.status=? AND (invocation.lease_machine_id IS NULL OR invocation.lease_until<=?)
		AND (endpoint.endpoint IS NULL OR endpoint.machine_id<>invocation.target_machine_id OR (endpoint.ownership_generation<>invocation.target_ownership_generation AND endpoint.lease_until<=?))`, machineID, InvocationPending, now.UnixMilli(), now.UnixMilli())
	if err != nil {
		return nil, fmt.Errorf("find invocation ownership changes: %w", err)
	}
	var staleOwnerIDs []string
	for staleOwnerRows.Next() {
		var invocationID string
		if err := staleOwnerRows.Scan(&invocationID); err != nil {
			_ = staleOwnerRows.Close()
			return nil, fmt.Errorf("read invocation ownership change: %w", err)
		}
		staleOwnerIDs = append(staleOwnerIDs, invocationID)
	}
	if err := staleOwnerRows.Close(); err != nil || staleOwnerRows.Err() != nil {
		return nil, fmt.Errorf("find invocation ownership changes: %w", err)
	}
	for _, invocationID := range staleOwnerIDs {
		if _, err := tx.ExecContext(context.Background(), `UPDATE invocations SET status=?,lease_machine_id=NULL,lease_consumer_id=NULL,lease_token=NULL,lease_until=NULL WHERE id=?`, InvocationFailed, invocationID); err != nil {
			return nil, fmt.Errorf("fail stale invocation owner: %w", err)
		}
		if err := recordInvocationAudit(tx, invocationID, "failed", now); err != nil {
			return nil, err
		}
	}
	staleRows, err := tx.QueryContext(context.Background(), `SELECT invocation.id FROM invocations AS invocation
		WHERE invocation.target_machine_id=? AND invocation.status=? AND (invocation.lease_machine_id IS NULL OR invocation.lease_until<=?)
		AND NOT EXISTS (SELECT 1 FROM deliveries WHERE recipient_endpoint=invocation.target_endpoint AND acked_at IS NULL)`, machineID, InvocationPending, now.UnixMilli())
	if err != nil {
		return nil, fmt.Errorf("find stale invocations: %w", err)
	}
	var staleIDs []string
	for staleRows.Next() {
		var invocationID string
		if err := staleRows.Scan(&invocationID); err != nil {
			_ = staleRows.Close()
			return nil, fmt.Errorf("read stale invocation: %w", err)
		}
		staleIDs = append(staleIDs, invocationID)
	}
	if err := staleRows.Close(); err != nil || staleRows.Err() != nil {
		return nil, fmt.Errorf("find stale invocations: %w", err)
	}
	for _, invocationID := range staleIDs {
		if _, err := tx.ExecContext(context.Background(), `UPDATE invocations SET status=? WHERE id=?`, InvocationFailed, invocationID); err != nil {
			return nil, fmt.Errorf("fail stale invocation: %w", err)
		}
		if err := recordInvocationAudit(tx, invocationID, "failed", now); err != nil {
			return nil, err
		}
	}
	// A role may have attached after its caller observed it offline. Terminally
	// consume that old request before leasing anything: attachment is the
	// authoritative proof that starting another copy is no longer allowed.
	onlineRows, err := tx.QueryContext(context.Background(), `SELECT invocation.id FROM invocations AS invocation
		JOIN endpoints AS endpoint ON endpoint.endpoint=invocation.target_endpoint
		WHERE invocation.target_machine_id=? AND invocation.status=? AND (invocation.lease_machine_id IS NULL OR invocation.lease_until<=?)
		AND endpoint.machine_id=invocation.target_machine_id AND endpoint.lease_until>?`, machineID, InvocationPending, now.UnixMilli(), now.UnixMilli())
	if err != nil {
		return nil, fmt.Errorf("find online invocation targets: %w", err)
	}
	var onlineIDs []string
	for onlineRows.Next() {
		var invocationID string
		if err := onlineRows.Scan(&invocationID); err != nil {
			_ = onlineRows.Close()
			return nil, fmt.Errorf("read online invocation target: %w", err)
		}
		onlineIDs = append(onlineIDs, invocationID)
	}
	if err := onlineRows.Close(); err != nil {
		return nil, fmt.Errorf("close online invocation targets: %w", err)
	}
	if err := onlineRows.Err(); err != nil {
		return nil, fmt.Errorf("find online invocation targets: %w", err)
	}
	for _, invocationID := range onlineIDs {
		if _, err := tx.ExecContext(context.Background(), `UPDATE invocations SET status=?,lease_machine_id=NULL,lease_consumer_id=NULL,lease_token=NULL,lease_until=NULL WHERE id=?`, InvocationAlreadyRunning, invocationID); err != nil {
			return nil, fmt.Errorf("record online invocation target: %w", err)
		}
		if err := recordInvocationAudit(tx, invocationID, "already_running", now); err != nil {
			return nil, err
		}
	}
	rows, err := tx.QueryContext(context.Background(), `SELECT invocation.id,invocation.conversation_id,invocation.target_endpoint,invocation.target_machine_id,invocation.fence,invocation.lease_generation,invocation.attempts,invocation.lease_until FROM invocations AS invocation
		JOIN endpoints AS endpoint ON endpoint.endpoint=invocation.target_endpoint AND endpoint.machine_id=invocation.target_machine_id
		WHERE invocation.target_machine_id=? AND invocation.status=? AND invocation.not_before<=? AND (invocation.lease_until IS NULL OR invocation.lease_until<=? OR (invocation.lease_machine_id=? AND invocation.lease_consumer_id=?))
		AND (endpoint.ownership_generation=invocation.target_ownership_generation OR (invocation.lease_machine_id=? AND invocation.lease_consumer_id=? AND invocation.lease_until>?))
		ORDER BY created_at,id LIMIT ?`, machineID, InvocationPending, now.UnixMilli(), now.UnixMilli(), machineID, consumerID, machineID, consumerID, now.UnixMilli(), limit)
	if err != nil {
		return nil, fmt.Errorf("find invocations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var invocations []Invocation
	for rows.Next() {
		var invocation Invocation
		var attempts int
		var priorLeaseUntil sql.NullInt64
		if err := rows.Scan(&invocation.ID, &invocation.ConversationID, &invocation.TargetEndpoint, &invocation.TargetMachineID, &invocation.Fence, &invocation.LeaseGeneration, &attempts, &priorLeaseUntil); err != nil {
			return nil, fmt.Errorf("read invocation: %w", err)
		}
		if !priorLeaseUntil.Valid || priorLeaseUntil.Int64 <= now.UnixMilli() {
			// A fresh lease, and a lease recovered after an adapter crash, each
			// consume one bounded runtime-start attempt. Releasing a still-live
			// lease to the same adapter does not.
			if attempts >= maxInvocationAttempts {
				if _, err := tx.ExecContext(context.Background(), `UPDATE invocations SET status=?,lease_machine_id=NULL,lease_consumer_id=NULL,lease_token=NULL,lease_until=NULL WHERE id=?`, InvocationFailed, invocation.ID); err != nil {
					return nil, fmt.Errorf("fail exhausted invocation: %w", err)
				}
				if err := recordInvocationAudit(tx, invocation.ID, "failed", now); err != nil {
					return nil, err
				}
				continue
			}
			attempts++
		}
		token, err := randomToken()
		if err != nil {
			return nil, err
		}
		invocation.Status = InvocationPending
		invocation.LeaseGeneration++
		invocation.LeaseToken = token
		invocation.LeaseUntil = now.Add(ttl).UTC()
		if _, err := tx.ExecContext(context.Background(), `UPDATE invocations SET attempts=?,lease_machine_id=?,lease_consumer_id=?,lease_token=?,lease_generation=?,lease_until=? WHERE id=?`, attempts, machineID, consumerID, token, invocation.LeaseGeneration, invocation.LeaseUntil.UnixMilli(), invocation.ID); err != nil {
			return nil, fmt.Errorf("lease invocation: %w", err)
		}
		if err := recordInvocationAudit(tx, invocation.ID, "leased", now); err != nil {
			return nil, err
		}
		invocations = append(invocations, invocation)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return invocations, nil
}

// ReportInvocation accepts a durable local handoff or returns it to the queue
// with bounded retry. A stale or foreign lease cannot change the result.
func (s *Store) ReportInvocation(machineID, invocationID, token string, generation int64, accepted bool, now time.Time) error {
	if !ValidMachineID(machineID) || strings.TrimSpace(invocationID) == "" || !ValidRequestToken(token) || generation < 1 {
		return ErrForbidden
	}
	exists, err := s.invocationSchemaExists()
	if err != nil {
		return err
	}
	if !exists {
		return ErrForbidden
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer rollback(tx)
	var status InvocationStatus
	var leaseMachine, leaseToken sql.NullString
	var leaseGeneration int64
	var leaseUntil sql.NullInt64
	var attempts int
	err = tx.QueryRowContext(context.Background(), `SELECT status,lease_machine_id,lease_token,lease_generation,lease_until,attempts FROM invocations WHERE id=?`, invocationID).Scan(&status, &leaseMachine, &leaseToken, &leaseGeneration, &leaseUntil, &attempts)
	if errors.Is(err, sql.ErrNoRows) || status != InvocationPending || !leaseMachine.Valid || leaseMachine.String != machineID || !leaseToken.Valid || leaseToken.String != token || leaseGeneration != generation || !leaseUntil.Valid || leaseUntil.Int64 <= now.UnixMilli() {
		return ErrForbidden
	}
	if err != nil {
		return fmt.Errorf("read invocation lease: %w", err)
	}
	if accepted {
		if _, err := tx.ExecContext(context.Background(), `UPDATE invocations SET status=?,not_before=?,lease_machine_id=NULL,lease_consumer_id=NULL,lease_token=NULL,lease_until=NULL WHERE id=?`, InvocationSucceeded, now.Add(maxInvocationBackoff).UnixMilli(), invocationID); err != nil {
			return fmt.Errorf("accept invocation: %w", err)
		}
		if err := recordInvocationAudit(tx, invocationID, "accepted", now); err != nil {
			return err
		}
	} else {
		status := InvocationPending
		action := "retry"
		if attempts >= maxInvocationAttempts {
			status, action = InvocationFailed, "failed"
		}
		notBefore := now
		if status == InvocationPending {
			notBefore = now.Add(invocationBackoff(attempts))
		}
		if _, err := tx.ExecContext(context.Background(), `UPDATE invocations SET status=?,attempts=?,not_before=?,lease_machine_id=NULL,lease_consumer_id=NULL,lease_token=NULL,lease_until=NULL WHERE id=?`, status, attempts, notBefore.UnixMilli(), invocationID); err != nil {
			return fmt.Errorf("retry invocation: %w", err)
		}
		if err := recordInvocationAudit(tx, invocationID, action, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func invocationBackoff(attempt int) time.Duration {
	// Leave a full poll interval for a transient local runtime failure before
	// a second start attempt. The final terminal failure occurs after three
	// leases, not by silently dropping the durable request.
	backoff := 2 * time.Second << (attempt - 1)
	if backoff > maxInvocationBackoff {
		return maxInvocationBackoff
	}
	return backoff
}

// InvocationAudit returns body-free audit history for operational inspection.
func (s *Store) InvocationAudit(invocationID string) ([]InvocationAuditEvent, error) {
	if err := s.ensureInvocationSchema(); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(context.Background(), `SELECT action,created_at FROM invocation_audit WHERE invocation_id=? ORDER BY ordinal`, invocationID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var events []InvocationAuditEvent
	for rows.Next() {
		var event InvocationAuditEvent
		var createdAt int64
		if err := rows.Scan(&event.Action, &createdAt); err != nil {
			return nil, err
		}
		event.CreatedAt = fromMillis(createdAt)
		events = append(events, event)
	}
	return events, rows.Err()
}

func invocationByID(tx *sql.Tx, id string) (Invocation, error) {
	var invocation Invocation
	err := tx.QueryRowContext(context.Background(), `SELECT id,conversation_id,target_endpoint,target_machine_id,fence,status FROM invocations WHERE id=?`, id).Scan(&invocation.ID, &invocation.ConversationID, &invocation.TargetEndpoint, &invocation.TargetMachineID, &invocation.Fence, &invocation.Status)
	if errors.Is(err, sql.ErrNoRows) {
		return Invocation{}, ErrForbidden
	}
	if err != nil {
		return Invocation{}, fmt.Errorf("read invocation: %w", err)
	}
	return invocation, nil
}

func recordInvocationAudit(tx *sql.Tx, invocationID, action string, now time.Time) error {
	var ordinal int
	if err := tx.QueryRowContext(context.Background(), `SELECT COALESCE(MAX(ordinal),0)+1 FROM invocation_audit WHERE invocation_id=?`, invocationID).Scan(&ordinal); err != nil {
		return fmt.Errorf("allocate invocation audit ordinal: %w", err)
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO invocation_audit(invocation_id,ordinal,action,created_at) VALUES(?,?,?,?)`, invocationID, ordinal, action, now.UnixMilli()); err != nil {
		return fmt.Errorf("record invocation audit: %w", err)
	}
	return nil
}

// ensureInvocationSchema is lazy because the published SQLite-to-PostgreSQL
// cutover snapshot has not yet gained invocation parity. Once invoke is used,
// that cutover intentionally refuses the unknown tables rather than silently
// dropping control-plane state; a future paired migration must carry it.
func (s *Store) ensureInvocationSchema() error {
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS invocations (
			id TEXT PRIMARY KEY,
			conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
			from_endpoint TEXT NOT NULL,
			target_endpoint TEXT NOT NULL,
			target_machine_id TEXT NOT NULL,
			fence TEXT NOT NULL UNIQUE,
			status TEXT NOT NULL CHECK(status IN ('pending', 'already_running', 'succeeded', 'failed')),
			attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
			not_before INTEGER NOT NULL,
			lease_machine_id TEXT,
			lease_consumer_id TEXT,
			lease_token TEXT,
			lease_generation INTEGER NOT NULL DEFAULT 0,
			target_ownership_generation INTEGER NOT NULL DEFAULT 0,
			lease_until INTEGER,
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS invocation_idempotency (
			machine_id TEXT NOT NULL,
			key TEXT NOT NULL,
			request_hash TEXT NOT NULL,
			invocation_id TEXT NOT NULL REFERENCES invocations(id) ON DELETE CASCADE,
			PRIMARY KEY(machine_id, key)
		)`,
		`CREATE TABLE IF NOT EXISTS invocation_audit (
			invocation_id TEXT NOT NULL REFERENCES invocations(id) ON DELETE CASCADE,
			ordinal INTEGER NOT NULL,
			action TEXT NOT NULL CHECK(action IN ('requested', 'coalesced', 'already_running', 'leased', 'retry', 'accepted', 'failed')),
			created_at INTEGER NOT NULL,
			PRIMARY KEY(invocation_id, ordinal)
		)`,
		`CREATE INDEX IF NOT EXISTS invocations_machine_pending ON invocations(target_machine_id, status, not_before, lease_until)`,
		`CREATE INDEX IF NOT EXISTS invocations_terminal_retention ON invocations(status, created_at)`,
	} {
		if _, err := s.db.ExecContext(context.Background(), statement); err != nil {
			return fmt.Errorf("initialize invocation state: %w", err)
		}
	}
	if err := ensureSQLiteColumn(context.Background(), s.db, "invocations", "target_ownership_generation", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	return nil
}

func (s *Store) invocationSchemaExists() (bool, error) {
	var exists bool
	if err := s.db.QueryRowContext(context.Background(), `SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='invocations')`).Scan(&exists); err != nil {
		return false, fmt.Errorf("inspect invocation state: %w", err)
	}
	return exists, nil
}
