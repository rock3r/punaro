package relay

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

type pendingClose struct {
	ID              string
	MessageID       string
	ConversationID  string
	Recipient       string
	Sequence        int64
	LeaseGeneration int64
	BodyBytes       int64
	CreatedAt       int64
}

// SetRetentionPolicy replaces the in-process pending-age and terminal-retention policy.
func (s *Store) SetRetentionPolicy(cfg RetentionConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	s.retentionMu.Lock()
	s.retention = cfg
	s.retentionMu.Unlock()
	return nil
}

func (s *Store) retentionConfig() RetentionConfig {
	s.retentionMu.Lock()
	defer s.retentionMu.Unlock()
	if s.retention == (RetentionConfig{}) {
		return DefaultRetentionConfig()
	}
	return s.retention
}

// MaintainDeliveries expires pending deliveries past the max-age boundary and
// prunes retained terminal metadata, each in one bounded page of independent
// transactions so a later timeout cannot undo earlier closes.
func (s *Store) MaintainDeliveries(now time.Time) (MaintenanceResult, error) {
	cfg := s.retentionConfig()
	now = now.UTC().Truncate(time.Millisecond)
	cutoff := now.Add(-time.Duration(cfg.PendingMaxAgeSeconds) * time.Second).UnixMilli()
	var result MaintenanceResult
	defer func() {
		s.metrics.ObserveTerminals(ClosedExpired, result.Expired)
		s.refreshPendingMetrics(now)
	}()
	for i := 0; i < cfg.MaintenanceBatch; i++ {
		found, closed, err := s.expireOneDueDelivery(cutoff, now)
		if err != nil {
			return result, err
		}
		if !found {
			break
		}
		result.Scanned++
		if closed {
			result.Expired++
		}
	}
	pruneCutoff := now.Add(-time.Duration(cfg.TerminalRetentionSeconds) * time.Second).UnixMilli()
	for i := 0; i < cfg.MaintenanceBatch; i++ {
		found, err := s.pruneOneTerminal(pruneCutoff)
		if err != nil {
			return result, err
		}
		if !found {
			break
		}
		result.Pruned++
	}
	return result, nil
}

func (s *Store) expireOneDueDelivery(cutoff int64, now time.Time) (bool, bool, error) {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return false, false, err
	}
	defer rollback(tx)
	var row pendingClose
	err = tx.QueryRowContext(context.Background(), `SELECT delivery.id, delivery.recipient_endpoint, message.id, message.conversation_id, message.sequence, delivery.lease_generation, `+sqlitePendingBodyBytes+`, message.created_at
		FROM deliveries AS delivery JOIN messages AS message ON message.id = delivery.message_id
		WHERE delivery.acked_at IS NULL AND message.created_at <= ?
		ORDER BY message.created_at, delivery.id
		LIMIT 1`, cutoff).Scan(&row.ID, &row.Recipient, &row.MessageID, &row.ConversationID, &row.Sequence, &row.LeaseGeneration, &row.BodyBytes, &row.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("find expired delivery: %w", err)
	}
	closed, err := closePendingDelivery(tx, row, ClosedExpired, now)
	if err != nil {
		return true, false, err
	}
	if !closed {
		return true, false, nil
	}
	if err := tx.Commit(); err != nil {
		return true, false, err
	}
	return true, true, nil
}

func (s *Store) pruneOneTerminal(cutoff int64) (bool, error) {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return false, err
	}
	defer rollback(tx)
	var id string
	err = tx.QueryRowContext(context.Background(), `SELECT delivery_id FROM delivery_terminals
		WHERE closed_at <= ? ORDER BY closed_at, delivery_id LIMIT 1`, cutoff).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("find retained terminal: %w", err)
	}
	if _, err := tx.ExecContext(context.Background(), `DELETE FROM delivery_terminals WHERE delivery_id = ?`, id); err != nil {
		return false, fmt.Errorf("prune terminal metadata: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// ListTerminalDeliveries returns one content-free operator page of retained terminals.
func (s *Store) ListTerminalDeliveries(after string, limit int) (TerminalPage, error) {
	limit, err := boundedListLimit(limit)
	if err != nil {
		return TerminalPage{}, err
	}
	tx, err := s.db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return TerminalPage{}, err
	}
	defer rollback(tx)
	rows, err := tx.QueryContext(context.Background(), `SELECT delivery_id, message_id, conversation_id, recipient_endpoint, sequence, closed_reason, lease_generation, created_at, closed_at
		FROM delivery_terminals WHERE delivery_id > ? ORDER BY delivery_id LIMIT ?`, after, limit)
	if err != nil {
		return TerminalPage{}, fmt.Errorf("list terminal deliveries: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var page TerminalPage
	for rows.Next() {
		var record TerminalRecord
		var createdAt, closedAt int64
		if err := rows.Scan(&record.DeliveryID, &record.MessageID, &record.ConversationID, &record.RecipientID, &record.Sequence, &record.ClosedReason, &record.LeaseGeneration, &createdAt, &closedAt); err != nil {
			return TerminalPage{}, err
		}
		record.CreatedAt = fromMillis(createdAt)
		record.ClosedAt = fromMillis(closedAt)
		page.Terminals = append(page.Terminals, record)
	}
	if err := rows.Err(); err != nil {
		return TerminalPage{}, err
	}
	if err := tx.Commit(); err != nil {
		return TerminalPage{}, err
	}
	if len(page.Terminals) == limit {
		page.NextCursor = page.Terminals[len(page.Terminals)-1].DeliveryID
	}
	return page, nil
}

func closePendingDelivery(tx *sql.Tx, row pendingClose, reason string, now time.Time) (bool, error) {
	if !validClosedReason(reason) || row.ID == "" || row.Recipient == "" {
		return false, fmt.Errorf("invalid terminal close")
	}
	closedAt := now.UTC().Truncate(time.Millisecond).UnixMilli()
	result, err := tx.ExecContext(context.Background(), `UPDATE deliveries SET acked_at = ?, lease_machine_id = NULL, lease_token = NULL, ownership_generation = NULL, consumer_generation = NULL, lease_until = NULL
		WHERE id = ? AND acked_at IS NULL`, closedAt, row.ID)
	if err != nil {
		return false, fmt.Errorf("close pending delivery: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("close pending delivery: %w", err)
	}
	if affected != 1 {
		return false, nil
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT OR IGNORE INTO delivery_terminals(delivery_id, message_id, conversation_id, recipient_endpoint, sequence, closed_reason, lease_generation, created_at, closed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, row.ID, row.MessageID, row.ConversationID, row.Recipient, row.Sequence, reason, row.LeaseGeneration, row.CreatedAt, closedAt); err != nil {
		return false, fmt.Errorf("record terminal delivery: %w", err)
	}
	if err := releaseQuota(tx, row.Recipient, row.BodyBytes); err != nil {
		return false, err
	}
	if err := advanceRecipientCursor(tx, row.Recipient, row.ConversationID); err != nil {
		return false, err
	}
	return true, nil
}

func recordAckedTerminal(tx *sql.Tx, deliveryID string, now time.Time) error {
	var row pendingClose
	if err := tx.QueryRowContext(context.Background(), `SELECT delivery.id, delivery.recipient_endpoint, message.id, message.conversation_id, message.sequence, delivery.lease_generation, `+sqlitePendingBodyBytes+`, message.created_at
		FROM deliveries AS delivery JOIN messages AS message ON message.id = delivery.message_id
		WHERE delivery.id = ?`, deliveryID).Scan(&row.ID, &row.Recipient, &row.MessageID, &row.ConversationID, &row.Sequence, &row.LeaseGeneration, &row.BodyBytes, &row.CreatedAt); err != nil {
		return fmt.Errorf("read acknowledged delivery: %w", err)
	}
	closedAt := now.UTC().Truncate(time.Millisecond).UnixMilli()
	if _, err := tx.ExecContext(context.Background(), `INSERT OR IGNORE INTO delivery_terminals(delivery_id, message_id, conversation_id, recipient_endpoint, sequence, closed_reason, lease_generation, created_at, closed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, row.ID, row.MessageID, row.ConversationID, row.Recipient, row.Sequence, ClosedAcked, row.LeaseGeneration, row.CreatedAt, closedAt); err != nil {
		return fmt.Errorf("record acknowledged terminal: %w", err)
	}
	return nil
}
