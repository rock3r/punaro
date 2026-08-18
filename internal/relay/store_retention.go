package relay

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// MaintainDeliveries expires due pending deliveries and prunes aged terminal
// metadata in one bounded page. Callers inject now; tests must not sleep.
func (s *Store) MaintainDeliveries(now time.Time) (MaintenanceResult, error) {
	now = now.UTC().Truncate(time.Millisecond)
	cfg := s.retentionConfig()
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return MaintenanceResult{}, err
	}
	defer rollback(tx)
	expired, err := expireDueDeliveries(tx, now, cfg)
	if err != nil {
		return MaintenanceResult{}, err
	}
	pruned, err := pruneExpiredTerminals(tx, now, cfg)
	if err != nil {
		return MaintenanceResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return MaintenanceResult{}, err
	}
	s.metrics.observeTerminalTransition(ClosedReasonExpired, uint64(expired)) // #nosec G115 -- expired is bounded by MaintenanceBatch.
	s.refreshDeliveryMetrics(now)
	return MaintenanceResult{
		Expired:      expired,
		Pruned:       pruned,
		Continuation: expired == cfg.MaintenanceBatch || pruned == cfg.MaintenanceBatch,
	}, nil
}

func expireDueDeliveries(tx *sql.Tx, now time.Time, cfg RetentionConfig) (int, error) {
	cutoff := now.Add(-cfg.PendingMaxAge()).UnixMilli()
	rows, err := tx.QueryContext(context.Background(), `SELECT delivery.id, delivery.recipient_endpoint, `+sqlitePendingBodyBytes+`, message.conversation_id
		FROM deliveries AS delivery JOIN messages AS message ON message.id = delivery.message_id
		WHERE delivery.acked_at IS NULL AND message.created_at <= ?
		ORDER BY message.created_at, delivery.id
		LIMIT ?`, cutoff, cfg.MaintenanceBatch)
	if err != nil {
		return 0, fmt.Errorf("find expired deliveries: %w", err)
	}
	type candidate struct {
		id, recipient, conversationID string
		bodyBytes                     int64
	}
	var due []candidate
	for rows.Next() {
		var row candidate
		if err := rows.Scan(&row.id, &row.recipient, &row.bodyBytes, &row.conversationID); err != nil {
			_ = rows.Close()
			return 0, err
		}
		due = append(due, row)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	closed := 0
	for _, row := range due {
		result, err := tx.ExecContext(context.Background(), `UPDATE deliveries
			SET acked_at = ?, lease_machine_id = NULL, lease_token = NULL, ownership_generation = NULL, consumer_generation = NULL, lease_until = NULL
			WHERE id = ? AND acked_at IS NULL`, now.UnixMilli(), row.id)
		if err != nil {
			return 0, fmt.Errorf("expire delivery: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("expire delivery: %w", err)
		}
		if affected != 1 {
			continue
		}
		if err := recordDeliveryTerminal(tx, row.id, ClosedReasonExpired, now); err != nil {
			return 0, err
		}
		if err := releaseQuota(tx, row.recipient, row.bodyBytes); err != nil {
			return 0, err
		}
		if err := advanceRecipientCursor(tx, row.recipient, row.conversationID); err != nil {
			return 0, err
		}
		closed++
	}
	return closed, nil
}

func pruneExpiredTerminals(tx *sql.Tx, now time.Time, cfg RetentionConfig) (int, error) {
	cutoff := now.Add(-cfg.TerminalRetention()).UnixMilli()
	result, err := tx.ExecContext(context.Background(), `DELETE FROM delivery_terminals WHERE delivery_id IN (
		SELECT delivery_id FROM (
			SELECT delivery_id FROM delivery_terminals WHERE closed_at <= ? ORDER BY closed_at, delivery_id LIMIT ?
		)
	)`, cutoff, cfg.MaintenanceBatch)
	if err != nil {
		return 0, fmt.Errorf("prune delivery terminals: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("prune delivery terminals: %w", err)
	}
	return int(affected), nil
}

func recordDeliveryTerminal(tx *sql.Tx, deliveryID, reason string, now time.Time) error {
	if _, err := tx.ExecContext(context.Background(), `INSERT OR IGNORE INTO delivery_terminals(
		delivery_id, message_id, conversation_id, recipient_id, sequence, closed_reason, lease_generation, closed_at, created_at)
		SELECT delivery.id, delivery.message_id, message.conversation_id, delivery.recipient_endpoint, message.sequence, ?, COALESCE(delivery.lease_generation, 0), ?, message.created_at
		FROM deliveries AS delivery JOIN messages AS message ON message.id = delivery.message_id
		WHERE delivery.id = ?`, reason, now.UTC().Truncate(time.Millisecond).UnixMilli(), deliveryID); err != nil {
		return fmt.Errorf("record delivery terminal: %w", err)
	}
	return nil
}

// ListDeliveryTerminals returns one bounded page of retained terminal metadata.
func (s *Store) ListDeliveryTerminals(input TerminalListInput) (TerminalListPage, error) {
	limit := input.Limit
	if limit <= 0 {
		limit = DefaultTerminalListLimit
	}
	if limit > MaxTerminalListLimit {
		limit = MaxTerminalListLimit
	}
	closedAt, deliveryID, ok := DecodeTerminalListCursor(input.Cursor)
	if !ok {
		return TerminalListPage{}, fmt.Errorf("invalid terminal cursor")
	}
	var rows *sql.Rows
	var err error
	if deliveryID == "" {
		rows, err = s.db.QueryContext(context.Background(), `SELECT delivery_id, message_id, conversation_id, recipient_id, sequence, closed_reason, lease_generation, closed_at, created_at
			FROM delivery_terminals ORDER BY closed_at, delivery_id LIMIT ?`, limit+1)
	} else {
		rows, err = s.db.QueryContext(context.Background(), `SELECT delivery_id, message_id, conversation_id, recipient_id, sequence, closed_reason, lease_generation, closed_at, created_at
			FROM delivery_terminals
			WHERE closed_at > ? OR (closed_at = ? AND delivery_id > ?)
			ORDER BY closed_at, delivery_id LIMIT ?`, closedAt.UnixMilli(), closedAt.UnixMilli(), deliveryID, limit+1)
	}
	if err != nil {
		return TerminalListPage{}, fmt.Errorf("list delivery terminals: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var terminals []DeliveryTerminal
	for rows.Next() {
		var terminal DeliveryTerminal
		var closedMillis, createdMillis int64
		if err := rows.Scan(&terminal.DeliveryID, &terminal.MessageID, &terminal.ConversationID, &terminal.RecipientID, &terminal.Sequence, &terminal.ClosedReason, &terminal.LeaseGeneration, &closedMillis, &createdMillis); err != nil {
			return TerminalListPage{}, err
		}
		terminal.ClosedAt = fromMillis(closedMillis)
		terminal.CreatedAt = fromMillis(createdMillis)
		terminals = append(terminals, terminal)
	}
	if err := rows.Err(); err != nil {
		return TerminalListPage{}, err
	}
	page := TerminalListPage{Terminals: terminals}
	if len(page.Terminals) > limit {
		last := page.Terminals[limit-1]
		page.Terminals = page.Terminals[:limit]
		page.NextCursor = EncodeTerminalListCursor(last.ClosedAt, last.DeliveryID)
	}
	return page, nil
}

func (s *Store) refreshDeliveryMetrics(now time.Time) {
	s.refreshPendingMetrics()
	if s.metrics == nil {
		return
	}
	var oldest sql.NullInt64
	if err := s.db.QueryRowContext(context.Background(), `SELECT MIN(message.created_at)
		FROM deliveries AS delivery JOIN messages AS message ON message.id = delivery.message_id
		WHERE delivery.acked_at IS NULL`).Scan(&oldest); err != nil {
		return
	}
	if oldest.Valid {
		s.metrics.SetQueueAge(pendingAgeSeconds(fromMillis(oldest.Int64), now.UTC()))
	} else {
		s.metrics.SetQueueAge(0)
	}
	var retained int64
	if err := s.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM delivery_terminals`).Scan(&retained); err != nil {
		return
	}
	s.metrics.SetTerminalsRetained(unsignedPending(retained))
}
