package relay

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// SetRetentionPolicy replaces the in-process pending-expiry and terminal-retention policy.
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

// ExpirePendingDeliveries moves a bounded page of aged pending deliveries to
// terminal expired state, releasing pending capacity once per delivery.
func (s *Store) ExpirePendingDeliveries(now time.Time) (MaintenanceResult, error) {
	cfg := s.retentionConfig()
	now = now.UTC().Truncate(time.Millisecond)
	cutoff := now.Add(-cfg.PendingMaxAge).UnixMilli()
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return MaintenanceResult{}, err
	}
	defer rollback(tx)
	rows, err := tx.QueryContext(context.Background(), `SELECT delivery.id, delivery.recipient_endpoint, message.conversation_id, `+sqlitePendingBodyBytes+`
		FROM deliveries AS delivery JOIN messages AS message ON message.id = delivery.message_id
		WHERE delivery.acked_at IS NULL AND message.created_at <= ?
		ORDER BY message.created_at, delivery.id
		LIMIT ?`, cutoff, cfg.MaintenanceBatch)
	if err != nil {
		return MaintenanceResult{}, fmt.Errorf("find expired deliveries: %w", err)
	}
	type pending struct {
		id, recipient, conversationID string
		bytes                         int64
	}
	var expired []pending
	for rows.Next() {
		var row pending
		if err := rows.Scan(&row.id, &row.recipient, &row.conversationID, &row.bytes); err != nil {
			_ = rows.Close()
			return MaintenanceResult{}, err
		}
		expired = append(expired, row)
	}
	if err := rows.Close(); err != nil {
		return MaintenanceResult{}, err
	}
	if err := rows.Err(); err != nil {
		return MaintenanceResult{}, err
	}
	closedAt := now.UnixMilli()
	var count int
	for _, row := range expired {
		result, err := tx.ExecContext(context.Background(), `UPDATE deliveries
			SET acked_at = ?, closed_reason = ?, lease_machine_id = NULL, lease_token = NULL,
			    ownership_generation = NULL, consumer_generation = NULL, lease_until = NULL
			WHERE id = ? AND acked_at IS NULL`, closedAt, ClosedReasonExpired, row.id)
		if err != nil {
			return MaintenanceResult{}, fmt.Errorf("expire delivery: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return MaintenanceResult{}, fmt.Errorf("expire delivery: %w", err)
		}
		if affected != 1 {
			continue
		}
		if err := releaseQuota(tx, row.recipient, row.bytes); err != nil {
			return MaintenanceResult{}, err
		}
		if err := advanceRecipientCursor(tx, row.recipient, row.conversationID); err != nil {
			return MaintenanceResult{}, err
		}
		s.metrics.ObserveTerminalTransition(ClosedReasonExpired)
		count++
	}
	if err := tx.Commit(); err != nil {
		return MaintenanceResult{}, err
	}
	s.refreshPendingMetricsAt(now)
	return MaintenanceResult{Expired: count}, nil
}

// PruneTerminalDeliveries deletes a bounded page of terminal rows older than retention.
func (s *Store) PruneTerminalDeliveries(now time.Time) (MaintenanceResult, error) {
	cfg := s.retentionConfig()
	now = now.UTC().Truncate(time.Millisecond)
	before := now.Add(-cfg.TerminalRetention).UnixMilli()
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return MaintenanceResult{}, err
	}
	defer rollback(tx)
	result, err := tx.ExecContext(context.Background(), `DELETE FROM deliveries WHERE id IN (
		SELECT id FROM (
			SELECT id FROM deliveries WHERE acked_at IS NOT NULL AND acked_at <= ? ORDER BY acked_at, id LIMIT ?
		)
	)`, before, cfg.MaintenanceBatch)
	if err != nil {
		return MaintenanceResult{}, fmt.Errorf("prune terminal deliveries: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return MaintenanceResult{}, fmt.Errorf("prune terminal deliveries: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return MaintenanceResult{}, err
	}
	s.refreshPendingMetricsAt(now)
	return MaintenanceResult{Pruned: int(affected)}, nil
}

// MaintainTerminalDeliveries expires one pending page then prunes one terminal page.
func (s *Store) MaintainTerminalDeliveries(now time.Time) (MaintenanceResult, error) {
	expired, err := s.ExpirePendingDeliveries(now)
	if err != nil {
		return MaintenanceResult{}, err
	}
	pruned, err := s.PruneTerminalDeliveries(now)
	if err != nil {
		return MaintenanceResult{}, err
	}
	return MaintenanceResult{Expired: expired.Expired, Pruned: pruned.Pruned}, nil
}

// ListTerminalDeliveries returns one content-free dead-letter page.
func (s *Store) ListTerminalDeliveries(limit int, after string) (TerminalPage, error) {
	if limit < 1 {
		limit = DefaultRoleListLimit
	}
	if limit > MaxRoleListLimit {
		limit = MaxRoleListLimit
	}
	query := `SELECT delivery.id, message.id, message.conversation_id, delivery.recipient_endpoint, message.sequence,
		delivery.closed_reason, delivery.lease_generation, delivery.acked_at
		FROM deliveries AS delivery JOIN messages AS message ON message.id = delivery.message_id
		WHERE delivery.closed_reason IN (?, ?)`
	args := []any{ClosedReasonExpired, ClosedReasonRevoked}
	if after != "" {
		query += ` AND (delivery.acked_at, delivery.id) > (
			SELECT acked_at, id FROM deliveries WHERE id = ? AND closed_reason IN (?, ?)
		)`
		args = append(args, after, ClosedReasonExpired, ClosedReasonRevoked)
	}
	query += ` ORDER BY delivery.acked_at, delivery.id LIMIT ?`
	args = append(args, limit+1)
	rows, err := s.db.QueryContext(context.Background(), query, args...)
	if err != nil {
		return TerminalPage{}, fmt.Errorf("list terminal deliveries: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var records []TerminalRecord
	for rows.Next() {
		var record TerminalRecord
		var closedAt int64
		if err := rows.Scan(&record.DeliveryID, &record.MessageID, &record.ConversationID, &record.RecipientID, &record.Sequence, &record.ClosedReason, &record.LeaseGeneration, &closedAt); err != nil {
			return TerminalPage{}, err
		}
		record.ClosedAt = fromMillis(closedAt)
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return TerminalPage{}, err
	}
	page := TerminalPage{Records: records}
	if len(page.Records) > limit {
		page.NextCursor = page.Records[limit-1].DeliveryID
		page.Records = page.Records[:limit]
	}
	return page, nil
}

func (s *Store) refreshPendingMetricsAt(now time.Time) {
	s.pendingMetricsMu.Lock()
	defer s.pendingMetricsMu.Unlock()
	counters, err := readInstallQuota(context.Background(), s.db)
	if err != nil {
		return
	}
	s.metrics.SetPending(counters.Count, counters.Bytes)
	var oldest sql.NullInt64
	if err := s.db.QueryRowContext(context.Background(), `SELECT MIN(message.created_at)
		FROM deliveries AS delivery JOIN messages AS message ON message.id = delivery.message_id
		WHERE delivery.acked_at IS NULL`).Scan(&oldest); err != nil {
		return
	}
	if oldest.Valid {
		age := now.UTC().UnixMilli() - oldest.Int64
		if age < 0 {
			age = 0
		}
		s.metrics.SetOldestPendingAge(time.Duration(age) * time.Millisecond)
	} else {
		s.metrics.SetOldestPendingAge(0)
	}
	var retained int64
	if err := s.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM deliveries WHERE closed_reason IS NOT NULL`).Scan(&retained); err != nil {
		return
	}
	s.metrics.SetTerminalRetained(retained)
}
