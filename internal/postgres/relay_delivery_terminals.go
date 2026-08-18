package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/rock3r/punaro/internal/relay"
)

// SetRetentionPolicy replaces the in-process pending-age and terminal-retention policy.
func (d *Database) SetRetentionPolicy(cfg relay.RetentionConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	d.retentionMu.Lock()
	d.retention = cfg
	d.retentionMu.Unlock()
	return nil
}

func (d *Database) retentionConfig() relay.RetentionConfig {
	d.retentionMu.Lock()
	defer d.retentionMu.Unlock()
	if d.retention == (relay.RetentionConfig{}) {
		return relay.DefaultRetentionConfig()
	}
	return d.retention
}

// MaintainDeliveries expires due pending deliveries and prunes aged terminal metadata.
func (d *Database) MaintainDeliveries(now time.Time) (relay.MaintenanceResult, error) {
	now = now.UTC().Truncate(time.Microsecond)
	cfg := d.retentionConfig()
	tx, cancel, err := d.beginRelayTransaction(nil)
	if err != nil {
		return relay.MaintenanceResult{}, errors.New("delivery maintenance cannot start")
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()
	expired, err := postgresExpireDueDeliveries(tx, now, cfg)
	if err != nil {
		return relay.MaintenanceResult{}, err
	}
	pruned, err := postgresPruneTerminals(tx, now, cfg)
	if err != nil {
		return relay.MaintenanceResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return relay.MaintenanceResult{}, relayDatabaseError(err, "commit delivery maintenance")
	}
	d.metrics.ObserveTerminalTransition(relay.ClosedReasonExpired, uint64(expired)) // #nosec G115 -- expired is bounded by MaintenanceBatch.
	d.refreshDeliveryMetrics(context.Background(), now)
	return relay.MaintenanceResult{
		Expired:      expired,
		Pruned:       pruned,
		Continuation: expired == cfg.MaintenanceBatch || pruned == cfg.MaintenanceBatch,
	}, nil
}

func postgresExpireDueDeliveries(tx *sql.Tx, now time.Time, cfg relay.RetentionConfig) (int, error) {
	cutoff := now.Add(-cfg.PendingMaxAge())
	rows, err := tx.QueryContext(context.Background(), `SELECT delivery.id::text, delivery.recipient_endpoint, `+postgresPendingBodyBytes+`, message.conversation_id::text
		FROM relay.mail_deliveries AS delivery JOIN relay.mail_messages AS message ON message.id=delivery.message_id
		WHERE delivery.acked_at IS NULL AND message.created_at <= $1
		ORDER BY message.created_at, delivery.id
		LIMIT $2
		FOR UPDATE OF delivery SKIP LOCKED`, cutoff, cfg.MaintenanceBatch)
	if err != nil {
		return 0, errors.New("expired deliveries cannot be inspected")
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
			return 0, errors.New("expired deliveries cannot be inspected")
		}
		due = append(due, row)
	}
	if err := rows.Close(); err != nil || rows.Err() != nil {
		return 0, errors.New("expired deliveries cannot be inspected")
	}
	closed := 0
	for _, row := range due {
		result, err := tx.ExecContext(context.Background(), `UPDATE relay.mail_deliveries
			SET acked_at=$1, lease_machine_id=NULL, lease_token=NULL, ownership_generation=NULL, consumer_generation=NULL, lease_until=NULL
			WHERE id=$2::uuid AND acked_at IS NULL`, now, row.id)
		if err != nil {
			return 0, relayDatabaseError(err, "expire delivery")
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return 0, errors.New("expire delivery is unavailable")
		}
		if affected != 1 {
			continue
		}
		if err := postgresRecordDeliveryTerminal(tx, row.id, relay.ClosedReasonExpired, now); err != nil {
			return 0, err
		}
		if err := postgresReleaseQuota(tx, row.recipient, row.bodyBytes); err != nil {
			return 0, err
		}
		if err := postgresAdvanceRecipientCursor(tx, row.recipient, row.conversationID); err != nil {
			return 0, err
		}
		closed++
	}
	return closed, nil
}

func postgresPruneTerminals(tx *sql.Tx, now time.Time, cfg relay.RetentionConfig) (int, error) {
	cutoff := now.Add(-cfg.TerminalRetention())
	result, err := tx.ExecContext(context.Background(), `DELETE FROM relay.mail_delivery_terminals WHERE delivery_id IN (
		SELECT delivery_id FROM relay.mail_delivery_terminals WHERE closed_at <= $1 ORDER BY closed_at, delivery_id LIMIT $2
	)`, cutoff, cfg.MaintenanceBatch)
	if err != nil {
		return 0, relayDatabaseError(err, "prune delivery terminals")
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, errors.New("prune delivery terminals is unavailable")
	}
	return int(affected), nil
}

func postgresRecordDeliveryTerminal(tx *sql.Tx, deliveryID, reason string, now time.Time) error {
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_delivery_terminals(
		delivery_id, message_id, conversation_id, recipient_id, sequence, closed_reason, lease_generation, closed_at, created_at)
		SELECT delivery.id, delivery.message_id, message.conversation_id, delivery.recipient_endpoint, message.sequence, $2, COALESCE(delivery.lease_generation, 0), $3, message.created_at
		FROM relay.mail_deliveries AS delivery JOIN relay.mail_messages AS message ON message.id=delivery.message_id
		WHERE delivery.id=$1::uuid
		ON CONFLICT (delivery_id) DO NOTHING`, deliveryID, reason, now.UTC()); err != nil {
		return relayDatabaseError(err, "record delivery terminal")
	}
	return nil
}

// ListDeliveryTerminals returns one bounded page of retained terminal metadata.
func (d *Database) ListDeliveryTerminals(input relay.TerminalListInput) (relay.TerminalListPage, error) {
	limit := input.Limit
	if limit <= 0 {
		limit = relay.DefaultTerminalListLimit
	}
	if limit > relay.MaxTerminalListLimit {
		limit = relay.MaxTerminalListLimit
	}
	closedAt, deliveryID, ok := relay.DecodeTerminalListCursor(input.Cursor)
	if !ok {
		return relay.TerminalListPage{}, errors.New("invalid terminal cursor")
	}
	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()
	var rows *sql.Rows
	var err error
	if deliveryID == "" {
		rows, err = d.relayPool().QueryContext(ctx, `SELECT delivery_id::text, message_id::text, conversation_id::text, recipient_id, sequence, closed_reason, lease_generation, closed_at, created_at
			FROM relay.mail_delivery_terminals ORDER BY closed_at, delivery_id LIMIT $1`, limit+1)
	} else {
		if _, parseErr := uuid.Parse(deliveryID); parseErr != nil {
			return relay.TerminalListPage{}, errors.New("invalid terminal cursor")
		}
		rows, err = d.relayPool().QueryContext(ctx, `SELECT delivery_id::text, message_id::text, conversation_id::text, recipient_id, sequence, closed_reason, lease_generation, closed_at, created_at
			FROM relay.mail_delivery_terminals
			WHERE closed_at > $1 OR (closed_at = $1 AND delivery_id > $2::uuid)
			ORDER BY closed_at, delivery_id LIMIT $3`, closedAt.UTC(), deliveryID, limit+1)
	}
	if err != nil {
		return relay.TerminalListPage{}, errors.New("delivery terminals are unavailable")
	}
	defer func() { _ = rows.Close() }()
	var terminals []relay.DeliveryTerminal
	for rows.Next() {
		var terminal relay.DeliveryTerminal
		if err := rows.Scan(&terminal.DeliveryID, &terminal.MessageID, &terminal.ConversationID, &terminal.RecipientID, &terminal.Sequence, &terminal.ClosedReason, &terminal.LeaseGeneration, &terminal.ClosedAt, &terminal.CreatedAt); err != nil {
			return relay.TerminalListPage{}, errors.New("delivery terminal is malformed")
		}
		terminal.ClosedAt = terminal.ClosedAt.UTC()
		terminal.CreatedAt = terminal.CreatedAt.UTC()
		terminals = append(terminals, terminal)
	}
	if err := rows.Err(); err != nil {
		return relay.TerminalListPage{}, errors.New("delivery terminals are unavailable")
	}
	page := relay.TerminalListPage{Terminals: terminals}
	if len(page.Terminals) > limit {
		last := page.Terminals[limit-1]
		page.Terminals = page.Terminals[:limit]
		page.NextCursor = relay.EncodeTerminalListCursor(last.ClosedAt, last.DeliveryID)
	}
	return page, nil
}

func (d *Database) refreshDeliveryMetrics(ctx context.Context, now time.Time) {
	d.refreshPendingMetrics(ctx)
	if d.metrics == nil {
		return
	}
	var oldest sql.NullTime
	if err := d.relayPool().QueryRowContext(ctx, `SELECT MIN(message.created_at)
		FROM relay.mail_deliveries AS delivery JOIN relay.mail_messages AS message ON message.id=delivery.message_id
		WHERE delivery.acked_at IS NULL`).Scan(&oldest); err != nil {
		return
	}
	if oldest.Valid {
		d.metrics.SetQueueAge(pendingAgeSecondsFor(oldest.Time, now))
	} else {
		d.metrics.SetQueueAge(0)
	}
	var retained int64
	if err := d.relayPool().QueryRowContext(ctx, `SELECT COUNT(*) FROM relay.mail_delivery_terminals`).Scan(&retained); err != nil {
		return
	}
	d.metrics.SetTerminalsRetained(uint64(max64(retained, 0))) // #nosec G115 -- retained count is CHECK-constrained to non-negative values.
}

func pendingAgeSecondsFor(oldest, now time.Time) uint64 {
	if oldest.IsZero() || now.Before(oldest) {
		return 0
	}
	seconds := int64(now.Sub(oldest) / time.Second)
	if seconds < 0 {
		return 0
	}
	return uint64(seconds) // #nosec G115 -- pending age is non-negative.
}

func max64(value, floor int64) int64 {
	if value < floor {
		return floor
	}
	return value
}
