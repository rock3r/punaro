package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/rock3r/punaro/internal/relay"
)

// SetRetentionPolicy replaces the in-process pending-expiry and terminal-retention policy.
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

func (d *Database) mailClosedReasonPresent() bool {
	d.closedReasonMu.Lock()
	defer d.closedReasonMu.Unlock()
	if d.closedReasonKnown {
		return d.closedReasonPresent
	}
	var present bool
	err := d.relayPool().QueryRowContext(context.Background(), `SELECT EXISTS (
		SELECT 1 FROM pg_attribute
		WHERE attrelid='relay.mail_deliveries'::regclass AND attname='closed_reason' AND NOT attisdropped
	)`).Scan(&present)
	if err != nil {
		return false
	}
	d.closedReasonKnown = true
	d.closedReasonPresent = present
	return present
}

// ExpirePendingDeliveries moves a bounded page of aged pending deliveries to
// terminal expired state, releasing pending capacity once per delivery.
func (d *Database) ExpirePendingDeliveries(now time.Time) (relay.MaintenanceResult, error) {
	if !d.mailClosedReasonPresent() {
		return relay.MaintenanceResult{}, nil
	}
	cfg := d.retentionConfig()
	now = now.UTC()
	cutoff := now.Add(-cfg.PendingMaxAge)
	tx, cancel, err := d.beginRelayTransaction(nil)
	if err != nil {
		return relay.MaintenanceResult{}, errors.New("pending expiry cannot start")
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(context.Background(), `SELECT delivery.id::text, delivery.recipient_endpoint, message.conversation_id::text, `+postgresPendingBodyBytes+`
		FROM relay.mail_deliveries AS delivery JOIN relay.mail_messages AS message ON message.id=delivery.message_id
		WHERE delivery.acked_at IS NULL AND message.created_at<=$1
		ORDER BY message.created_at, delivery.id
		LIMIT $2
		FOR UPDATE OF delivery SKIP LOCKED`, cutoff, cfg.MaintenanceBatch)
	if err != nil {
		return relay.MaintenanceResult{}, errors.New("expired deliveries are unavailable")
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
			return relay.MaintenanceResult{}, errors.New("expired delivery is malformed")
		}
		expired = append(expired, row)
	}
	if err := rows.Close(); err != nil || rows.Err() != nil {
		return relay.MaintenanceResult{}, errors.New("expired deliveries are unavailable")
	}
	var count int
	for _, row := range expired {
		result, err := tx.ExecContext(context.Background(), `UPDATE relay.mail_deliveries
			SET acked_at=$1, closed_reason=$2, lease_machine_id=NULL, lease_token=NULL,
			    ownership_generation=NULL, consumer_generation=NULL, lease_until=NULL
			WHERE id=$3::uuid AND acked_at IS NULL`, now, relay.ClosedReasonExpired, row.id)
		if err != nil {
			return relay.MaintenanceResult{}, relayDatabaseError(err, "expire delivery")
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return relay.MaintenanceResult{}, errors.New("expire delivery is unavailable")
		}
		if affected != 1 {
			continue
		}
		if err := postgresReleaseQuota(tx, row.recipient, row.bytes); err != nil {
			return relay.MaintenanceResult{}, err
		}
		if err := postgresAdvanceRecipientCursor(tx, row.recipient, row.conversationID); err != nil {
			return relay.MaintenanceResult{}, err
		}
		d.metrics.ObserveTerminalTransition(relay.ClosedReasonExpired)
		count++
	}
	if err := tx.Commit(); err != nil {
		return relay.MaintenanceResult{}, relayDatabaseError(err, "commit pending expiry")
	}
	d.refreshPendingMetricsAt(context.Background(), now)
	return relay.MaintenanceResult{Expired: count}, nil
}

// PruneTerminalDeliveries deletes a bounded page of terminal rows older than retention.
func (d *Database) PruneTerminalDeliveries(now time.Time) (relay.MaintenanceResult, error) {
	if !d.mailClosedReasonPresent() {
		return relay.MaintenanceResult{}, nil
	}
	cfg := d.retentionConfig()
	now = now.UTC()
	before := now.Add(-cfg.TerminalRetention)
	tx, cancel, err := d.beginRelayTransaction(nil)
	if err != nil {
		return relay.MaintenanceResult{}, errors.New("terminal prune cannot start")
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()
	var pruned int64
	if err := tx.QueryRowContext(context.Background(), `SELECT relay.prune_mail_terminal($1,$2)`, before, cfg.MaintenanceBatch).Scan(&pruned); err != nil {
		return relay.MaintenanceResult{}, relayDatabaseError(err, "prune terminal deliveries")
	}
	if err := tx.Commit(); err != nil {
		return relay.MaintenanceResult{}, relayDatabaseError(err, "commit terminal prune")
	}
	d.refreshPendingMetricsAt(context.Background(), now)
	return relay.MaintenanceResult{Pruned: int(pruned)}, nil
}

// MaintainTerminalDeliveries expires one pending page then prunes one terminal page.
func (d *Database) MaintainTerminalDeliveries(now time.Time) (relay.MaintenanceResult, error) {
	expired, err := d.ExpirePendingDeliveries(now)
	if err != nil {
		return relay.MaintenanceResult{}, err
	}
	pruned, err := d.PruneTerminalDeliveries(now)
	if err != nil {
		return relay.MaintenanceResult{}, err
	}
	return relay.MaintenanceResult{Expired: expired.Expired, Pruned: pruned.Pruned}, nil
}

// ListTerminalDeliveries returns one content-free dead-letter page.
func (d *Database) ListTerminalDeliveries(limit int, after string) (relay.TerminalPage, error) {
	if !d.mailClosedReasonPresent() {
		return relay.TerminalPage{}, nil
	}
	if limit < 1 {
		limit = relay.DefaultRoleListLimit
	}
	if limit > relay.MaxRoleListLimit {
		limit = relay.MaxRoleListLimit
	}
	if after != "" {
		if _, err := uuid.Parse(after); err != nil {
			return relay.TerminalPage{}, errors.New("terminal cursor is invalid")
		}
	}
	query := `SELECT delivery.id::text, message.id::text, message.conversation_id::text, delivery.recipient_endpoint, message.sequence,
		delivery.closed_reason, delivery.lease_generation, delivery.acked_at
		FROM relay.mail_deliveries AS delivery JOIN relay.mail_messages AS message ON message.id=delivery.message_id
		WHERE delivery.closed_reason IN ($1,$2)`
	args := []any{relay.ClosedReasonExpired, relay.ClosedReasonRevoked}
	if after != "" {
		query += ` AND (delivery.acked_at, delivery.id) > (
			SELECT acked_at, id FROM relay.mail_deliveries WHERE id=$3::uuid AND closed_reason IN ($1,$2)
		)`
		args = append(args, after)
	}
	query += ` ORDER BY delivery.acked_at, delivery.id LIMIT $` + strconv.Itoa(len(args)+1)
	args = append(args, limit+1)
	rows, err := d.relayPool().QueryContext(context.Background(), query, args...)
	if err != nil {
		return relay.TerminalPage{}, errors.New("terminal deliveries are unavailable")
	}
	defer func() { _ = rows.Close() }()
	var records []relay.TerminalRecord
	for rows.Next() {
		var record relay.TerminalRecord
		var closedAt time.Time
		if err := rows.Scan(&record.DeliveryID, &record.MessageID, &record.ConversationID, &record.RecipientID, &record.Sequence, &record.ClosedReason, &record.LeaseGeneration, &closedAt); err != nil {
			return relay.TerminalPage{}, errors.New("terminal delivery is malformed")
		}
		record.ClosedAt = closedAt.UTC()
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return relay.TerminalPage{}, errors.New("terminal deliveries are unavailable")
	}
	page := relay.TerminalPage{Records: records}
	if len(page.Records) > limit {
		page.NextCursor = page.Records[limit-1].DeliveryID
		page.Records = page.Records[:limit]
	}
	return page, nil
}

func (d *Database) refreshPendingMetricsAt(ctx context.Context, now time.Time) {
	present := d.mailClosedReasonPresent()
	d.pendingMetricsMu.Lock()
	defer d.pendingMetricsMu.Unlock()
	counters, err := postgresReadInstallQuota(ctx, d.relayPool())
	if err != nil {
		return
	}
	d.metrics.SetPending(counters.Count, counters.Bytes)
	var oldest sql.NullTime
	if err := d.relayPool().QueryRowContext(ctx, `SELECT MIN(message.created_at)
		FROM relay.mail_deliveries AS delivery JOIN relay.mail_messages AS message ON message.id=delivery.message_id
		WHERE delivery.acked_at IS NULL`).Scan(&oldest); err != nil {
		return
	}
	if oldest.Valid {
		age := now.UTC().Sub(oldest.Time.UTC())
		if age < 0 {
			age = 0
		}
		d.metrics.SetOldestPendingAge(age)
	} else {
		d.metrics.SetOldestPendingAge(0)
	}
	if !present {
		d.metrics.SetTerminalRetained(0)
		return
	}
	var retained int64
	if err := d.relayPool().QueryRowContext(ctx, `SELECT COUNT(*) FROM relay.mail_deliveries WHERE closed_reason IS NOT NULL`).Scan(&retained); err != nil {
		return
	}
	d.metrics.SetTerminalRetained(retained)
}
