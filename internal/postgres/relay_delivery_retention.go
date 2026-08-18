package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/rock3r/punaro/internal/relay"
)

type postgresPendingClose struct {
	ID              string
	MessageID       string
	ConversationID  string
	Recipient       string
	Sequence        int64
	LeaseGeneration int64
	BodyBytes       int64
	CreatedAt       time.Time
}

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

// MaintainDeliveries expires due pending deliveries and prunes retained terminals.
// Each close is its own bounded transaction so the five-second relay budget
// cannot roll back earlier expiry or quota release.
func (d *Database) MaintainDeliveries(now time.Time) (relay.MaintenanceResult, error) {
	cfg := d.retentionConfig()
	now = now.UTC()
	expireCutoff := now.Add(-time.Duration(cfg.PendingMaxAgeSeconds) * time.Second)
	var result relay.MaintenanceResult
	defer func() {
		d.metrics.ObserveTerminals(relay.ClosedExpired, result.Expired)
		d.refreshPendingMetrics(context.Background(), now)
	}()
	for i := 0; i < cfg.MaintenanceBatch; i++ {
		found, closed, err := d.expireOneDueDelivery(expireCutoff, now)
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
	pruneCutoff := now.Add(-time.Duration(cfg.TerminalRetentionSeconds) * time.Second)
	for i := 0; i < cfg.MaintenanceBatch; i++ {
		found, err := d.pruneOneTerminal(pruneCutoff)
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

func (d *Database) expireOneDueDelivery(cutoff, now time.Time) (bool, bool, error) {
	tx, cancel, err := d.beginRelayTransaction(nil)
	if err != nil {
		return false, false, errors.New("delivery maintenance cannot start")
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()
	var row postgresPendingClose
	err = tx.QueryRowContext(context.Background(), `SELECT delivery.id::text, delivery.recipient_endpoint, message.id::text, message.conversation_id::text, message.sequence, delivery.lease_generation, `+postgresPendingBodyBytes+`, message.created_at
		FROM relay.mail_deliveries AS delivery JOIN relay.mail_messages AS message ON message.id=delivery.message_id
		WHERE delivery.acked_at IS NULL AND message.created_at <= $1
		ORDER BY message.created_at, delivery.id
		LIMIT 1
		FOR UPDATE OF delivery SKIP LOCKED`, cutoff).Scan(&row.ID, &row.Recipient, &row.MessageID, &row.ConversationID, &row.Sequence, &row.LeaseGeneration, &row.BodyBytes, &row.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, errors.New("expired deliveries cannot be inspected")
	}
	closed, err := postgresClosePendingDelivery(tx, row, relay.ClosedExpired, now)
	if err != nil {
		return true, false, err
	}
	if !closed {
		return true, false, nil
	}
	if err := tx.Commit(); err != nil {
		return true, false, relayDatabaseError(err, "commit expired delivery")
	}
	return true, true, nil
}

func (d *Database) pruneOneTerminal(cutoff time.Time) (bool, error) {
	tx, cancel, err := d.beginRelayTransaction(nil)
	if err != nil {
		return false, errors.New("delivery maintenance cannot start")
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()
	var id string
	err = tx.QueryRowContext(context.Background(), `SELECT delivery_id::text FROM relay.mail_delivery_terminals
		WHERE closed_at <= $1
		ORDER BY closed_at, delivery_id
		LIMIT 1
		FOR UPDATE SKIP LOCKED`, cutoff).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, errors.New("retained terminals cannot be inspected")
	}
	if _, err := tx.ExecContext(context.Background(), `DELETE FROM relay.mail_delivery_terminals WHERE delivery_id=$1::uuid`, id); err != nil {
		return false, relayDatabaseError(err, "prune terminal metadata")
	}
	if err := tx.Commit(); err != nil {
		return false, relayDatabaseError(err, "commit terminal prune")
	}
	return true, nil
}

// ListTerminalDeliveries returns one content-free operator page of retained terminals.
func (d *Database) ListTerminalDeliveries(after string, limit int) (relay.TerminalPage, error) {
	if limit < relay.TerminalListLimitMin || limit > relay.TerminalListLimitMax {
		return relay.TerminalPage{}, fmt.Errorf("relay terminal page limit must be an integer between %d and %d", relay.TerminalListLimitMin, relay.TerminalListLimitMax)
	}
	if after == "" {
		after = "00000000-0000-0000-0000-000000000000"
	}
	tx, cancel, err := d.beginRelayTransaction(&sql.TxOptions{ReadOnly: true})
	if err != nil {
		return relay.TerminalPage{}, errors.New("terminal listing cannot start")
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(context.Background(), `SELECT delivery_id::text, message_id::text, conversation_id::text, recipient_endpoint, sequence, closed_reason, lease_generation, created_at, closed_at
		FROM relay.mail_delivery_terminals WHERE delivery_id > $1::uuid ORDER BY delivery_id LIMIT $2`, after, limit)
	if err != nil {
		return relay.TerminalPage{}, errors.New("terminal deliveries cannot be listed")
	}
	defer func() { _ = rows.Close() }()
	var page relay.TerminalPage
	for rows.Next() {
		var record relay.TerminalRecord
		if err := rows.Scan(&record.DeliveryID, &record.MessageID, &record.ConversationID, &record.RecipientID, &record.Sequence, &record.ClosedReason, &record.LeaseGeneration, &record.CreatedAt, &record.ClosedAt); err != nil {
			return relay.TerminalPage{}, errors.New("terminal delivery is malformed")
		}
		record.CreatedAt = record.CreatedAt.UTC()
		record.ClosedAt = record.ClosedAt.UTC()
		page.Terminals = append(page.Terminals, record)
	}
	if err := rows.Err(); err != nil {
		return relay.TerminalPage{}, errors.New("terminal deliveries cannot be listed")
	}
	if err := tx.Commit(); err != nil {
		return relay.TerminalPage{}, errors.New("terminal listing cannot commit")
	}
	if len(page.Terminals) == limit {
		page.NextCursor = page.Terminals[len(page.Terminals)-1].DeliveryID
	}
	return page, nil
}

func postgresClosePendingDelivery(tx *sql.Tx, row postgresPendingClose, reason string, now time.Time) (bool, error) {
	closedAt := now.UTC()
	result, err := tx.ExecContext(context.Background(), `UPDATE relay.mail_deliveries SET acked_at=$1, lease_machine_id=NULL, lease_token=NULL, ownership_generation=NULL, consumer_generation=NULL, lease_until=NULL
		WHERE id=$2::uuid AND acked_at IS NULL`, closedAt, row.ID)
	if err != nil {
		return false, relayDatabaseError(err, "close pending delivery")
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, relayDatabaseError(err, "close pending delivery")
	}
	if affected != 1 {
		return false, nil
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_delivery_terminals(delivery_id,message_id,conversation_id,recipient_endpoint,sequence,closed_reason,lease_generation,created_at,closed_at)
		VALUES ($1::uuid,$2::uuid,$3::uuid,$4,$5,$6,$7,$8,$9) ON CONFLICT (delivery_id) DO NOTHING`, row.ID, row.MessageID, row.ConversationID, row.Recipient, row.Sequence, reason, row.LeaseGeneration, row.CreatedAt.UTC(), closedAt); err != nil {
		return false, relayDatabaseError(err, "record terminal delivery")
	}
	if err := postgresReleaseQuota(tx, row.Recipient, row.BodyBytes); err != nil {
		return false, err
	}
	if err := postgresAdvanceRecipientCursor(tx, row.Recipient, row.ConversationID); err != nil {
		return false, err
	}
	return true, nil
}

func postgresRecordAckedTerminal(tx *sql.Tx, deliveryID string, now time.Time) error {
	var row postgresPendingClose
	if err := tx.QueryRowContext(context.Background(), `SELECT delivery.id::text, delivery.recipient_endpoint, message.id::text, message.conversation_id::text, message.sequence, delivery.lease_generation, `+postgresPendingBodyBytes+`, message.created_at
		FROM relay.mail_deliveries AS delivery JOIN relay.mail_messages AS message ON message.id=delivery.message_id
		WHERE delivery.id=$1::uuid`, deliveryID).Scan(&row.ID, &row.Recipient, &row.MessageID, &row.ConversationID, &row.Sequence, &row.LeaseGeneration, &row.BodyBytes, &row.CreatedAt); err != nil {
		return errors.New("acknowledged delivery is unavailable")
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_delivery_terminals(delivery_id,message_id,conversation_id,recipient_endpoint,sequence,closed_reason,lease_generation,created_at,closed_at)
		VALUES ($1::uuid,$2::uuid,$3::uuid,$4,$5,$6,$7,$8,$9) ON CONFLICT (delivery_id) DO NOTHING`, row.ID, row.MessageID, row.ConversationID, row.Recipient, row.Sequence, relay.ClosedAcked, row.LeaseGeneration, row.CreatedAt.UTC(), now.UTC()); err != nil {
		return relayDatabaseError(err, "record acknowledged terminal")
	}
	return nil
}
