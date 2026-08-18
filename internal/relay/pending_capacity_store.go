package relay

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
)

func (s *Store) reservePendingCapacity(tx *sql.Tx, recipients []string, bodyBytes int64) error {
	if len(recipients) == 0 {
		return nil
	}
	if bodyBytes < 0 {
		return errors.New("invalid pending body size")
	}
	charges := groupedPendingCharges(recipients, bodyBytes)
	cfg := s.pendingCapacityConfig()
	if err := ensurePendingCapacityRow(tx, pendingScopeInstallation, pendingInstallationKey); err != nil {
		return err
	}
	keys := make([]string, 0, len(charges))
	for recipient := range charges {
		keys = append(keys, recipient)
	}
	sort.Strings(keys)
	current := make(map[string]struct{ Count, Bytes int64 }, len(keys))
	for _, recipient := range keys {
		if err := ensurePendingCapacityRow(tx, pendingScopeRecipient, recipient); err != nil {
			return err
		}
		count, bytes, err := readPendingCapacityRow(tx, pendingScopeRecipient, recipient)
		if err != nil {
			return err
		}
		current[recipient] = struct{ Count, Bytes int64 }{Count: count, Bytes: bytes}
	}
	installationCount, installationBytes, err := readPendingCapacityRow(tx, pendingScopeInstallation, pendingInstallationKey)
	if err != nil {
		return err
	}
	chargeList := make([]PendingCharge, 0, len(keys))
	for _, recipient := range keys {
		chargeList = append(chargeList, charges[recipient])
	}
	decision := DecidePendingCapacity(cfg, installationCount, installationBytes, current, chargeList)
	if !decision.Allowed {
		s.metrics.ObserveCapacityRejected()
		return &CapacityError{RetryAfterSeconds: decision.RetryAfterSeconds}
	}
	for _, recipient := range keys {
		charge := charges[recipient]
		if err := adjustPendingCapacityRow(tx, pendingScopeRecipient, recipient, charge.Count, charge.Bytes); err != nil {
			return err
		}
	}
	var addCount, addBytes int64
	for _, charge := range chargeList {
		addCount += charge.Count
		addBytes += charge.Bytes
	}
	return adjustPendingCapacityRow(tx, pendingScopeInstallation, pendingInstallationKey, addCount, addBytes)
}

func releasePendingCharges(tx *sql.Tx, charges []PendingCharge) error {
	if len(charges) == 0 {
		return nil
	}
	grouped := map[string]PendingCharge{}
	var addCount, addBytes int64
	for _, charge := range charges {
		if charge.Count == 0 && charge.Bytes == 0 {
			continue
		}
		existing := grouped[charge.Recipient]
		existing.Recipient = charge.Recipient
		existing.Count += charge.Count
		existing.Bytes += charge.Bytes
		grouped[charge.Recipient] = existing
		addCount += charge.Count
		addBytes += charge.Bytes
	}
	if addCount == 0 && addBytes == 0 {
		return nil
	}
	keys := make([]string, 0, len(grouped))
	for recipient := range grouped {
		keys = append(keys, recipient)
	}
	sort.Strings(keys)
	for _, recipient := range keys {
		charge := grouped[recipient]
		if err := adjustPendingCapacityRow(tx, pendingScopeRecipient, recipient, -charge.Count, -charge.Bytes); err != nil {
			return err
		}
	}
	return adjustPendingCapacityRow(tx, pendingScopeInstallation, pendingInstallationKey, -addCount, -addBytes)
}

func groupedPendingCharges(recipients []string, bodyBytes int64) map[string]PendingCharge {
	charges := make(map[string]PendingCharge, len(recipients))
	for _, recipient := range recipients {
		charge := charges[recipient]
		charge.Recipient = recipient
		charge.Count++
		charge.Bytes += bodyBytes
		charges[recipient] = charge
	}
	return charges
}

func ensurePendingCapacityRow(tx *sql.Tx, scope, key string) error {
	if _, err := tx.ExecContext(context.Background(), `INSERT OR IGNORE INTO pending_capacity(scope, scope_key, pending_count, pending_bytes) VALUES (?, ?, 0, 0)`, scope, key); err != nil {
		return fmt.Errorf("initialize pending capacity: %w", err)
	}
	return nil
}

func readPendingCapacityRow(tx *sql.Tx, scope, key string) (int64, int64, error) {
	var count, bytes int64
	if err := tx.QueryRowContext(context.Background(), `SELECT pending_count, pending_bytes FROM pending_capacity WHERE scope = ? AND scope_key = ?`, scope, key).Scan(&count, &bytes); err != nil {
		return 0, 0, fmt.Errorf("read pending capacity: %w", err)
	}
	return count, bytes, nil
}

func adjustPendingCapacityRow(tx *sql.Tx, scope, key string, deltaCount, deltaBytes int64) error {
	result, err := tx.ExecContext(context.Background(), `UPDATE pending_capacity SET pending_count = pending_count + ?, pending_bytes = pending_bytes + ? WHERE scope = ? AND scope_key = ? AND pending_count + ? >= 0 AND pending_bytes + ? >= 0`, deltaCount, deltaBytes, scope, key, deltaCount, deltaBytes)
	if err != nil {
		return fmt.Errorf("update pending capacity: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update pending capacity: %w", err)
	}
	if affected != 1 {
		return errors.New("pending capacity counter would underflow")
	}
	return nil
}

func retirePendingDeliveries(tx *sql.Tx, recipient, conversationID string, nowMillis int64) error {
	rows, err := tx.QueryContext(context.Background(), `SELECT octet_length(message.body)
		FROM deliveries AS delivery JOIN messages AS message ON message.id = delivery.message_id
		WHERE delivery.recipient_endpoint = ? AND delivery.acked_at IS NULL AND message.conversation_id = ?`, recipient, conversationID)
	if err != nil {
		return fmt.Errorf("read revoked pending deliveries: %w", err)
	}
	var charges []PendingCharge
	for rows.Next() {
		var bodyBytes int64
		if err := rows.Scan(&bodyBytes); err != nil {
			_ = rows.Close()
			return fmt.Errorf("read revoked pending deliveries: %w", err)
		}
		charges = append(charges, PendingCharge{Recipient: recipient, Count: 1, Bytes: bodyBytes})
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("read revoked pending deliveries: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read revoked pending deliveries: %w", err)
	}
	if _, err := tx.ExecContext(context.Background(), "UPDATE deliveries SET acked_at=? WHERE recipient_endpoint=? AND acked_at IS NULL AND message_id IN (SELECT id FROM messages WHERE conversation_id=?)", nowMillis, recipient, conversationID); err != nil {
		return fmt.Errorf("retire revoked deliveries: %w", err)
	}
	if len(charges) == 0 {
		return nil
	}
	return releasePendingCharges(tx, charges)
}

func pendingDeliveryCharge(tx *sql.Tx, deliveryID string) (PendingCharge, error) {
	var charge PendingCharge
	if err := tx.QueryRowContext(context.Background(), `SELECT delivery.recipient_endpoint, octet_length(message.body)
		FROM deliveries AS delivery JOIN messages AS message ON message.id = delivery.message_id
		WHERE delivery.id = ?`, deliveryID).Scan(&charge.Recipient, &charge.Bytes); err != nil {
		return PendingCharge{}, fmt.Errorf("read delivery capacity charge: %w", err)
	}
	charge.Count = 1
	return charge, nil
}

func (s *Store) refreshPendingMetrics(tx queryRower) {
	count, bytes, err := installationPendingTotals(tx)
	if err != nil {
		return
	}
	s.metrics.SetPendingGauges(count, bytes)
}

type queryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func installationPendingTotals(q queryRower) (int64, int64, error) {
	var count, bytes int64
	err := q.QueryRowContext(context.Background(), `SELECT pending_count, pending_bytes FROM pending_capacity WHERE scope = ? AND scope_key = ?`, pendingScopeInstallation, pendingInstallationKey).Scan(&count, &bytes)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	return count, bytes, nil
}

func (s *Store) backfillPendingCapacity(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if err := rebuildPendingCapacity(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func rebuildPendingCapacity(tx *sql.Tx) error {
	if _, err := tx.ExecContext(context.Background(), `DELETE FROM pending_capacity`); err != nil {
		return fmt.Errorf("clear pending capacity: %w", err)
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO pending_capacity(scope, scope_key, pending_count, pending_bytes)
		SELECT ?, ?, COUNT(*), COALESCE(SUM(octet_length(message.body)), 0)
		FROM deliveries AS delivery JOIN messages AS message ON message.id = delivery.message_id
		WHERE delivery.acked_at IS NULL`, pendingScopeInstallation, pendingInstallationKey); err != nil {
		return fmt.Errorf("backfill installation pending capacity: %w", err)
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO pending_capacity(scope, scope_key, pending_count, pending_bytes)
		SELECT ?, delivery.recipient_endpoint, COUNT(*), COALESCE(SUM(octet_length(message.body)), 0)
		FROM deliveries AS delivery JOIN messages AS message ON message.id = delivery.message_id
		WHERE delivery.acked_at IS NULL
		GROUP BY delivery.recipient_endpoint`, pendingScopeRecipient); err != nil {
		return fmt.Errorf("backfill recipient pending capacity: %w", err)
	}
	return nil
}

// VerifyPendingCapacity reports whether explicit counters match pending deliveries.
func (s *Store) VerifyPendingCapacity() error {
	var actualCount, actualBytes, counterCount, counterBytes int64
	if err := s.db.QueryRowContext(context.Background(), `SELECT COUNT(*), COALESCE(SUM(octet_length(message.body)), 0)
		FROM deliveries AS delivery JOIN messages AS message ON message.id = delivery.message_id
		WHERE delivery.acked_at IS NULL`).Scan(&actualCount, &actualBytes); err != nil {
		return errors.New("pending capacity table is unavailable")
	}
	err := s.db.QueryRowContext(context.Background(), `SELECT pending_count, pending_bytes FROM pending_capacity WHERE scope = ? AND scope_key = ?`, pendingScopeInstallation, pendingInstallationKey).Scan(&counterCount, &counterBytes)
	if errors.Is(err, sql.ErrNoRows) {
		if actualCount == 0 && actualBytes == 0 {
			return nil
		}
		return errors.New("pending capacity counters are missing")
	}
	if err != nil {
		return errors.New("pending capacity counters are unavailable")
	}
	if actualCount != counterCount || actualBytes != counterBytes {
		return errors.New("pending capacity counters are inconsistent")
	}
	var recipientDrift bool
	if err := s.db.QueryRowContext(context.Background(), `SELECT EXISTS (
		SELECT recipient.scope_key FROM pending_capacity AS recipient
		LEFT JOIN (
			SELECT delivery.recipient_endpoint AS scope_key, COUNT(*) AS pending_count, COALESCE(SUM(octet_length(message.body)), 0) AS pending_bytes
			FROM deliveries AS delivery JOIN messages AS message ON message.id = delivery.message_id
			WHERE delivery.acked_at IS NULL
			GROUP BY delivery.recipient_endpoint
		) AS actual ON actual.scope_key = recipient.scope_key
		WHERE recipient.scope = ?
		  AND (COALESCE(actual.pending_count, 0) != recipient.pending_count OR COALESCE(actual.pending_bytes, 0) != recipient.pending_bytes)
	) OR EXISTS (
		SELECT actual.scope_key FROM (
			SELECT delivery.recipient_endpoint AS scope_key, COUNT(*) AS pending_count, COALESCE(SUM(octet_length(message.body)), 0) AS pending_bytes
			FROM deliveries AS delivery JOIN messages AS message ON message.id = delivery.message_id
			WHERE delivery.acked_at IS NULL
			GROUP BY delivery.recipient_endpoint
		) AS actual
		LEFT JOIN pending_capacity AS recipient ON recipient.scope = ? AND recipient.scope_key = actual.scope_key
		WHERE recipient.scope_key IS NULL
	)`, pendingScopeRecipient, pendingScopeRecipient).Scan(&recipientDrift); err != nil {
		return errors.New("pending capacity counters are unavailable")
	}
	if recipientDrift {
		return errors.New("pending capacity counters are inconsistent")
	}
	return nil
}

// ReconcilePendingCapacity rebuilds explicit counters from pending deliveries.
func (s *Store) ReconcilePendingCapacity() error {
	if err := s.backfillPendingCapacity(context.Background()); err != nil {
		return err
	}
	if err := s.VerifyPendingCapacity(); err != nil {
		return err
	}
	s.refreshPendingMetrics(s.db)
	return nil
}

// ReconcilePendingCapacityFile rebuilds pending-capacity counters for one SQLite file.
func ReconcilePendingCapacityFile(database string) error {
	store, err := openStore(database, false)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()
	return store.ReconcilePendingCapacity()
}
