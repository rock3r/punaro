package postgres

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"time"

	"github.com/rock3r/punaro/internal/relay"
)

const (
	pendingScopeInstallation = "installation"
	pendingScopeRecipient    = "recipient"
	pendingInstallationKey   = ""
)

// SetPendingCapacity replaces the in-process pending-delivery ceilings.
// Durable counters remain in the store; this does not reset occupancy.
func (d *Database) SetPendingCapacity(cfg relay.PendingCapacityConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	d.capacityMu.Lock()
	d.capacity = cfg
	d.capacityMu.Unlock()
	return nil
}

func (d *Database) pendingCapacityConfig() relay.PendingCapacityConfig {
	d.capacityMu.Lock()
	defer d.capacityMu.Unlock()
	if d.capacity == (relay.PendingCapacityConfig{}) {
		return relay.DefaultPendingCapacityConfig()
	}
	return d.capacity
}

func (d *Database) reservePendingCapacity(tx *sql.Tx, recipients []string, bodyBytes int64) error {
	if len(recipients) == 0 {
		return nil
	}
	if bodyBytes < 0 {
		return errors.New("invalid pending body size")
	}
	charges := postgresGroupedPendingCharges(recipients, bodyBytes)
	cfg := d.pendingCapacityConfig()
	if err := postgresLockPendingCapacity(tx, charges); err != nil {
		return err
	}
	if err := postgresEnsurePendingCapacityRow(tx, pendingScopeInstallation, pendingInstallationKey); err != nil {
		return err
	}
	keys := make([]string, 0, len(charges))
	for recipient := range charges {
		keys = append(keys, recipient)
	}
	sort.Strings(keys)
	current := make(map[string]struct{ Count, Bytes int64 }, len(keys))
	for _, recipient := range keys {
		if err := postgresEnsurePendingCapacityRow(tx, pendingScopeRecipient, recipient); err != nil {
			return err
		}
		count, bytes, err := postgresReadPendingCapacityRow(tx, pendingScopeRecipient, recipient)
		if err != nil {
			return err
		}
		current[recipient] = struct{ Count, Bytes int64 }{Count: count, Bytes: bytes}
	}
	installationCount, installationBytes, err := postgresReadPendingCapacityRow(tx, pendingScopeInstallation, pendingInstallationKey)
	if err != nil {
		return err
	}
	chargeList := make([]relay.PendingCharge, 0, len(keys))
	for _, recipient := range keys {
		chargeList = append(chargeList, charges[recipient])
	}
	decision := relay.DecidePendingCapacity(cfg, installationCount, installationBytes, current, chargeList)
	if !decision.Allowed {
		d.metrics.ObserveCapacityRejected()
		return &relay.CapacityError{RetryAfterSeconds: decision.RetryAfterSeconds}
	}
	for _, recipient := range keys {
		charge := charges[recipient]
		if err := postgresAdjustPendingCapacityRow(tx, pendingScopeRecipient, recipient, charge.Count, charge.Bytes); err != nil {
			return err
		}
	}
	var addCount, addBytes int64
	for _, charge := range chargeList {
		addCount += charge.Count
		addBytes += charge.Bytes
	}
	return postgresAdjustPendingCapacityRow(tx, pendingScopeInstallation, pendingInstallationKey, addCount, addBytes)
}

func postgresLockPendingCapacity(tx *sql.Tx, charges map[string]relay.PendingCharge) error {
	if _, err := tx.ExecContext(context.Background(), `SELECT pg_advisory_xact_lock(hashtextextended('capacity-installation', 579001230615))`); err != nil {
		return errors.New("installation capacity lock is unavailable")
	}
	keys := make([]string, 0, len(charges))
	for recipient := range charges {
		keys = append(keys, recipient)
	}
	sort.Strings(keys)
	for _, recipient := range keys {
		if _, err := tx.ExecContext(context.Background(), `SELECT pg_advisory_xact_lock(hashtextextended(jsonb_build_array('capacity-recipient',$1::text)::text, 579001230616))`, recipient); err != nil {
			return errors.New("recipient capacity lock is unavailable")
		}
	}
	return nil
}

func postgresGroupedPendingCharges(recipients []string, bodyBytes int64) map[string]relay.PendingCharge {
	charges := make(map[string]relay.PendingCharge, len(recipients))
	for _, recipient := range recipients {
		charge := charges[recipient]
		charge.Recipient = recipient
		charge.Count++
		charge.Bytes += bodyBytes
		charges[recipient] = charge
	}
	return charges
}

func postgresEnsurePendingCapacityRow(tx *sql.Tx, scope, key string) error {
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_pending_capacity(scope,scope_key,pending_count,pending_bytes) VALUES ($1,$2,0,0) ON CONFLICT (scope, scope_key) DO NOTHING`, scope, key); err != nil {
		return errors.New("pending capacity initialize is unavailable")
	}
	return nil
}

func postgresReadPendingCapacityRow(tx *sql.Tx, scope, key string) (int64, int64, error) {
	var count, bytes int64
	if err := tx.QueryRowContext(context.Background(), `SELECT pending_count,pending_bytes FROM relay.mail_pending_capacity WHERE scope=$1 AND scope_key=$2 FOR UPDATE`, scope, key).Scan(&count, &bytes); err != nil {
		return 0, 0, errors.New("pending capacity read is unavailable")
	}
	return count, bytes, nil
}

func postgresAdjustPendingCapacityRow(tx *sql.Tx, scope, key string, deltaCount, deltaBytes int64) error {
	result, err := tx.ExecContext(context.Background(), `UPDATE relay.mail_pending_capacity SET pending_count=pending_count+$1,pending_bytes=pending_bytes+$2 WHERE scope=$3 AND scope_key=$4 AND pending_count+$1>=0 AND pending_bytes+$2>=0`, deltaCount, deltaBytes, scope, key)
	if err != nil {
		return errors.New("pending capacity update is unavailable")
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return errors.New("pending capacity update is unavailable")
	}
	if affected != 1 {
		return errors.New("pending capacity counter would underflow")
	}
	return nil
}

func postgresReleasePendingCharges(tx *sql.Tx, charges []relay.PendingCharge) error {
	if len(charges) == 0 {
		return nil
	}
	grouped := map[string]relay.PendingCharge{}
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
	if err := postgresLockPendingCapacity(tx, grouped); err != nil {
		return err
	}
	keys := make([]string, 0, len(grouped))
	for recipient := range grouped {
		keys = append(keys, recipient)
	}
	sort.Strings(keys)
	for _, recipient := range keys {
		charge := grouped[recipient]
		if err := postgresAdjustPendingCapacityRow(tx, pendingScopeRecipient, recipient, -charge.Count, -charge.Bytes); err != nil {
			return err
		}
	}
	return postgresAdjustPendingCapacityRow(tx, pendingScopeInstallation, pendingInstallationKey, -addCount, -addBytes)
}

func postgresRetirePendingDeliveries(tx *sql.Tx, recipient, conversationID string, now time.Time) error {
	rows, err := tx.QueryContext(context.Background(), `SELECT octet_length(message.body)
		FROM relay.mail_deliveries AS delivery JOIN relay.mail_messages AS message ON message.id=delivery.message_id
		WHERE delivery.recipient_endpoint=$1 AND delivery.acked_at IS NULL AND message.conversation_id=$2::uuid
		FOR UPDATE OF delivery`, recipient, conversationID)
	if err != nil {
		return errors.New("revoked pending deliveries are unavailable")
	}
	var charges []relay.PendingCharge
	for rows.Next() {
		var bodyBytes int64
		if err := rows.Scan(&bodyBytes); err != nil {
			_ = rows.Close()
			return errors.New("revoked pending deliveries are unavailable")
		}
		charges = append(charges, relay.PendingCharge{Recipient: recipient, Count: 1, Bytes: bodyBytes})
	}
	if err := rows.Close(); err != nil {
		return errors.New("revoked pending deliveries are unavailable")
	}
	if err := rows.Err(); err != nil {
		return errors.New("revoked pending deliveries are unavailable")
	}
	if _, err := tx.ExecContext(context.Background(), `UPDATE relay.mail_deliveries SET acked_at=$3 WHERE recipient_endpoint=$1 AND acked_at IS NULL AND message_id IN (SELECT id FROM relay.mail_messages WHERE conversation_id=$2::uuid)`, recipient, conversationID, now.UTC()); err != nil {
		return relayDatabaseError(err, "retire revoked deliveries")
	}
	if len(charges) == 0 {
		return nil
	}
	return postgresReleasePendingCharges(tx, charges)
}

func postgresPendingDeliveryCharge(tx *sql.Tx, deliveryID string) (relay.PendingCharge, error) {
	var charge relay.PendingCharge
	if err := tx.QueryRowContext(context.Background(), `SELECT delivery.recipient_endpoint,octet_length(message.body)
		FROM relay.mail_deliveries AS delivery JOIN relay.mail_messages AS message ON message.id=delivery.message_id
		WHERE delivery.id=$1::uuid`, deliveryID).Scan(&charge.Recipient, &charge.Bytes); err != nil {
		return relay.PendingCharge{}, errors.New("delivery capacity charge is unavailable")
	}
	charge.Count = 1
	return charge, nil
}

func postgresDeliveryTargets(tx *sql.Tx, conversationID, fromEndpoint, targetRole string, rolesAvailable bool) ([]string, error) {
	var targets []string
	if targetRole == "" {
		rows, err := tx.QueryContext(context.Background(), `SELECT endpoint FROM relay.mail_memberships WHERE conversation_id=$1::uuid AND (capabilities & $2)<>0 AND endpoint<>$3`, conversationID, relay.CapReceive, fromEndpoint)
		if err != nil {
			return nil, errors.New("message recipients are unavailable")
		}
		for rows.Next() {
			var endpoint string
			if err := rows.Scan(&endpoint); err != nil {
				_ = rows.Close()
				return nil, errors.New("message recipients are unavailable")
			}
			targets = append(targets, endpoint)
		}
		if err := rows.Close(); err != nil || rows.Err() != nil {
			return nil, errors.New("message recipients are unavailable")
		}
	}
	if !rolesAvailable {
		return targets, nil
	}
	rows, err := tx.QueryContext(context.Background(), `SELECT chr(30)||'role:'||membership.role FROM relay.mail_role_memberships AS membership WHERE membership.conversation_id=$1::uuid AND (membership.capabilities & $2)<>0 AND ($3='' OR membership.role=$3)`, conversationID, relay.CapReceive, targetRole)
	if err != nil {
		return nil, errors.New("durable role recipients are unavailable")
	}
	for rows.Next() {
		var recipient string
		if err := rows.Scan(&recipient); err != nil {
			_ = rows.Close()
			return nil, errors.New("durable role recipients are unavailable")
		}
		targets = append(targets, recipient)
	}
	if err := rows.Close(); err != nil || rows.Err() != nil {
		return nil, errors.New("durable role recipients are unavailable")
	}
	return targets, nil
}

func (d *Database) refreshPendingMetrics(q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) {
	count, bytes, err := postgresInstallationPendingTotals(q)
	if err != nil {
		return
	}
	d.metrics.SetPendingGauges(count, bytes)
}

func postgresInstallationPendingTotals(q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (int64, int64, error) {
	var count, bytes int64
	err := q.QueryRowContext(context.Background(), `SELECT pending_count,pending_bytes FROM relay.mail_pending_capacity WHERE scope=$1 AND scope_key=$2`, pendingScopeInstallation, pendingInstallationKey).Scan(&count, &bytes)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	return count, bytes, nil
}

func (d *Database) ensurePendingCapacityReady() error {
	var initialized bool
	if err := d.relayPool().QueryRowContext(context.Background(), `SELECT EXISTS(SELECT 1 FROM relay.mail_pending_capacity WHERE scope=$1 AND scope_key=$2)`, pendingScopeInstallation, pendingInstallationKey).Scan(&initialized); err != nil {
		return errors.New("pending capacity counters are unavailable")
	}
	if initialized {
		return d.VerifyPendingCapacity()
	}
	var actualCount int64
	if err := d.relayPool().QueryRowContext(context.Background(), `SELECT COUNT(*) FROM relay.mail_deliveries WHERE acked_at IS NULL`).Scan(&actualCount); err != nil {
		return errors.New("pending capacity table is unavailable")
	}
	if actualCount == 0 {
		return nil
	}
	return d.ReconcilePendingCapacity()
}

// VerifyPendingCapacity reports whether explicit counters match pending deliveries.
func (d *Database) VerifyPendingCapacity() error {
	var actualCount, actualBytes, counterCount, counterBytes int64
	if err := d.relayPool().QueryRowContext(context.Background(), `SELECT COUNT(*), COALESCE(SUM(octet_length(message.body)), 0)
		FROM relay.mail_deliveries AS delivery JOIN relay.mail_messages AS message ON message.id=delivery.message_id
		WHERE delivery.acked_at IS NULL`).Scan(&actualCount, &actualBytes); err != nil {
		return errors.New("pending capacity table is unavailable")
	}
	err := d.relayPool().QueryRowContext(context.Background(), `SELECT pending_count,pending_bytes FROM relay.mail_pending_capacity WHERE scope=$1 AND scope_key=$2`, pendingScopeInstallation, pendingInstallationKey).Scan(&counterCount, &counterBytes)
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
	if err := d.relayPool().QueryRowContext(context.Background(), `SELECT EXISTS (
		SELECT recipient.scope_key FROM relay.mail_pending_capacity AS recipient
		LEFT JOIN (
			SELECT delivery.recipient_endpoint AS scope_key, COUNT(*) AS pending_count, COALESCE(SUM(octet_length(message.body)), 0) AS pending_bytes
			FROM relay.mail_deliveries AS delivery JOIN relay.mail_messages AS message ON message.id=delivery.message_id
			WHERE delivery.acked_at IS NULL
			GROUP BY delivery.recipient_endpoint
		) AS actual ON actual.scope_key=recipient.scope_key
		WHERE recipient.scope=$1
		  AND (COALESCE(actual.pending_count, 0) != recipient.pending_count OR COALESCE(actual.pending_bytes, 0) != recipient.pending_bytes)
	) OR EXISTS (
		SELECT actual.scope_key FROM (
			SELECT delivery.recipient_endpoint AS scope_key
			FROM relay.mail_deliveries AS delivery
			WHERE delivery.acked_at IS NULL
			GROUP BY delivery.recipient_endpoint
		) AS actual
		LEFT JOIN relay.mail_pending_capacity AS recipient ON recipient.scope=$1 AND recipient.scope_key=actual.scope_key
		WHERE recipient.scope_key IS NULL
	)`, pendingScopeRecipient).Scan(&recipientDrift); err != nil {
		return errors.New("pending capacity counters are unavailable")
	}
	if recipientDrift {
		return errors.New("pending capacity counters are inconsistent")
	}
	d.refreshPendingMetrics(d.relayPool())
	return nil
}

// ReconcilePendingCapacity rebuilds explicit counters from pending deliveries.
func (d *Database) ReconcilePendingCapacity() error {
	tx, cancel, err := d.beginRelayTransaction(nil)
	if err != nil {
		return errors.New("pending capacity reconciliation cannot start")
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(context.Background(), `SELECT pg_advisory_xact_lock(hashtextextended('capacity-installation', 579001230615))`); err != nil {
		return errors.New("installation capacity lock is unavailable")
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_pending_capacity(scope,scope_key,pending_count,pending_bytes)
		SELECT $1,$2,COUNT(*),COALESCE(SUM(octet_length(message.body)),0)
		FROM relay.mail_deliveries AS delivery JOIN relay.mail_messages AS message ON message.id=delivery.message_id
		WHERE delivery.acked_at IS NULL
		ON CONFLICT (scope, scope_key) DO UPDATE SET pending_count=EXCLUDED.pending_count, pending_bytes=EXCLUDED.pending_bytes`, pendingScopeInstallation, pendingInstallationKey); err != nil {
		return errors.New("pending capacity installation rebuild is unavailable")
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_pending_capacity(scope,scope_key,pending_count,pending_bytes)
		SELECT $1,delivery.recipient_endpoint,COUNT(*),COALESCE(SUM(octet_length(message.body)),0)
		FROM relay.mail_deliveries AS delivery JOIN relay.mail_messages AS message ON message.id=delivery.message_id
		WHERE delivery.acked_at IS NULL
		GROUP BY delivery.recipient_endpoint
		ON CONFLICT (scope, scope_key) DO UPDATE SET pending_count=EXCLUDED.pending_count, pending_bytes=EXCLUDED.pending_bytes`, pendingScopeRecipient); err != nil {
		return errors.New("pending capacity recipient rebuild is unavailable")
	}
	if _, err := tx.ExecContext(context.Background(), `UPDATE relay.mail_pending_capacity AS recipient SET pending_count=0,pending_bytes=0
		WHERE recipient.scope=$1 AND NOT EXISTS (
			SELECT 1 FROM relay.mail_deliveries AS delivery
			WHERE delivery.acked_at IS NULL AND delivery.recipient_endpoint=recipient.scope_key
		)`, pendingScopeRecipient); err != nil {
		return errors.New("pending capacity leftover reset is unavailable")
	}
	if err := tx.Commit(); err != nil {
		return errors.New("pending capacity reconciliation cannot commit")
	}
	return d.VerifyPendingCapacity()
}
