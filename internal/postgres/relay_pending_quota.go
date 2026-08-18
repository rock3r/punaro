package postgres

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"time"

	"github.com/rock3r/punaro/internal/relay"
)

const postgresPendingBodyBytes = "octet_length(message.body)"

// SetQuotaLimits replaces the in-process pending-delivery ceilings.
func (d *Database) SetQuotaLimits(cfg relay.QuotaConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	d.quotaMu.Lock()
	d.quota = cfg
	d.quotaMu.Unlock()
	return nil
}

func (d *Database) quotaConfig() relay.QuotaConfig {
	d.quotaMu.Lock()
	defer d.quotaMu.Unlock()
	if d.quota == (relay.QuotaConfig{}) {
		return relay.DefaultQuotaConfig()
	}
	return d.quota
}

func (d *Database) consumeQuota(tx *sql.Tx, recipients []string, bodyBytes int64) error {
	if len(recipients) == 0 {
		return nil
	}
	cfg := d.quotaConfig()
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_pending_install(singleton,pending_count,pending_bytes) VALUES (1,0,0) ON CONFLICT (singleton) DO NOTHING`); err != nil {
		return errors.New("installation quota initialize is unavailable")
	}
	var install relay.QuotaCounters
	if err := tx.QueryRowContext(context.Background(), `SELECT pending_count,pending_bytes FROM relay.mail_pending_install WHERE singleton=1 FOR UPDATE`).Scan(&install.Count, &install.Bytes); err != nil {
		return errors.New("installation quota read is unavailable")
	}
	current := make(map[string]relay.QuotaCounters, len(recipients))
	charges := make([]relay.QuotaCharge, 0, len(recipients))
	for _, recipient := range recipients {
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_pending_recipients(recipient_endpoint,pending_count,pending_bytes) VALUES ($1,0,0) ON CONFLICT (recipient_endpoint) DO NOTHING`, recipient); err != nil {
			return errors.New("recipient quota initialize is unavailable")
		}
		var counters relay.QuotaCounters
		if err := tx.QueryRowContext(context.Background(), `SELECT pending_count,pending_bytes FROM relay.mail_pending_recipients WHERE recipient_endpoint=$1 FOR UPDATE`, recipient).Scan(&counters.Count, &counters.Bytes); err != nil {
			return errors.New("recipient quota read is unavailable")
		}
		current[recipient] = counters
		charges = append(charges, relay.QuotaCharge{Recipient: recipient, Bytes: bodyBytes})
	}
	decision := relay.DecideQuota(cfg, current, install, charges)
	if !decision.Allowed {
		d.metrics.ObserveCapacityExceeded()
		return &relay.CapacityError{RetryAfterSeconds: decision.RetryAfterSeconds}
	}
	for _, recipient := range recipients {
		if _, err := tx.ExecContext(context.Background(), `UPDATE relay.mail_pending_recipients SET pending_count=pending_count+1,pending_bytes=pending_bytes+$1 WHERE recipient_endpoint=$2`, bodyBytes, recipient); err != nil {
			return errors.New("recipient quota reserve is unavailable")
		}
	}
	if _, err := tx.ExecContext(context.Background(), `UPDATE relay.mail_pending_install SET pending_count=pending_count+$1,pending_bytes=pending_bytes+$2 WHERE singleton=1`, int64(len(recipients)), bodyBytes*int64(len(recipients))); err != nil {
		return errors.New("installation quota reserve is unavailable")
	}
	return nil
}

func postgresReleaseQuota(tx *sql.Tx, recipient string, bodyBytes int64) error {
	if recipient == "" || bodyBytes < 0 {
		return errors.New("quota release is invalid")
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_pending_install(singleton,pending_count,pending_bytes) VALUES (1,0,0) ON CONFLICT (singleton) DO NOTHING`); err != nil {
		return errors.New("installation quota initialize is unavailable")
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_pending_recipients(recipient_endpoint,pending_count,pending_bytes) VALUES ($1,0,0) ON CONFLICT (recipient_endpoint) DO NOTHING`, recipient); err != nil {
		return errors.New("recipient quota initialize is unavailable")
	}
	if _, err := tx.ExecContext(context.Background(), `SELECT pending_count FROM relay.mail_pending_install WHERE singleton=1 FOR UPDATE`); err != nil {
		return errors.New("installation quota lock is unavailable")
	}
	if _, err := tx.ExecContext(context.Background(), `SELECT pending_count FROM relay.mail_pending_recipients WHERE recipient_endpoint=$1 FOR UPDATE`, recipient); err != nil {
		return errors.New("recipient quota lock is unavailable")
	}
	result, err := tx.ExecContext(context.Background(), `UPDATE relay.mail_pending_recipients SET pending_count=pending_count-1,pending_bytes=pending_bytes-$1
		WHERE recipient_endpoint=$2 AND pending_count>=1 AND pending_bytes>=$1`, bodyBytes, recipient)
	if err != nil {
		return errors.New("recipient quota release is unavailable")
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return errors.New("relay pending quota is inconsistent")
	}
	result, err = tx.ExecContext(context.Background(), `UPDATE relay.mail_pending_install SET pending_count=pending_count-1,pending_bytes=pending_bytes-$1
		WHERE singleton=1 AND pending_count>=1 AND pending_bytes>=$1`, bodyBytes)
	if err != nil {
		return errors.New("installation quota release is unavailable")
	}
	affected, err = result.RowsAffected()
	if err != nil || affected != 1 {
		return errors.New("relay pending quota is inconsistent")
	}
	return nil
}

func postgresAppendDeliveryRecipients(tx *sql.Tx, conversationID, fromEndpoint, targetRole string, rolesAvailable bool) ([]string, error) {
	var recipients []string
	if targetRole == "" {
		rows, err := tx.QueryContext(context.Background(), `SELECT endpoint FROM relay.mail_memberships WHERE conversation_id=$1::uuid AND (capabilities & $2) <> 0 AND endpoint<>$3 ORDER BY endpoint`, conversationID, relay.CapReceive, fromEndpoint)
		if err != nil {
			return nil, errors.New("recipient list is unavailable")
		}
		for rows.Next() {
			var endpoint string
			if err := rows.Scan(&endpoint); err != nil {
				_ = rows.Close()
				return nil, errors.New("recipient list is unavailable")
			}
			recipients = append(recipients, endpoint)
		}
		if err := rows.Close(); err != nil || rows.Err() != nil {
			return nil, errors.New("recipient list is unavailable")
		}
	}
	if rolesAvailable {
		rows, err := tx.QueryContext(context.Background(), `SELECT membership.role FROM relay.mail_role_memberships AS membership
			WHERE membership.conversation_id=$1::uuid AND (membership.capabilities & $2) <> 0 AND ($3='' OR membership.role=$3) ORDER BY membership.role`, conversationID, relay.CapReceive, targetRole)
		if err != nil {
			return nil, errors.New("durable role recipient list is unavailable")
		}
		for rows.Next() {
			var role string
			if err := rows.Scan(&role); err != nil {
				_ = rows.Close()
				return nil, errors.New("durable role recipient list is unavailable")
			}
			recipients = append(recipients, string([]byte{0x1e})+"role:"+role)
		}
		if err := rows.Close(); err != nil || rows.Err() != nil {
			return nil, errors.New("durable role recipient list is unavailable")
		}
	}
	sort.Strings(recipients)
	return recipients, nil
}

func postgresRetireConversationDeliveries(tx *sql.Tx, recipient, conversationID string, ackedAt time.Time) (int, error) {
	rows, err := tx.QueryContext(context.Background(), `SELECT delivery.id::text, `+postgresPendingBodyBytes+`
		FROM relay.mail_deliveries AS delivery JOIN relay.mail_messages AS message ON message.id=delivery.message_id
		WHERE delivery.recipient_endpoint=$1 AND delivery.acked_at IS NULL AND message.conversation_id=$2::uuid
		FOR UPDATE OF delivery`, recipient, conversationID)
	if err != nil {
		return 0, errors.New("revoked deliveries cannot be inspected")
	}
	type pending struct {
		id    string
		bytes int64
	}
	var retired []pending
	for rows.Next() {
		var row pending
		if err := rows.Scan(&row.id, &row.bytes); err != nil {
			_ = rows.Close()
			return 0, errors.New("revoked deliveries cannot be inspected")
		}
		retired = append(retired, row)
	}
	if err := rows.Close(); err != nil || rows.Err() != nil {
		return 0, errors.New("revoked deliveries cannot be inspected")
	}
	for _, row := range retired {
		if err := postgresReleaseQuota(tx, recipient, row.bytes); err != nil {
			return 0, err
		}
		if err := postgresRecordDeliveryTerminal(tx, row.id, relay.ClosedReasonRevoked, ackedAt); err != nil {
			return 0, err
		}
	}
	if _, err := tx.ExecContext(context.Background(), `UPDATE relay.mail_deliveries SET acked_at=$3 WHERE recipient_endpoint=$1 AND acked_at IS NULL AND message_id IN (SELECT id FROM relay.mail_messages WHERE conversation_id=$2::uuid)`, recipient, conversationID, ackedAt); err != nil {
		return 0, relayDatabaseError(err, "retire revoked deliveries")
	}
	return len(retired), nil
}

func (d *Database) refreshPendingMetrics(ctx context.Context) {
	d.pendingMetricsMu.Lock()
	defer d.pendingMetricsMu.Unlock()
	counters, err := postgresReadInstallQuota(ctx, d.relayPool())
	if err != nil {
		return
	}
	d.metrics.SetPending(counters.Count, counters.Bytes)
}

func postgresReadInstallQuota(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (relay.QuotaCounters, error) {
	var counters relay.QuotaCounters
	err := q.QueryRowContext(ctx, `SELECT pending_count,pending_bytes FROM relay.mail_pending_install WHERE singleton=1`).Scan(&counters.Count, &counters.Bytes)
	if errors.Is(err, sql.ErrNoRows) {
		return relay.QuotaCounters{}, nil
	}
	return counters, err
}

// VerifyPendingQuota fails closed when explicit counters disagree with pending deliveries.
func (d *Database) VerifyPendingQuota(ctx context.Context) error {
	tx, cancel, err := d.beginRelayTransaction(&sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return errors.New("pending quota verification cannot start")
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()
	return verifyPostgresPendingQuota(ctx, tx)
}

func verifyPostgresPendingQuota(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) error {
	var actualCount, actualBytes int64
	if err := q.QueryRowContext(ctx, `SELECT count(*), COALESCE(sum(`+postgresPendingBodyBytes+`),0)
		FROM relay.mail_deliveries AS delivery JOIN relay.mail_messages AS message ON message.id=delivery.message_id
		WHERE delivery.acked_at IS NULL`).Scan(&actualCount, &actualBytes); err != nil {
		return errors.New("pending deliveries cannot be measured")
	}
	install, err := postgresReadInstallQuota(ctx, q)
	if err != nil {
		return errors.New("installation quota cannot be read")
	}
	if install != (relay.QuotaCounters{Count: actualCount, Bytes: actualBytes}) {
		return errors.New("relay pending quota is inconsistent")
	}
	rows, err := q.QueryContext(ctx, `SELECT delivery.recipient_endpoint, count(*), COALESCE(sum(`+postgresPendingBodyBytes+`),0)
		FROM relay.mail_deliveries AS delivery JOIN relay.mail_messages AS message ON message.id=delivery.message_id
		WHERE delivery.acked_at IS NULL
		GROUP BY delivery.recipient_endpoint`)
	if err != nil {
		return errors.New("recipient pending deliveries cannot be measured")
	}
	defer func() { _ = rows.Close() }()
	actual := make(map[string]relay.QuotaCounters)
	var summed relay.QuotaCounters
	for rows.Next() {
		var recipient string
		var counters relay.QuotaCounters
		if err := rows.Scan(&recipient, &counters.Count, &counters.Bytes); err != nil {
			return errors.New("recipient pending deliveries cannot be measured")
		}
		actual[recipient] = counters
		summed.Count += counters.Count
		summed.Bytes += counters.Bytes
	}
	if err := rows.Err(); err != nil || summed != install {
		return errors.New("relay pending quota is inconsistent")
	}
	counterRows, err := q.QueryContext(ctx, `SELECT recipient_endpoint,pending_count,pending_bytes FROM relay.mail_pending_recipients`)
	if err != nil {
		return errors.New("recipient quota cannot be read")
	}
	defer func() { _ = counterRows.Close() }()
	seen := make(map[string]struct{}, len(actual))
	for counterRows.Next() {
		var recipient string
		var counters relay.QuotaCounters
		if err := counterRows.Scan(&recipient, &counters.Count, &counters.Bytes); err != nil {
			return errors.New("recipient quota cannot be read")
		}
		if counters != actual[recipient] {
			return errors.New("relay pending quota is inconsistent")
		}
		seen[recipient] = struct{}{}
	}
	if err := counterRows.Err(); err != nil {
		return errors.New("recipient quota cannot be read")
	}
	for recipient := range actual {
		if _, ok := seen[recipient]; !ok {
			return errors.New("relay pending quota is inconsistent")
		}
	}
	return nil
}

// ReconcilePendingQuota rebuilds explicit counters from pending deliveries.
func (d *Database) ReconcilePendingQuota(ctx context.Context) (relay.QuotaCounters, error) {
	tx, cancel, err := d.beginRelayTransaction(nil)
	if err != nil {
		return relay.QuotaCounters{}, errors.New("pending quota reconciliation cannot start")
	}
	defer cancel()
	defer func() { _ = tx.Rollback() }()
	if err := postgresRebuildPendingQuota(tx); err != nil {
		return relay.QuotaCounters{}, err
	}
	install, err := postgresReadInstallQuota(ctx, tx)
	if err != nil {
		return relay.QuotaCounters{}, errors.New("installation quota cannot be read")
	}
	if err := tx.Commit(); err != nil {
		return relay.QuotaCounters{}, errors.New("pending quota reconciliation cannot commit")
	}
	d.refreshDeliveryMetrics(ctx, time.Now().UTC())
	return install, nil
}

func postgresRebuildPendingQuota(tx *sql.Tx) error {
	if _, err := tx.ExecContext(context.Background(), `DELETE FROM relay.mail_pending_recipients`); err != nil {
		return errors.New("recipient quota cannot be cleared")
	}
	if _, err := tx.ExecContext(context.Background(), `DELETE FROM relay.mail_pending_install`); err != nil {
		return errors.New("installation quota cannot be cleared")
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_pending_recipients(recipient_endpoint,pending_count,pending_bytes)
		SELECT delivery.recipient_endpoint, count(*), COALESCE(sum(`+postgresPendingBodyBytes+`),0)
		FROM relay.mail_deliveries AS delivery JOIN relay.mail_messages AS message ON message.id=delivery.message_id
		WHERE delivery.acked_at IS NULL
		GROUP BY delivery.recipient_endpoint`); err != nil {
		return errors.New("recipient quota cannot be rebuilt")
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO relay.mail_pending_install(singleton,pending_count,pending_bytes)
		SELECT 1, counted, bytes FROM (
			SELECT count(*) AS counted, COALESCE(sum(`+postgresPendingBodyBytes+`),0) AS bytes
			FROM relay.mail_deliveries AS delivery JOIN relay.mail_messages AS message ON message.id=delivery.message_id
			WHERE delivery.acked_at IS NULL
		) AS pending
		WHERE counted > 0`); err != nil {
		return errors.New("installation quota cannot be rebuilt")
	}
	return nil
}
