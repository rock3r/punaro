package relay

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"
)

const sqlitePendingBodyBytes = "length(CAST(message.body AS BLOB))"

func (s *Store) bootstrapPendingQuota(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO pending_quota_install(singleton, pending_count, pending_bytes)
		SELECT 1, counted, bytes FROM (
			SELECT COUNT(*) AS counted, COALESCE(SUM(`+sqlitePendingBodyBytes+`), 0) AS bytes
			FROM deliveries AS delivery JOIN messages AS message ON message.id = delivery.message_id
			WHERE delivery.acked_at IS NULL
		) WHERE counted > 0`); err != nil {
		return fmt.Errorf("bootstrap pending installation quota: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO pending_quota_recipients(recipient_endpoint, pending_count, pending_bytes)
		SELECT delivery.recipient_endpoint, COUNT(*), COALESCE(SUM(`+sqlitePendingBodyBytes+`), 0)
		FROM deliveries AS delivery JOIN messages AS message ON message.id = delivery.message_id
		WHERE delivery.acked_at IS NULL
		GROUP BY delivery.recipient_endpoint`); err != nil {
		return fmt.Errorf("bootstrap pending recipient quota: %w", err)
	}
	return nil
}

func appendDeliveryRecipients(tx *sql.Tx, conversationID, fromEndpoint, targetRole string) ([]string, error) {
	var recipients []string
	if targetRole == "" {
		rows, err := tx.QueryContext(context.Background(), "SELECT endpoint FROM memberships WHERE conversation_id = ? AND (capabilities & ?) != 0 AND endpoint != ?", conversationID, CapReceive, fromEndpoint)
		if err != nil {
			return nil, fmt.Errorf("find recipients: %w", err)
		}
		for rows.Next() {
			var endpoint string
			if err := rows.Scan(&endpoint); err != nil {
				_ = rows.Close()
				return nil, err
			}
			recipients = append(recipients, endpoint)
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	roleRows, err := tx.QueryContext(context.Background(), "SELECT role FROM role_memberships WHERE conversation_id = ? AND (capabilities & ?) != 0", conversationID, CapReceive)
	if err != nil {
		return nil, fmt.Errorf("find durable role recipients: %w", err)
	}
	for roleRows.Next() {
		var role string
		if err := roleRows.Scan(&role); err != nil {
			_ = roleRows.Close()
			return nil, err
		}
		if targetRole == "" || role == targetRole {
			recipients = append(recipients, roleRecipient(role))
		}
	}
	if err := roleRows.Close(); err != nil {
		return nil, fmt.Errorf("find durable role recipients: %w", err)
	}
	if err := roleRows.Err(); err != nil {
		return nil, err
	}
	sort.Strings(recipients)
	return recipients, nil
}

func (s *Store) consumeQuota(tx *sql.Tx, recipients []string, bodyBytes int64) error {
	if len(recipients) == 0 {
		return nil
	}
	cfg := s.quotaConfig()
	if _, err := tx.ExecContext(context.Background(), `INSERT OR IGNORE INTO pending_quota_install(singleton, pending_count, pending_bytes) VALUES (1, 0, 0)`); err != nil {
		return fmt.Errorf("initialize installation quota: %w", err)
	}
	var install QuotaCounters
	if err := tx.QueryRowContext(context.Background(), `SELECT pending_count, pending_bytes FROM pending_quota_install WHERE singleton = 1`).Scan(&install.Count, &install.Bytes); err != nil {
		return fmt.Errorf("read installation quota: %w", err)
	}
	current := make(map[string]QuotaCounters, len(recipients))
	charges := make([]QuotaCharge, 0, len(recipients))
	for _, recipient := range recipients {
		if _, err := tx.ExecContext(context.Background(), `INSERT OR IGNORE INTO pending_quota_recipients(recipient_endpoint, pending_count, pending_bytes) VALUES (?, 0, 0)`, recipient); err != nil {
			return fmt.Errorf("initialize recipient quota: %w", err)
		}
		var counters QuotaCounters
		if err := tx.QueryRowContext(context.Background(), `SELECT pending_count, pending_bytes FROM pending_quota_recipients WHERE recipient_endpoint = ?`, recipient).Scan(&counters.Count, &counters.Bytes); err != nil {
			return fmt.Errorf("read recipient quota: %w", err)
		}
		current[recipient] = counters
		charges = append(charges, QuotaCharge{Recipient: recipient, Bytes: bodyBytes})
	}
	decision := DecideQuota(cfg, current, install, charges)
	if !decision.Allowed {
		s.metrics.ObserveCapacityExceeded()
		return &CapacityError{RetryAfterSeconds: decision.RetryAfterSeconds}
	}
	for _, recipient := range recipients {
		if _, err := tx.ExecContext(context.Background(), `UPDATE pending_quota_recipients SET pending_count = pending_count + 1, pending_bytes = pending_bytes + ? WHERE recipient_endpoint = ?`, bodyBytes, recipient); err != nil {
			return fmt.Errorf("reserve recipient quota: %w", err)
		}
	}
	if _, err := tx.ExecContext(context.Background(), `UPDATE pending_quota_install SET pending_count = pending_count + ?, pending_bytes = pending_bytes + ? WHERE singleton = 1`, int64(len(recipients)), bodyBytes*int64(len(recipients))); err != nil {
		return fmt.Errorf("reserve installation quota: %w", err)
	}
	return nil
}

func releaseQuota(tx *sql.Tx, recipient string, bodyBytes int64) error {
	if recipient == "" || bodyBytes < 0 {
		return fmt.Errorf("invalid quota release")
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT OR IGNORE INTO pending_quota_install(singleton, pending_count, pending_bytes) VALUES (1, 0, 0)`); err != nil {
		return fmt.Errorf("initialize installation quota: %w", err)
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT OR IGNORE INTO pending_quota_recipients(recipient_endpoint, pending_count, pending_bytes) VALUES (?, 0, 0)`, recipient); err != nil {
		return fmt.Errorf("initialize recipient quota: %w", err)
	}
	result, err := tx.ExecContext(context.Background(), `UPDATE pending_quota_recipients SET pending_count = pending_count - 1, pending_bytes = pending_bytes - ?
		WHERE recipient_endpoint = ? AND pending_count >= 1 AND pending_bytes >= ?`, bodyBytes, recipient, bodyBytes)
	if err != nil {
		return fmt.Errorf("release recipient quota: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("release recipient quota: %w", err)
	}
	if affected != 1 {
		return errors.New("relay pending quota is inconsistent")
	}
	result, err = tx.ExecContext(context.Background(), `UPDATE pending_quota_install SET pending_count = pending_count - 1, pending_bytes = pending_bytes - ?
		WHERE singleton = 1 AND pending_count >= 1 AND pending_bytes >= ?`, bodyBytes, bodyBytes)
	if err != nil {
		return fmt.Errorf("release installation quota: %w", err)
	}
	affected, err = result.RowsAffected()
	if err != nil {
		return fmt.Errorf("release installation quota: %w", err)
	}
	if affected != 1 {
		return errors.New("relay pending quota is inconsistent")
	}
	return nil
}

func retireRecipientDeliveries(tx *sql.Tx, recipient, conversationID string, now time.Time) error {
	rows, err := tx.QueryContext(context.Background(), `SELECT delivery.id, `+sqlitePendingBodyBytes+`
		FROM deliveries AS delivery JOIN messages AS message ON message.id = delivery.message_id
		WHERE delivery.recipient_endpoint = ? AND delivery.acked_at IS NULL AND message.conversation_id = ?`, recipient, conversationID)
	if err != nil {
		return fmt.Errorf("find revoked deliveries: %w", err)
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
			return err
		}
		retired = append(retired, row)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, row := range retired {
		if err := releaseQuota(tx, recipient, row.bytes); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(context.Background(), "UPDATE deliveries SET acked_at=? WHERE recipient_endpoint=? AND acked_at IS NULL AND message_id IN (SELECT id FROM messages WHERE conversation_id=?)", now.UTC().UnixMilli(), recipient, conversationID); err != nil {
		return fmt.Errorf("retire revoked deliveries: %w", err)
	}
	return nil
}

func (s *Store) refreshPendingMetrics() {
	s.pendingMetricsMu.Lock()
	defer s.pendingMetricsMu.Unlock()
	counters, err := readInstallQuota(context.Background(), s.db)
	if err != nil {
		return
	}
	s.metrics.SetPending(counters.Count, counters.Bytes)
}

func readInstallQuota(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (QuotaCounters, error) {
	var counters QuotaCounters
	err := q.QueryRowContext(ctx, `SELECT pending_count, pending_bytes FROM pending_quota_install WHERE singleton = 1`).Scan(&counters.Count, &counters.Bytes)
	if errors.Is(err, sql.ErrNoRows) {
		return QuotaCounters{}, nil
	}
	return counters, err
}

// VerifyPendingQuota fails closed when explicit counters disagree with pending deliveries.
func (s *Store) VerifyPendingQuota() error {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if err := verifySQLitePendingQuota(context.Background(), tx); err != nil {
		return err
	}
	return tx.Rollback()
}

type quotaQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func verifySQLitePendingQuota(ctx context.Context, db quotaQueryer) error {
	var actualCount, actualBytes int64
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(`+sqlitePendingBodyBytes+`), 0)
		FROM deliveries AS delivery JOIN messages AS message ON message.id = delivery.message_id
		WHERE delivery.acked_at IS NULL`).Scan(&actualCount, &actualBytes); err != nil {
		return fmt.Errorf("measure pending deliveries: %w", err)
	}
	install, err := readInstallQuota(ctx, db)
	if err != nil {
		return fmt.Errorf("read installation quota: %w", err)
	}
	if install != (QuotaCounters{Count: actualCount, Bytes: actualBytes}) {
		return errors.New("relay pending quota is inconsistent")
	}
	rows, err := db.QueryContext(ctx, `SELECT delivery.recipient_endpoint, COUNT(*), COALESCE(SUM(`+sqlitePendingBodyBytes+`), 0)
		FROM deliveries AS delivery JOIN messages AS message ON message.id = delivery.message_id
		WHERE delivery.acked_at IS NULL
		GROUP BY delivery.recipient_endpoint`)
	if err != nil {
		return fmt.Errorf("measure recipient pending deliveries: %w", err)
	}
	defer func() { _ = rows.Close() }()
	actual := make(map[string]QuotaCounters)
	var summed QuotaCounters
	for rows.Next() {
		var recipient string
		var counters QuotaCounters
		if err := rows.Scan(&recipient, &counters.Count, &counters.Bytes); err != nil {
			return err
		}
		actual[recipient] = counters
		summed.Count += counters.Count
		summed.Bytes += counters.Bytes
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if summed != install {
		return errors.New("relay pending quota is inconsistent")
	}
	counterRows, err := db.QueryContext(ctx, `SELECT recipient_endpoint, pending_count, pending_bytes FROM pending_quota_recipients`)
	if err != nil {
		return fmt.Errorf("read recipient quota: %w", err)
	}
	defer func() { _ = counterRows.Close() }()
	seen := make(map[string]struct{}, len(actual))
	for counterRows.Next() {
		var recipient string
		var counters QuotaCounters
		if err := counterRows.Scan(&recipient, &counters.Count, &counters.Bytes); err != nil {
			return err
		}
		want := actual[recipient]
		if counters != want {
			return errors.New("relay pending quota is inconsistent")
		}
		seen[recipient] = struct{}{}
	}
	if err := counterRows.Err(); err != nil {
		return err
	}
	for recipient := range actual {
		if _, ok := seen[recipient]; !ok {
			return errors.New("relay pending quota is inconsistent")
		}
	}
	return nil
}

// ReconcilePendingQuota rebuilds explicit counters from pending deliveries.
func ReconcilePendingQuota(store *Store) (QuotaCounters, error) {
	if store == nil {
		return QuotaCounters{}, errors.New("relay store is required")
	}
	tx, err := store.db.BeginTx(context.Background(), nil)
	if err != nil {
		return QuotaCounters{}, err
	}
	defer rollback(tx)
	if _, err := tx.ExecContext(context.Background(), `DELETE FROM pending_quota_recipients`); err != nil {
		return QuotaCounters{}, fmt.Errorf("clear recipient quota: %w", err)
	}
	if _, err := tx.ExecContext(context.Background(), `DELETE FROM pending_quota_install`); err != nil {
		return QuotaCounters{}, fmt.Errorf("clear installation quota: %w", err)
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO pending_quota_recipients(recipient_endpoint, pending_count, pending_bytes)
		SELECT delivery.recipient_endpoint, COUNT(*), COALESCE(SUM(`+sqlitePendingBodyBytes+`), 0)
		FROM deliveries AS delivery JOIN messages AS message ON message.id = delivery.message_id
		WHERE delivery.acked_at IS NULL
		GROUP BY delivery.recipient_endpoint`); err != nil {
		return QuotaCounters{}, fmt.Errorf("rebuild recipient quota: %w", err)
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO pending_quota_install(singleton, pending_count, pending_bytes)
		SELECT 1, COUNT(*), COALESCE(SUM(`+sqlitePendingBodyBytes+`), 0)
		FROM deliveries AS delivery JOIN messages AS message ON message.id = delivery.message_id
		WHERE delivery.acked_at IS NULL`); err != nil {
		return QuotaCounters{}, fmt.Errorf("rebuild installation quota: %w", err)
	}
	install, err := readInstallQuota(context.Background(), tx)
	if err != nil {
		return QuotaCounters{}, err
	}
	if err := tx.Commit(); err != nil {
		return QuotaCounters{}, err
	}
	store.refreshPendingMetrics()
	return install, nil
}

func isOperationalQuotaTable(name string) bool {
	return name == "pending_quota_recipients" || name == "pending_quota_install"
}

func filterOperationalQuotaTables(names []string) []string {
	filtered := make([]string, 0, len(names))
	for _, name := range names {
		if isOperationalQuotaTable(name) {
			continue
		}
		filtered = append(filtered, name)
	}
	return filtered
}
