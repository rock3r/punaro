package relay

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"regexp"
	"strconv"
	"strings"
)

const maxMigrationBatchRows = 256

var migrationRowDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// MaxMigrationSourcePayloadBytes accounts for worst-case JSON escaping of a
// valid 32 KiB message body plus its bounded canonical metadata.
const MaxMigrationSourcePayloadBytes = 256 << 10

// MigrationSourceRow is one canonical, content-addressed SQLite relay row.
// Payload contains only the allowlisted logical columns from the source
// manifest; Key is an opaque resume cursor derived from the table primary key.
type MigrationSourceRow struct {
	Table   string          `json:"table"`
	Key     string          `json:"key"`
	Payload json.RawMessage `json:"payload"`
	SHA256  string          `json:"sha256"`
}

// MigrationSourceBatch is a bounded page from one prepared SQLite source.
type MigrationSourceBatch struct {
	Rows    []MigrationSourceRow `json:"rows"`
	NextKey string               `json:"next_key,omitempty"`
	Done    bool                 `json:"done"`
}

// MigrationTableHasher verifies exported rows and reproduces the exact
// per-table count and digest committed by MigrationSourceManifest.
type MigrationTableHasher struct {
	table   string
	columns []string
	hash    hash.Hash
	count   int64
}

// NewMigrationTableHasher creates a streaming verifier for one allowlisted
// destination table.
func NewMigrationTableHasher(table string) (*MigrationTableHasher, error) {
	for _, spec := range migrationBatchSpecs {
		if spec.target == table {
			return &MigrationTableHasher{table: table, columns: strings.Split(spec.source.columns, ","), hash: sha256.New()}, nil
		}
	}
	return nil, errors.New("invalid relay migration table")
}

// Add verifies one row envelope and adds its source values in manifest order.
func (h *MigrationTableHasher) Add(row MigrationSourceRow) error {
	if h == nil || h.hash == nil || row.Table != h.table || row.Key == "" || len(row.Key) > 4096 || len(row.Payload) == 0 || len(row.Payload) > MaxMigrationSourcePayloadBytes || !migrationRowDigestPattern.MatchString(row.SHA256) {
		return errors.New("invalid relay migration row")
	}
	digest := sha256.Sum256(row.Payload)
	if hex.EncodeToString(digest[:]) != row.SHA256 {
		return errors.New("relay migration row digest does not match")
	}
	decoder := json.NewDecoder(strings.NewReader(string(row.Payload)))
	decoder.UseNumber()
	var payload map[string]any
	if err := decoder.Decode(&payload); err != nil {
		return errors.New("relay migration row payload is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || len(payload) != len(h.columns) {
		return errors.New("relay migration row payload is invalid")
	}
	for _, column := range h.columns {
		value, ok := payload[column]
		if !ok {
			return errors.New("relay migration row payload is incomplete")
		}
		if number, ok := value.(json.Number); ok {
			integer, err := strconv.ParseInt(string(number), 10, 64)
			if err != nil {
				return errors.New("relay migration row number is invalid")
			}
			value = integer
		} else if value != nil {
			if _, ok := value.(string); !ok {
				return errors.New("relay migration row value is invalid")
			}
		}
		if err := writeMigrationHashValue(h.hash, value); err != nil {
			return err
		}
	}
	h.count++
	return nil
}

// Evidence returns the current exact row count and manifest-compatible digest.
func (h *MigrationTableHasher) Evidence() (int64, string) {
	if h == nil || h.hash == nil {
		return 0, ""
	}
	return h.count, hex.EncodeToString(h.hash.Sum(nil))
}

type migrationBatchSpec struct {
	target     string
	source     migrationTableSpec
	keyColumns []string
}

var migrationBatchSpecs = []migrationBatchSpec{
	{target: "mail_endpoints", source: migrationTableSpecs[0], keyColumns: []string{"endpoint"}},
	{target: "mail_conversations", source: migrationTableSpecs[1], keyColumns: []string{"id"}},
	{target: "mail_memberships", source: migrationTableSpecs[2], keyColumns: []string{"conversation_id", "endpoint"}},
	{target: "mail_messages", source: migrationTableSpecs[3], keyColumns: []string{"id"}},
	{target: "mail_deliveries", source: migrationTableSpecs[4], keyColumns: []string{"id"}},
	{target: "mail_recipient_cursors", source: migrationTableSpecs[5], keyColumns: []string{"recipient_endpoint", "conversation_id"}},
	{target: "mail_message_idempotency", source: migrationTableSpecs[6], keyColumns: []string{"machine_id", "key"}},
	{target: "mail_conversation_idempotency", source: migrationTableSpecs[7], keyColumns: []string{"machine_id", "key"}},
	{target: "mail_request_nonces", source: migrationTableSpecs[8], keyColumns: []string{"machine_id", "nonce"}},
}

// ReadMigrationSourceBatch reads one bounded page from the exact prepared
// snapshot. The caller must present the last returned key to resume; invented
// or stale cursors fail closed instead of skipping source rows.
func ReadMigrationSourceBatch(ctx context.Context, path, table, afterKey string, limit int) (MigrationSourceBatch, error) {
	if limit < 1 || limit > maxMigrationBatchRows {
		return MigrationSourceBatch{}, errors.New("invalid relay migration batch")
	}
	var spec *migrationBatchSpec
	for index := range migrationBatchSpecs {
		if migrationBatchSpecs[index].target == table {
			spec = &migrationBatchSpecs[index]
			break
		}
	}
	if spec == nil {
		return MigrationSourceBatch{}, errors.New("invalid relay migration batch")
	}
	db, err := openMigrationSourceDatabase(path, true)
	if err != nil {
		return MigrationSourceBatch{}, err
	}
	defer func() { _ = db.Close() }()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return MigrationSourceBatch{}, errors.New("relay migration batch snapshot cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	manifest, err := inspectMigrationSource(ctx, tx)
	if err != nil {
		return MigrationSourceBatch{}, err
	}
	if manifest.Phase != MigrationSourcePrepared {
		return MigrationSourceBatch{}, errors.New("relay migration source is not prepared")
	}
	var keyValues []any
	where := ""
	if afterKey != "" {
		parts := strings.Split(afterKey, "\x1f")
		if len(parts) != len(spec.keyColumns) {
			return MigrationSourceBatch{}, errors.New("relay migration resume key is invalid")
		}
		keyValues = make([]any, len(parts))
		predicates := make([]string, len(parts))
		placeholders := make([]string, len(parts))
		for index, part := range parts {
			if part == "" || strings.ContainsRune(part, 0) || strings.ContainsRune(part, '\x1f') {
				return MigrationSourceBatch{}, errors.New("relay migration resume key is invalid")
			}
			keyValues[index] = part
			predicates[index] = spec.keyColumns[index] + "=?"
			placeholders[index] = "?"
		}
		var present int
		// #nosec G201 -- identifiers come only from migrationBatchSpecs.
		exactQuery := fmt.Sprintf("SELECT 1 FROM %s WHERE %s LIMIT 1", spec.source.name, strings.Join(predicates, " AND "))
		if err := tx.QueryRowContext(ctx, exactQuery, keyValues...).Scan(&present); err != nil || present != 1 { // #nosec G202 -- fragments come only from migrationBatchSpecs.
			return MigrationSourceBatch{}, errors.New("relay migration resume key is unavailable")
		}
		if len(parts) == 1 {
			where = " WHERE " + spec.keyColumns[0] + ">?"
		} else {
			where = " WHERE (" + strings.Join(spec.keyColumns, ",") + ")>(" + strings.Join(placeholders, ",") + ")"
		}
	}
	// #nosec G201 -- fragments come only from migrationBatchSpecs.
	query := fmt.Sprintf("SELECT %s FROM %s%s ORDER BY %s LIMIT ?", spec.source.columns, spec.source.name, where, spec.source.order)
	arguments := make([]any, 0, len(keyValues)+1)
	arguments = append(arguments, keyValues...)
	arguments = append(arguments, limit+1)
	rows, err := tx.QueryContext(ctx, query, arguments...) // #nosec G202 -- fragments come only from migrationBatchSpecs.
	if err != nil {
		return MigrationSourceBatch{}, errors.New("relay migration batch rows are unavailable")
	}
	defer func() { _ = rows.Close() }()
	columns := strings.Split(spec.source.columns, ",")
	keyIndexes := make([]int, len(spec.keyColumns))
	for keyIndex, keyColumn := range spec.keyColumns {
		keyIndexes[keyIndex] = -1
		for columnIndex, column := range columns {
			if column == keyColumn {
				keyIndexes[keyIndex] = columnIndex
				break
			}
		}
		if keyIndexes[keyIndex] < 0 {
			return MigrationSourceBatch{}, errors.New("relay migration batch schema is invalid")
		}
	}
	batch := MigrationSourceBatch{Rows: make([]MigrationSourceRow, 0, limit), Done: true}
	for rows.Next() {
		values := make([]any, len(columns))
		destinations := make([]any, len(columns))
		for index := range values {
			destinations[index] = &values[index]
		}
		if err := rows.Scan(destinations...); err != nil {
			return MigrationSourceBatch{}, errors.New("relay migration batch row is malformed")
		}
		keyValues := make([]string, len(keyIndexes))
		for index, columnIndex := range keyIndexes {
			value, ok := values[columnIndex].(string)
			if !ok || value == "" || strings.ContainsRune(value, 0) || strings.ContainsRune(value, '\x1f') {
				return MigrationSourceBatch{}, errors.New("relay migration batch key is invalid")
			}
			keyValues[index] = value
		}
		key := encodeMigrationRowKey(keyValues)
		if len(key) == 0 || len(key) > 4096 {
			return MigrationSourceBatch{}, errors.New("relay migration batch key is invalid")
		}
		if len(batch.Rows) == limit {
			batch.Done = false
			break
		}
		payloadValues := make(map[string]any, len(columns))
		for index, column := range columns {
			payloadValues[column] = values[index]
		}
		payload, err := json.Marshal(payloadValues)
		if err != nil || len(payload) == 0 || len(payload) > MaxMigrationSourcePayloadBytes {
			return MigrationSourceBatch{}, errors.New("relay migration batch payload is invalid")
		}
		digest := sha256.Sum256(payload)
		batch.Rows = append(batch.Rows, MigrationSourceRow{Table: table, Key: key, Payload: payload, SHA256: hex.EncodeToString(digest[:])})
		batch.NextKey = key
	}
	if err := rows.Err(); err != nil {
		return MigrationSourceBatch{}, errors.New("relay migration batch rows are unavailable")
	}
	if err := tx.Commit(); err != nil {
		return MigrationSourceBatch{}, errors.New("relay migration batch snapshot cannot commit")
	}
	return batch, nil
}

// encodeMigrationRowKey preserves SQLite's binary string ordering. Source key
// columns reject control characters, so unit separator is an unambiguous tuple
// delimiter and the raw UTF-8 cursor remains within the 4096-byte bound.
func encodeMigrationRowKey(values []string) string {
	return strings.Join(values, "\x1f")
}
