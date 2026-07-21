package postgres

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rock3r/punaro/internal/relay"
)

type mailCutoverScannerFunc func(...any) error

func (f mailCutoverScannerFunc) Scan(destinations ...any) error { return f(destinations...) }

func TestScanMailCutoverPreservesManifestText(t *testing.T) {
	t.Parallel()
	const manifest = `{"version":1,"source_id":"exact-bytes"}`
	row := mailCutoverScannerFunc(func(destinations ...any) error {
		text, ok := destinations[4].(*string)
		if !ok {
			t.Fatalf("manifest destination=%T, want *string", destinations[4])
		}
		*text = manifest
		return nil
	})
	var epoch MailCutoverEpoch
	if err := scanMailCutover(row, &epoch); err != nil {
		t.Fatal(err)
	}
	if string(epoch.Manifest) != manifest {
		t.Fatalf("manifest=%q, want exact text %q", epoch.Manifest, manifest)
	}
}

func TestMailCutoverRequestValidation(t *testing.T) {
	t.Parallel()
	valid := MailCutoverRequest{
		EpochID:           "019f7f07-4b88-7c12-a394-b663274a6555",
		SourceID:          "019f7f07-5b88-7c12-a394-b663274a6555",
		TargetIdentity:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SourceFingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	manifest := relay.MigrationSourceManifest{
		Version: 1, SourceID: valid.SourceID, Phase: relay.MigrationSourcePrepared, EpochID: valid.EpochID,
		TargetIdentity: valid.TargetIdentity, Fingerprint: valid.SourceFingerprint,
		TableSHA256: relay.MigrationSourceHashes{
			Endpoints: strings.Repeat("c", 64), Conversations: strings.Repeat("c", 64), Memberships: strings.Repeat("c", 64),
			Messages: strings.Repeat("c", 64), Deliveries: strings.Repeat("c", 64), RecipientCursors: strings.Repeat("c", 64),
			MessageIdempotency: strings.Repeat("c", 64), ConversationIdempotency: strings.Repeat("c", 64), RequestNonces: strings.Repeat("c", 64),
		},
	}
	valid.Manifest, _ = json.Marshal(manifest)
	digest := sha256.Sum256(valid.Manifest)
	valid.ManifestSHA256 = hex.EncodeToString(digest[:])
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	invalid := []MailCutoverRequest{
		{},
		func() MailCutoverRequest { changed := valid; changed.EpochID = "bad"; return changed }(),
		func() MailCutoverRequest { changed := valid; changed.SourceID = "bad"; return changed }(),
		func() MailCutoverRequest { changed := valid; changed.TargetIdentity = "bad"; return changed }(),
		func() MailCutoverRequest { changed := valid; changed.SourceFingerprint = "bad"; return changed }(),
		func() MailCutoverRequest { changed := valid; changed.Manifest = json.RawMessage(`[]`); return changed }(),
		func() MailCutoverRequest {
			changed := valid
			changed.Manifest = json.RawMessage(`{"padding":"` + strings.Repeat("x", 9000) + `"}`)
			return changed
		}(),
		func() MailCutoverRequest { changed := valid; changed.ManifestSHA256 = "bad"; return changed }(),
		func() MailCutoverRequest {
			changed := valid
			changed.SourceFingerprint = strings.Repeat("d", 64)
			return changed
		}(),
	}
	for index, request := range invalid {
		if err := request.Validate(); err == nil {
			t.Fatalf("invalid request %d accepted: %#v", index, request)
		}
	}
}

func TestMailCutoverBatchValidationAndRollingDigest(t *testing.T) {
	t.Parallel()
	rows := []relay.MigrationSourceRow{
		migrationEndpointRow(t, "agent/a", "machine-a", 1),
		migrationEndpointRow(t, "agent/b", "machine-b", 2),
	}
	batch := MailCutoverBatch{EpochID: "019f7f07-4b88-7c12-a394-b663274a6555", Table: "mail_endpoints", Rows: rows, Done: true}
	if err := batch.Validate(); err != nil {
		t.Fatal(err)
	}
	first := nextMailCutoverDigest(emptyMailCutoverDigest, rows[:1])
	second := nextMailCutoverDigest(first, rows[1:])
	combined := nextMailCutoverDigest(emptyMailCutoverDigest, rows)
	empty := nextMailCutoverDigest(emptyMailCutoverDigest, nil)
	if empty != emptyMailCutoverDigest || first == emptyMailCutoverDigest || second == first || combined == second {
		t.Fatalf("rolling digests empty=%s first=%s second=%s combined=%s", empty, first, second, combined)
	}
	invalid := []MailCutoverBatch{
		{},
		{EpochID: batch.EpochID, Table: "unknown", Rows: rows},
		{EpochID: batch.EpochID, Table: batch.Table},
		{EpochID: batch.EpochID, Table: batch.Table, Rows: []relay.MigrationSourceRow{rows[1], rows[0]}},
		{EpochID: batch.EpochID, Table: batch.Table, Rows: []relay.MigrationSourceRow{rows[0], rows[0]}},
	}
	for index, candidate := range invalid {
		if err := candidate.Validate(); err == nil {
			t.Fatalf("invalid batch %d accepted: %#v", index, candidate)
		}
	}
}

func TestMailCutoverMaterializationUsesBinaryResumeOrdering(t *testing.T) {
	t.Parallel()
	for index, statement := range mailCutoverMaterializationStatements {
		if !strings.Contains(statement, `ORDER BY row_key COLLATE "C"`) {
			t.Fatalf("materialization statement %d lacks binary ordering: %s", index, statement)
		}
	}
}

func TestMailCutoverEnrollmentKeysExactlyMatchMigratedInventory(t *testing.T) {
	t.Parallel()
	keyA := make([]byte, 32)
	keyA[0] = 1
	keyB := make([]byte, 32)
	keyB[0] = 2
	machines := []relay.Machine{{ID: "machine-a", PublicKey: keyA}, {ID: "machine-b", PublicKey: keyB}}
	if err := validateMailCutoverEnrollmentKeys(machines, []mailCutoverLegacyKey{{publicKey: keyB, state: LegacyRetired}, {publicKey: keyA, state: LegacyMigrated}}); err != nil {
		t.Fatalf("matching migrated keys rejected: %v", err)
	}
	mismatched := append([]byte(nil), keyB...)
	mismatched[0] = 3
	if err := validateMailCutoverEnrollmentKeys(machines, []mailCutoverLegacyKey{{publicKey: keyA, state: LegacyMigrated}, {publicKey: mismatched, state: LegacyRetired}}); err == nil {
		t.Fatal("mismatched migrated key was accepted")
	}
	if err := validateMailCutoverEnrollmentKeys(machines[:1], []mailCutoverLegacyKey{{publicKey: keyA, state: LegacyMigrated}, {publicKey: keyB, state: LegacyMigrated}}); err == nil {
		t.Fatal("omitted migrated key was accepted")
	}
}

func TestPostgresAppendRejectsNonPortableBodyBeforeDatabaseAccess(t *testing.T) {
	t.Parallel()
	database := &Database{}
	base := relay.AppendInput{ConversationID: "019f7f07-4b88-7c12-a394-b663274a6555", SenderMachineID: "machine-a", FromEndpoint: "agent/a", IdempotencyKey: "portable-key"}
	for _, body := range []string{string([]byte{0xff}), "body\x00value"} {
		input := base
		input.Body = body
		if _, _, err := database.AppendMessage(input); err == nil || !strings.Contains(err.Error(), "portable UTF-8") {
			t.Fatalf("non-portable body %q err=%v", body, err)
		}
	}
}

func migrationEndpointRow(t *testing.T, endpoint, machine string, generation int64) relay.MigrationSourceRow {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"endpoint": endpoint, "machine_id": machine, "lease_until": int64(1), "ownership_generation": generation,
		"consumer_id": nil, "consumer_generation": int64(0), "consumer_lease_until": nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	key, err := json.Marshal([]any{endpoint})
	if err != nil {
		t.Fatal(err)
	}
	return relay.MigrationSourceRow{Table: "mail_endpoints", Key: string(key), Payload: payload, SHA256: hex.EncodeToString(digest[:])}
}
