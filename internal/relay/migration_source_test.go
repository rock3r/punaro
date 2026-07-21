package relay

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMigrationSourceManifestAndBarrier(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, time.July, 21, 9, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/source/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/source/b"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "source-create", CreatorEndpoint: "agent/source/a", Now: now,
		Members: []Member{
			{Endpoint: "agent/source/a", Capabilities: CapSend | CapReceive | CapAdmin},
			{Endpoint: "agent/source/b", Capabilities: CapReceive},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	message, duplicate, err := store.AppendMessage(AppendInput{
		ConversationID: conversation.ID, SenderMachineID: "machine-a", FromEndpoint: "agent/source/a",
		Body: "migration body", IdempotencyKey: "source-message", Now: now,
	})
	if err != nil || duplicate {
		t.Fatalf("append=%#v duplicate=%t err=%v", message, duplicate, err)
	}
	page, err := store.LeaseDeliveries("machine-b", "source-consumer", "agent/source/b", conversation.ID, now, time.Minute, 10)
	if err != nil || len(page.Deliveries) != 1 {
		t.Fatalf("lease page=%#v err=%v", page, err)
	}

	beforePhase := migrationSourcePhase(t, store)
	first, err := InspectMigrationSource(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := InspectMigrationSource(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || first.Version != 1 || first.SourceID == "" || first.Phase != MigrationSourceActive || first.Fingerprint == "" {
		t.Fatalf("unstable manifest first=%#v second=%#v", first, second)
	}
	if first.Counts.Endpoints != 2 || first.Counts.Conversations != 1 || first.Counts.Messages != 1 || first.Counts.Deliveries != 1 || first.Counts.MessageIdempotency != 1 || first.Counts.ConversationIdempotency != 1 {
		t.Fatalf("manifest counts=%#v", first.Counts)
	}
	if got := migrationSourcePhase(t, store); got != beforePhase {
		t.Fatalf("read-only inspection changed phase from %q to %q", beforePhase, got)
	}

	epochID := uuid.NewString()
	targetID := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if _, err := PrepareMigrationSource(ctx, path, epochID, targetID, strings.Repeat("f", 64), now.Add(time.Minute)); err == nil {
		t.Fatal("wrong source fingerprint was accepted")
	}
	afterRejectedPrepare, err := InspectMigrationSource(ctx, path)
	if err != nil || afterRejectedPrepare != first {
		t.Fatalf("rejected prepare mutated source=%#v err=%v", afterRejectedPrepare, err)
	}
	prepared, err := PrepareMigrationSource(ctx, path, epochID, targetID, first.Fingerprint, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Phase != MigrationSourcePrepared || prepared.EpochID != epochID || prepared.TargetIdentity != targetID || prepared.Fingerprint == first.Fingerprint {
		t.Fatalf("prepared manifest=%#v active=%#v", prepared, first)
	}
	preparedRetry, err := PrepareMigrationSource(ctx, path, epochID, targetID, first.Fingerprint, now.Add(time.Minute))
	if err != nil || preparedRetry != prepared {
		t.Fatalf("exact prepare retry=%#v err=%v, want %#v", preparedRetry, err, prepared)
	}
	if _, err := PrepareMigrationSource(ctx, path, epochID, targetID, first.Fingerprint, now.Add(2*time.Minute)); err == nil {
		t.Fatal("changed prepare cutoff was accepted as an exact retry")
	}
	firstBatch, err := ReadMigrationSourceBatch(ctx, path, "mail_endpoints", "", 1)
	if err != nil || len(firstBatch.Rows) != 1 || firstBatch.Done || firstBatch.NextKey == "" {
		t.Fatalf("first migration batch=%#v err=%v", firstBatch, err)
	}
	secondBatch, err := ReadMigrationSourceBatch(ctx, path, "mail_endpoints", firstBatch.NextKey, 1)
	if err != nil || len(secondBatch.Rows) != 1 || !secondBatch.Done || secondBatch.NextKey == firstBatch.NextKey {
		t.Fatalf("second migration batch=%#v err=%v", secondBatch, err)
	}
	if firstBatch.Rows[0].Table != "mail_endpoints" || firstBatch.Rows[0].Key >= secondBatch.Rows[0].Key || firstBatch.Rows[0].SHA256 == "" {
		t.Fatalf("noncanonical migration rows first=%#v second=%#v", firstBatch.Rows[0], secondBatch.Rows[0])
	}
	endpointHasher, err := NewMigrationTableHasher("mail_endpoints")
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range append(firstBatch.Rows, secondBatch.Rows...) {
		if err := endpointHasher.Add(row); err != nil {
			t.Fatal(err)
		}
	}
	endpointCount, endpointSHA256 := endpointHasher.Evidence()
	if endpointCount != prepared.Counts.Endpoints || endpointSHA256 != prepared.TableSHA256.Endpoints {
		t.Fatalf("export evidence count=%d sha=%s manifest=%#v", endpointCount, endpointSHA256, prepared)
	}
	deliveryBatch, err := ReadMigrationSourceBatch(ctx, path, "mail_deliveries", "", 10)
	if err != nil || len(deliveryBatch.Rows) != 1 || !deliveryBatch.Done {
		t.Fatalf("delivery migration batch=%#v err=%v", deliveryBatch, err)
	}
	var delivery map[string]any
	if err := json.Unmarshal(deliveryBatch.Rows[0].Payload, &delivery); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"lease_machine_id", "lease_token", "ownership_generation", "consumer_generation", "lease_until"} {
		if delivery[field] != nil {
			t.Fatalf("prepared delivery retained %s=%v", field, delivery[field])
		}
	}
	if _, err := ReadMigrationSourceBatch(ctx, path, "mail_endpoints", "missing-key", 1); err == nil {
		t.Fatal("migration batch accepted an unknown resume key")
	}
	if _, err := ReadMigrationSourceBatch(ctx, path, "unknown", "", 1); err == nil {
		t.Fatal("migration batch accepted an unknown table")
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO request_nonces(machine_id,nonce,expires_at) VALUES('old-daemon','blocked-direct-write',?)`, now.Add(time.Hour).UnixMilli()); err == nil || !strings.Contains(err.Error(), "relay migration source is not writable") {
		t.Fatalf("persisted mutation trigger err=%v", err)
	}
	if _, _, err := store.AppendMessage(AppendInput{
		ConversationID: conversation.ID, SenderMachineID: "machine-a", FromEndpoint: "agent/source/a",
		Body: "blocked", IdempotencyKey: "source-blocked", Now: now.Add(time.Minute),
	}); err == nil {
		t.Fatalf("existing writable store after prepare err=%v", err)
	}
	if reopened, err := Open(path); !errors.Is(err, ErrMigrationSourcePrepared) {
		if reopened != nil {
			_ = reopened.Close()
		}
		t.Fatalf("new writable store after prepare err=%v", err)
	}
	var endpointUntil, ownershipGeneration, consumerGeneration int64
	var consumerID, consumerUntil any
	if err := store.db.QueryRowContext(ctx, `SELECT lease_until,ownership_generation,consumer_id,consumer_generation,consumer_lease_until FROM endpoints WHERE endpoint='agent/source/b'`).Scan(&endpointUntil, &ownershipGeneration, &consumerID, &consumerGeneration, &consumerUntil); err != nil {
		t.Fatal(err)
	}
	if endpointUntil > now.Add(time.Minute).UnixMilli() || ownershipGeneration != 2 || consumerID != nil || consumerGeneration != 2 || consumerUntil != nil {
		t.Fatalf("prepared endpoint until=%d ownership=%d consumer=%v generation=%d consumer_until=%v", endpointUntil, ownershipGeneration, consumerID, consumerGeneration, consumerUntil)
	}
	var leaseMachine, leaseToken, leaseOwnership, leaseConsumer, leaseUntil any
	var leaseGeneration int64
	if err := store.db.QueryRowContext(ctx, `SELECT lease_machine_id,lease_token,lease_generation,ownership_generation,consumer_generation,lease_until FROM deliveries WHERE id=?`, page.Deliveries[0].ID).Scan(&leaseMachine, &leaseToken, &leaseGeneration, &leaseOwnership, &leaseConsumer, &leaseUntil); err != nil {
		t.Fatal(err)
	}
	if leaseMachine != nil || leaseToken != nil || leaseGeneration != page.Deliveries[0].LeaseGeneration+1 || leaseOwnership != nil || leaseConsumer != nil || leaseUntil != nil {
		t.Fatalf("prepared delivery machine=%v token=%v generation=%d ownership=%v consumer=%v until=%v", leaseMachine, leaseToken, leaseGeneration, leaseOwnership, leaseConsumer, leaseUntil)
	}

	active, err := AbortPreparedMigrationSource(ctx, path, epochID, targetID, prepared.Fingerprint)
	if err != nil || active.Phase != MigrationSourceActive || active.EpochID != "" || active.TargetIdentity != "" {
		t.Fatalf("aborted manifest=%#v err=%v", active, err)
	}
	activeRetry, err := AbortPreparedMigrationSource(ctx, path, epochID, targetID, prepared.Fingerprint)
	if err != nil || activeRetry.Fingerprint != active.Fingerprint || activeRetry.Phase != MigrationSourceActive {
		t.Fatalf("exact abort retry=%#v err=%v", activeRetry, err)
	}
	if err := store.ConsumeRequestNonce("machine-a", "post-abort-write", now.Add(2*time.Minute), now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if recovered, err := AbortPreparedMigrationSource(ctx, path, epochID, targetID, prepared.Fingerprint); err != nil || recovered.Phase != MigrationSourceActive || recovered.Fingerprint == prepared.Fingerprint {
		t.Fatalf("post-write abort recovery=%#v err=%v", recovered, err)
	}
	active, err = InspectMigrationSource(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = reopened.Close()

	prepared, err = PrepareMigrationSource(ctx, path, uuid.NewString(), targetID, active.Fingerprint, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	retired, err := RetirePreparedMigrationSource(ctx, path, prepared.EpochID, targetID, prepared.Fingerprint)
	if err != nil || retired.Phase != MigrationSourceRetired {
		t.Fatalf("retired manifest=%#v err=%v", retired, err)
	}
	retiredRetry, err := RetirePreparedMigrationSource(ctx, path, prepared.EpochID, targetID, prepared.Fingerprint)
	if err != nil || retiredRetry != retired {
		t.Fatalf("exact retire retry=%#v err=%v", retiredRetry, err)
	}
	if _, err := AbortPreparedMigrationSource(ctx, path, prepared.EpochID, targetID, prepared.Fingerprint); !errors.Is(err, ErrMigrationSourceRetired) {
		t.Fatalf("abort retired source err=%v", err)
	}
	if reopened, err := Open(path); !errors.Is(err, ErrMigrationSourceRetired) {
		if reopened != nil {
			_ = reopened.Close()
		}
		t.Fatalf("new writable store after retirement err=%v", err)
	}
}

func TestMigrationSourceRefusesMissingOrPermissiveGuard(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		tamper string
	}{
		{name: "missing", tamper: `DROP TRIGGER relay_migration_guard_request_nonces_insert`},
		{name: "permissive", tamper: `DROP TRIGGER relay_migration_guard_request_nonces_insert; CREATE TRIGGER relay_migration_guard_request_nonces_insert BEFORE INSERT ON request_nonces BEGIN SELECT 1; END`},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "relay.db")
			store, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.ExecContext(context.Background(), test.tamper); err != nil {
				_ = store.Close()
				t.Fatal(err)
			}
			_ = store.Close()
			if _, err := InspectMigrationSource(context.Background(), path); err == nil {
				t.Fatal("tampered mutation guard was accepted")
			}
		})
	}
}

func TestMigrationSourceGuardFailsClosedWithoutControlRow(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), `DELETE FROM relay_migration_control`); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), `INSERT INTO request_nonces(machine_id,nonce,expires_at) VALUES('machine','nonce',1)`); err == nil || !strings.Contains(err.Error(), "relay migration source is not writable") {
		_ = store.Close()
		t.Fatalf("write without control singleton err=%v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := Open(path); err == nil {
		_ = reopened.Close()
		t.Fatal("ordinary startup recreated the missing migration-control singleton")
	}
}

func TestMigrationSourceRefusesUnexpectedIndex(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), `CREATE INDEX unexpected_endpoint_index ON endpoints(lease_until)`); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	_ = store.Close()
	if _, err := InspectMigrationSource(context.Background(), path); err == nil {
		t.Fatal("unexpected source index was accepted")
	}
}

func TestMigrationSourceRefusesMalformedRuntimeType(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := store.AdvertiseEndpoints("runtime-type-machine", []string{"agent/runtime-type"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "runtime-type-machine", IdempotencyKey: "runtime-type-conversation", CreatorEndpoint: "agent/runtime-type", Now: now,
		Members: []Member{{Endpoint: "agent/runtime-type", Capabilities: CapSend | CapReceive | CapAdmin}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), `UPDATE conversations SET created_at='bad-timestamp' WHERE id=?`, conversation.ID); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	if _, err := InspectMigrationSource(context.Background(), path); err == nil {
		t.Fatal("malformed SQLite runtime type was accepted")
	}
}

func TestMigrationSourceConcurrentPreparersSingleWinner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	manifest, err := InspectMigrationSource(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	target := strings.Repeat("a", 64)
	type result struct {
		manifest MigrationSourceManifest
		err      error
	}
	results := make(chan result, 2)
	for range 2 {
		epoch := uuid.NewString()
		go func() {
			prepared, err := PrepareMigrationSource(ctx, path, epoch, target, manifest.Fingerprint, time.Now().UTC())
			results <- result{manifest: prepared, err: err}
		}()
	}
	var successes int
	for range 2 {
		outcome := <-results
		if outcome.err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent prepare successes=%d, want 1", successes)
	}
}

func TestInspectMigrationSourceRefusesMissingAndSymlink(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	directory := t.TempDir()
	missing := filepath.Join(directory, "missing.db")
	if _, err := InspectMigrationSource(ctx, missing); err == nil {
		t.Fatal("missing source was created or accepted")
	}
	target := filepath.Join(directory, "target.db")
	store, err := Open(target)
	if err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	link := filepath.Join(directory, "source-link.db")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectMigrationSource(ctx, link); err == nil {
		t.Fatal("symlink source was accepted")
	}
	linkedDirectory := filepath.Join(directory, "linked-directory")
	if err := os.Symlink(directory, linkedDirectory); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectMigrationSource(ctx, filepath.Join(linkedDirectory, "target.db")); err == nil {
		t.Fatal("source beneath symlinked directory was accepted")
	}
	specialSource := filepath.Join(directory, "special-source.db")
	specialStore, err := Open(specialSource)
	if err != nil {
		t.Fatal(err)
	}
	_ = specialStore.Close()
	special := filepath.Join(directory, "relay?#.db")
	if err := os.Rename(specialSource, special); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectMigrationSource(ctx, special); err != nil {
		t.Fatalf("literal special-character source path: %v", err)
	}
}

func migrationSourcePhase(t *testing.T, store *Store) MigrationSourcePhase {
	t.Helper()
	var phase MigrationSourcePhase
	if err := store.db.QueryRowContext(context.Background(), `SELECT phase FROM relay_migration_control WHERE singleton=1`).Scan(&phase); err != nil {
		t.Fatal(err)
	}
	return phase
}
