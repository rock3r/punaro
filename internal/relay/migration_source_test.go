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
			{Role: "role/source-reviewer", RoleMachineID: "machine-b", Capabilities: CapReceive},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BindRoleToSession("machine-b", "role/source-reviewer", "agent/source/b", now, time.Hour); err != nil {
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
	if first != second || first.Version != 6 || first.SourceID == "" || first.Phase != MigrationSourceActive || first.Fingerprint == "" {
		t.Fatalf("unstable manifest first=%#v second=%#v", first, second)
	}
	if first.Counts.Endpoints != 2 || first.Counts.Conversations != 1 || first.Counts.Roles != 1 || first.Counts.RoleMemberships != 1 || first.Counts.RoleBindings != 1 || first.Counts.Messages != 1 || first.Counts.Deliveries != 1 || first.Counts.MessageIdempotency != 1 || first.Counts.ConversationIdempotency != 1 || first.Counts.RateBuckets != 2 {
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
	roleBatch, err := ReadMigrationSourceBatch(ctx, path, "mail_roles", "", 10)
	if err != nil || len(roleBatch.Rows) != 1 || !roleBatch.Done {
		t.Fatalf("role migration batch=%#v err=%v", roleBatch, err)
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

func TestMigrationSourceAcceptsInvokeCapabilityBeforePreparation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateConversationIdempotent(CreateConversationInput{MachineID: "machine-a", IdempotencyKey: "create", CreatorEndpoint: "agent/a", Now: now, Members: []Member{{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin | CapInvoke}}}); err != nil {
		t.Fatal(err)
	}
	manifest, err := InspectMigrationSource(ctx, path)
	if err != nil || manifest.Phase != MigrationSourceActive {
		t.Fatalf("invoke-capability manifest=%#v err=%v", manifest, err)
	}
	if got := migrationSourcePhase(t, store); got != MigrationSourceActive {
		t.Fatalf("source inspection changed phase to %q", got)
	}
}

func TestMigrationSourceRejectsControlAuditWithoutRetryRecord(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, time.August, 3, 12, 10, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	for machine, endpoint := range map[string]string{"machine-a": "agent/a", "machine-b": "agent/b"} {
		if err := store.AdvertiseEndpoints(machine, []string{endpoint}, now, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	conversation, err := store.CreateConversation("agent/a", []Member{{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin}}, now)
	if err != nil {
		t.Fatal(err)
	}
	event, _, err := store.ApplyControl(ControlInput{ConversationID: conversation.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a", Operation: ControlUpsertMember, Member: Member{Endpoint: "agent/b", Capabilities: CapReceive}, IdempotencyKey: "orphaned-control", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, "DELETE FROM conversation_control_idempotency WHERE control_id=?", event.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectMigrationSource(ctx, path); err == nil {
		t.Fatal("migration source accepted a control audit event without its retry record")
	}
}

func TestMigrationSourceRejectsOperationInconsistentControlAudit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, time.August, 3, 12, 15, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	for machine, endpoint := range map[string]string{"machine-a": "agent/a", "machine-b": "agent/b"} {
		if err := store.AdvertiseEndpoints(machine, []string{endpoint}, now, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	conversation, err := store.CreateConversation("agent/a", []Member{{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin}}, now)
	if err != nil {
		t.Fatal(err)
	}
	event, _, err := store.ApplyControl(ControlInput{ConversationID: conversation.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a", Operation: ControlUpsertMember, Member: Member{Endpoint: "agent/b", Capabilities: CapReceive}, IdempotencyKey: "inconsistent-control", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, "UPDATE conversation_controls SET member_capabilities=0 WHERE id=?", event.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectMigrationSource(ctx, path); err == nil {
		t.Fatal("migration source accepted an upsert control audit event without capabilities")
	}
}

func TestMigrationSourceRejectsControlAuditWithMissingEndpoint(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, time.August, 3, 12, 20, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	for machine, endpoint := range map[string]string{"machine-a": "agent/a", "machine-b": "agent/b"} {
		if err := store.AdvertiseEndpoints(machine, []string{endpoint}, now, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	conversation, err := store.CreateConversation("agent/a", []Member{{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin}, {Endpoint: "agent/b", Capabilities: CapReceive}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ApplyControl(ControlInput{ConversationID: conversation.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a", Operation: ControlRemoveMember, Member: Member{Endpoint: "agent/b"}, IdempotencyKey: "missing-control-target", Now: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, "DELETE FROM endpoints WHERE endpoint='agent/b'"); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectMigrationSource(ctx, path); err == nil {
		t.Fatal("migration source accepted a control audit event with a missing endpoint")
	}
}

func TestCheckMigrationSourceEnrollmentCoverage(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.July, 21, 9, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/source/a", "claude/jbr-reviewer"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateConversationIdempotent(CreateConversationInput{MachineID: "machine-a", IdempotencyKey: "source-role", CreatorEndpoint: "agent/source/a", Members: []Member{
		{Endpoint: "agent/source/a", Capabilities: CapSend | CapReceive | CapAdmin},
		{Role: "role/source-reviewer", RoleMachineID: "machine-b", Capabilities: CapReceive},
	}, Now: now}); err != nil {
		t.Fatal(err)
	}
	covered := `[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/source/"],"endpoints":["claude/jbr-reviewer"]},{"id":"machine-b","public_key":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/reviewer/"]}]`
	if err := CheckMigrationSourceEnrollmentCoverage(ctx, path, covered); err != nil {
		t.Fatalf("covered enrollment rejected: %v", err)
	}
	roleUncovered := `[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/source/"],"endpoints":["claude/jbr-reviewer"]}]`
	if err := CheckMigrationSourceEnrollmentCoverage(ctx, path, roleUncovered); err == nil {
		t.Fatal("enrollment missing a durable role owner was accepted")
	}
	uncovered := `[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/source/"]}]`
	if err := CheckMigrationSourceEnrollmentCoverage(ctx, path, uncovered); err == nil {
		t.Fatal("enrollment missing an exact endpoint was accepted")
	}
	reassigned := `[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/source/"]},{"id":"machine-b","public_key":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["claude/"]}]`
	if err := CheckMigrationSourceEnrollmentCoverage(ctx, path, reassigned); err == nil {
		t.Fatal("another machine's authority was accepted for the persisted endpoint owner")
	}
}

func TestMigrationSourceRefusesOutOfRangeRoleCapabilities(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.July, 21, 9, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/source/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "source-invalid-role-capability", CreatorEndpoint: "agent/source/a", Now: now,
		Members: []Member{
			{Endpoint: "agent/source/a", Capabilities: CapSend | CapReceive | CapAdmin},
			{Role: "role/source-reviewer", RoleMachineID: "machine-b", Capabilities: CapReceive},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, "UPDATE role_memberships SET capabilities = 8"); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectMigrationSource(ctx, path); err == nil {
		t.Fatal("source with out-of-range durable role capabilities was accepted")
	}
}

func TestMigrationSourceRefusesInvalidRoleBindingFence(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.July, 21, 9, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/source/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/source/b"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "source-invalid-role-binding", CreatorEndpoint: "agent/source/a", Now: now,
		Members: []Member{
			{Endpoint: "agent/source/a", Capabilities: CapSend | CapReceive | CapAdmin},
			{Role: "role/source-reviewer", RoleMachineID: "machine-b", Capabilities: CapReceive},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.BindRoleToSession("machine-b", "role/source-reviewer", "agent/source/b", now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, "UPDATE role_bindings SET session_endpoint='agent/source/missing', ownership_generation=0"); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectMigrationSource(ctx, path); err == nil {
		t.Fatal("source with an invalid durable role binding fence was accepted")
	}
}

func TestMigrationBatchCarriesWorstCaseValidMessageBody(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, time.July, 21, 10, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/source/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "large-create", CreatorEndpoint: "agent/source/a", Now: now,
		Members: []Member{{Endpoint: "agent/source/a", Capabilities: CapSend | CapReceive | CapAdmin}},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Repeat("\x01", maxMessageBodyBytes)
	if _, duplicate, err := store.AppendMessage(AppendInput{
		ConversationID: conversation.ID, SenderMachineID: "machine-a", FromEndpoint: "agent/source/a",
		Body: body, IdempotencyKey: "large-message", Now: now,
	}); err != nil || duplicate {
		t.Fatalf("append large message duplicate=%t err=%v", duplicate, err)
	}
	active, err := InspectMigrationSource(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareMigrationSource(ctx, path, uuid.NewString(), strings.Repeat("a", 64), active.Fingerprint, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	batch, err := ReadMigrationSourceBatch(ctx, path, "mail_messages", "", 1)
	if err != nil || len(batch.Rows) != 1 || !batch.Done {
		t.Fatalf("large message batch=%#v err=%v", batch, err)
	}
	if len(batch.Rows[0].Payload) <= 65536 || len(batch.Rows[0].Payload) > MaxMigrationSourcePayloadBytes {
		t.Fatalf("large message payload bytes=%d", len(batch.Rows[0].Payload))
	}
	hasher, err := NewMigrationTableHasher("mail_messages")
	if err != nil {
		t.Fatal(err)
	}
	if err := hasher.Add(batch.Rows[0]); err != nil {
		t.Fatal(err)
	}
	count, digest := hasher.Evidence()
	if count != prepared.Counts.Messages || digest != prepared.TableSHA256.Messages {
		t.Fatalf("large message evidence count=%d digest=%s manifest=%#v", count, digest, prepared)
	}
}

func TestPreparedV1MigrationSourceRemainsRecoverable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "relay.db")
	now := time.Date(2026, time.August, 3, 10, 0, 0, 0, time.UTC)
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/legacy/a"}, now, time.Hour); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := openMigrationSourceDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `DROP TABLE direct_message_idempotency; DROP TABLE message_from_roles; DROP TABLE direct_conversations; DROP TABLE rate_buckets; DROP TABLE role_profile_idempotency; DROP TABLE role_profiles; DROP TABLE conversation_control_idempotency; DROP TABLE conversation_controls; DROP TABLE role_bindings; DROP TABLE role_memberships; DROP TABLE roles`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	legacy, err := InspectMigrationSource(ctx, path)
	if err != nil || legacy.Phase != MigrationSourceActive || legacy.Fingerprint == "" {
		t.Fatalf("legacy active manifest=%#v err=%v", legacy, err)
	}
	preparedLegacy, err := PrepareMigrationSource(ctx, path, uuid.NewString(), strings.Repeat("a", 64), legacy.Fingerprint, now.Add(time.Minute))
	if err != nil || preparedLegacy.Phase != MigrationSourcePrepared || preparedLegacy.Version != 1 {
		t.Fatalf("legacy preparation=%#v err=%v", preparedLegacy, err)
	}
	controls, err := ReadMigrationSourceBatch(ctx, path, "mail_conversation_controls", "", 1)
	if err != nil || len(controls.Rows) != 0 || !controls.Done {
		t.Fatalf("prepared legacy control batch=%#v err=%v", controls, err)
	}
	legacy, err = AbortPreparedMigrationSource(ctx, path, preparedLegacy.EpochID, preparedLegacy.TargetIdentity, preparedLegacy.Fingerprint)
	if err != nil || legacy.Phase != MigrationSourceActive || legacy.Version != 1 {
		t.Fatalf("legacy preparation abort=%#v err=%v", legacy, err)
	}

	prepareLegacy := func(epoch string) {
		db, err := openMigrationSourceDatabase(path, false)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = db.Close() }()
		if _, err := db.ExecContext(ctx, `UPDATE relay_migration_control SET phase='prepared',epoch_id=?,target_identity=?,fingerprint=?,last_epoch_id=?,last_target_identity=?,last_expected_fingerprint=?,last_result_fingerprint=?,last_cutoff=?,last_transition=? WHERE singleton=1`, epoch, strings.Repeat("b", 64), legacy.Fingerprint, epoch, strings.Repeat("b", 64), legacy.Fingerprint, legacy.Fingerprint, now.UnixMilli(), "prepared"); err != nil {
			t.Fatal(err)
		}
	}

	epoch := uuid.NewString()
	prepareLegacy(epoch)
	prepared, err := InspectMigrationSource(ctx, path)
	if err != nil || prepared.Phase != MigrationSourcePrepared || prepared.Fingerprint != legacy.Fingerprint {
		t.Fatalf("legacy prepared manifest=%#v err=%v", prepared, err)
	}
	if reopened, err := Open(path); !errors.Is(err, ErrMigrationSourcePrepared) {
		if reopened != nil {
			_ = reopened.Close()
		}
		t.Fatalf("opening legacy prepared source err=%v", err)
	}
	preparedAfterOpen, err := InspectMigrationSource(ctx, path)
	if err != nil || preparedAfterOpen.Fingerprint != legacy.Fingerprint || preparedAfterOpen.Phase != MigrationSourcePrepared {
		t.Fatalf("legacy prepared source changed after Open: manifest=%#v err=%v", preparedAfterOpen, err)
	}
	batch, err := ReadMigrationSourceBatch(ctx, path, "mail_endpoints", "", 1)
	if err != nil || len(batch.Rows) != 1 || !batch.Done {
		t.Fatalf("legacy endpoint batch=%#v err=%v", batch, err)
	}
	controls, err = ReadMigrationSourceBatch(ctx, path, "mail_conversation_controls", "", 1)
	if err != nil || len(controls.Rows) != 0 || !controls.Done {
		t.Fatalf("legacy control batch=%#v err=%v", controls, err)
	}
	aborted, err := AbortPreparedMigrationSource(ctx, path, epoch, strings.Repeat("b", 64), legacy.Fingerprint)
	if err != nil || aborted.Phase != MigrationSourceActive || aborted.Fingerprint != legacy.Fingerprint {
		t.Fatalf("legacy abort=%#v err=%v", aborted, err)
	}

	epoch = uuid.NewString()
	prepareLegacy(epoch)
	retired, err := RetirePreparedMigrationSource(ctx, path, epoch, strings.Repeat("b", 64), legacy.Fingerprint)
	if err != nil || retired.Phase != MigrationSourceRetired || retired.Fingerprint != legacy.Fingerprint {
		t.Fatalf("legacy retirement=%#v err=%v", retired, err)
	}
}

func TestPreparedParentV3RoleOnlyMigrationSourcePreservesManifestIdentity(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "relay.db")
	now := time.Date(2026, time.August, 3, 10, 0, 0, 0, time.UTC)
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if _, err := store.CreateConversation("agent/a", []Member{{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin}, {Role: "role/fenced", RoleMachineID: "machine-a", Capabilities: CapReceive}}, now); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.BindRoleToSession("machine-a", "role/fenced", "agent/a", now, time.Hour); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := openMigrationSourceDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `DROP TABLE direct_message_idempotency; DROP TABLE message_from_roles; DROP TABLE direct_conversations; DROP TABLE rate_buckets; DROP TABLE role_profile_idempotency; DROP TABLE role_profiles; DROP TABLE conversation_control_idempotency; DROP TABLE conversation_controls`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	active, err := InspectMigrationSource(ctx, path)
	if err != nil || active.Version != 2 || active.Phase != MigrationSourceActive {
		t.Fatalf("role-only active manifest=%#v err=%v", active, err)
	}
	epoch, target := uuid.NewString(), strings.Repeat("a", 64)
	preparedV2, err := PrepareMigrationSource(ctx, path, epoch, target, active.Fingerprint, now.Add(time.Minute))
	if err != nil || preparedV2.Version != 2 || preparedV2.Phase != MigrationSourcePrepared {
		t.Fatalf("role-only v2 preparation=%#v err=%v", preparedV2, err)
	}
	preparedV2AfterRestart, err := InspectMigrationSource(ctx, path)
	if err != nil || preparedV2AfterRestart.Version != 2 || preparedV2AfterRestart.Phase != MigrationSourcePrepared || preparedV2AfterRestart.Fingerprint != preparedV2.Fingerprint {
		t.Fatalf("role-only v2 restart manifest=%#v err=%v", preparedV2AfterRestart, err)
	}
	active, err = AbortPreparedMigrationSource(ctx, path, epoch, target, preparedV2.Fingerprint)
	if err != nil || active.Version != 2 || active.Phase != MigrationSourceActive {
		t.Fatalf("role-only v2 abort=%#v err=%v", active, err)
	}
	epoch = uuid.NewString()
	db, err = openMigrationSourceDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `UPDATE relay_migration_control SET phase='prepared',epoch_id=?,target_identity=?,fingerprint=?,last_epoch_id=?,last_target_identity=?,last_expected_fingerprint=?,last_result_fingerprint=?,last_cutoff=?,last_transition=? WHERE singleton=1`, epoch, target, active.Fingerprint, epoch, target, active.Fingerprint, active.Fingerprint, now.UnixMilli(), "prepared")
	closeErr := db.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("record parent prepared source err=%v close=%v", err, closeErr)
	}
	prepared, err := InspectMigrationSource(ctx, path)
	if err != nil || prepared.Version != 3 || prepared.Phase != MigrationSourcePrepared || prepared.Fingerprint != active.Fingerprint {
		t.Fatalf("parent v3 prepared manifest=%#v err=%v", prepared, err)
	}
	body, err := json.Marshal(prepared)
	if err != nil || strings.Contains(string(body), `"control_events"`) || strings.Contains(string(body), `"control_idempotency"`) {
		t.Fatalf("parent v3 manifest changed body=%s err=%v", body, err)
	}
	controls, err := ReadMigrationSourceBatch(ctx, path, "mail_conversation_controls", "", 1)
	if err != nil || len(controls.Rows) != 0 || !controls.Done {
		t.Fatalf("parent v3 control batch=%#v err=%v", controls, err)
	}
	aborted, err := AbortPreparedMigrationSource(ctx, path, epoch, target, active.Fingerprint)
	if err != nil || aborted.Version != 2 || aborted.Phase != MigrationSourceActive {
		t.Fatalf("parent v3 abort=%#v err=%v", aborted, err)
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

func TestMigrationSourceRefusesNonPortableLegacyRequestTokens(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		query string
	}{
		{name: "invalid UTF-8", query: `INSERT INTO request_nonces(machine_id,nonce,expires_at) VALUES('machine-a',CAST(X'ff' AS TEXT),1)`},
		{name: "NUL", query: `INSERT INTO request_nonces(machine_id,nonce,expires_at) VALUES('machine-a',CAST(X'610062' AS TEXT),1)`},
		{name: "resume delimiter", query: `INSERT INTO request_nonces(machine_id,nonce,expires_at) VALUES('machine-a',CAST(X'611f62' AS TEXT),1)`},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "relay.db")
			store, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.ExecContext(context.Background(), test.query); err != nil { // #nosec G202 -- query is a fixed test-only SQL expression.
				_ = store.Close()
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := InspectMigrationSource(context.Background(), path); err == nil {
				t.Fatal("non-portable legacy request token was accepted")
			}
		})
	}
}

func TestMigrationSourceRefusesDelimiterInLegacyUUIDKey(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), `INSERT INTO conversations(id,next_sequence,created_at) VALUES(CAST(X'611f62' AS TEXT),0,1)`); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectMigrationSource(context.Background(), path); err == nil {
		t.Fatal("resume delimiter in legacy UUID key was accepted")
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

func TestInspectMigrationSourceAcceptsPreparedParentWithoutRateBuckets(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, time.August, 18, 18, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := openMigrationSourceDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `DROP TABLE direct_message_idempotency; DROP TABLE message_from_roles; DROP TABLE direct_conversations; DROP TABLE rate_buckets`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	inspected, err := InspectMigrationSource(ctx, path)
	if err != nil || inspected.Version != 4 || inspected.Phase != MigrationSourceActive {
		t.Fatalf("parent without rate_buckets inspect=%#v err=%v", inspected, err)
	}
	prepared, err := PrepareMigrationSource(ctx, path, uuid.NewString(), strings.Repeat("c", 64), inspected.Fingerprint, now.Add(time.Minute))
	if err != nil || prepared.Phase != MigrationSourcePrepared || prepared.Version != 4 {
		t.Fatalf("parent prepare=%#v err=%v", prepared, err)
	}
	if reopened, err := Open(path); !errors.Is(err, ErrMigrationSourcePrepared) {
		if reopened != nil {
			_ = reopened.Close()
		}
		t.Fatalf("opening prepared parent source err=%v", err)
	}
	afterOpen, err := InspectMigrationSource(ctx, path)
	if err != nil || afterOpen.Fingerprint != prepared.Fingerprint || afterOpen.Phase != MigrationSourcePrepared || afterOpen.Version != 4 {
		t.Fatalf("prepared parent changed after Open: %#v err=%v", afterOpen, err)
	}
	batch, err := ReadMigrationSourceBatch(ctx, path, "mail_rate_buckets", "", 10)
	if err != nil || len(batch.Rows) != 0 || !batch.Done {
		t.Fatalf("parent rate-bucket batch=%#v err=%v", batch, err)
	}
}

func TestInspectMigrationSourceAcceptsPreparedParentWithoutDirectMessages(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, time.August, 18, 18, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := openMigrationSourceDatabase(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `DROP TABLE direct_message_idempotency; DROP TABLE message_from_roles; DROP TABLE direct_conversations`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	inspected, err := InspectMigrationSource(ctx, path)
	if err != nil || inspected.Version != 5 || inspected.Phase != MigrationSourceActive {
		t.Fatalf("parent without direct messages inspect=%#v err=%v", inspected, err)
	}
	prepared, err := PrepareMigrationSource(ctx, path, uuid.NewString(), strings.Repeat("e", 64), inspected.Fingerprint, now.Add(time.Minute))
	if err != nil || prepared.Phase != MigrationSourcePrepared || prepared.Version != 5 {
		t.Fatalf("parent prepare=%#v err=%v", prepared, err)
	}
	if reopened, err := Open(path); !errors.Is(err, ErrMigrationSourcePrepared) {
		if reopened != nil {
			_ = reopened.Close()
		}
		t.Fatalf("opening prepared parent source err=%v", err)
	}
	afterOpen, err := InspectMigrationSource(ctx, path)
	if err != nil || afterOpen.Fingerprint != prepared.Fingerprint || afterOpen.Phase != MigrationSourcePrepared || afterOpen.Version != 5 {
		t.Fatalf("prepared parent changed after Open: %#v err=%v", afterOpen, err)
	}
	batch, err := ReadMigrationSourceBatch(ctx, path, "mail_direct_conversations", "", 10)
	if err != nil || len(batch.Rows) != 0 || !batch.Done {
		t.Fatalf("parent direct-conversation batch=%#v err=%v", batch, err)
	}
}

func TestInspectMigrationSourceCarriesRateBucketsThroughCurrentCutoverSurface(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, time.August, 18, 18, 30, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.SetRateLimits(tightRateLimits()); err != nil {
		t.Fatal(err)
	}
	conversation := createRateTestConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "one", "one", now)); err != nil {
		t.Fatal(err)
	}
	inspected, err := InspectMigrationSource(ctx, path)
	if err != nil || inspected.Version != 6 || inspected.Counts.RateBuckets != 2 {
		t.Fatalf("current inspect=%#v err=%v", inspected, err)
	}
	hasher, err := NewMigrationTableHasher("mail_rate_buckets")
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareMigrationSource(ctx, path, uuid.NewString(), strings.Repeat("d", 64), inspected.Fingerprint, now.Add(time.Minute))
	if err != nil || prepared.Version != 6 {
		t.Fatalf("current prepare=%#v err=%v", prepared, err)
	}
	batch, err := ReadMigrationSourceBatch(ctx, path, "mail_rate_buckets", "", 10)
	if err != nil || len(batch.Rows) != 2 || !batch.Done {
		t.Fatalf("current rate-bucket batch=%#v err=%v", batch, err)
	}
	for _, row := range batch.Rows {
		if err := hasher.Add(row); err != nil {
			t.Fatal(err)
		}
	}
	count, digest := hasher.Evidence()
	if count != inspected.Counts.RateBuckets || digest != inspected.TableSHA256.RateBuckets {
		t.Fatalf("rate-bucket evidence count=%d digest=%s want count=%d digest=%s", count, digest, inspected.Counts.RateBuckets, inspected.TableSHA256.RateBuckets)
	}
}

func TestInspectMigrationSourceExportsTelegramClaimsAndInboundMetadata(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, time.August, 19, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	conversation := createClaimedTelegramConversation(t, store, now)
	inbound, duplicate, err := store.AppendTelegramInbound(TelegramInboundInput{
		ConversationID: conversation.ID, SenderMachineID: "machine-telegram", FromEndpoint: TelegramGatewayEndpoint,
		FromParticipant: TelegramUserParticipant, Body: "ship it", InReplyToMessageID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
		InReplyToEndpoint: "agent/a", TelegramThreadID: 795446, IdempotencyKey: "telegram-update:7", Now: now,
	})
	if err != nil || duplicate || inbound.FromParticipant != TelegramUserParticipant || inbound.TelegramThreadID != 795446 {
		t.Fatalf("inbound=%#v duplicate=%t err=%v", inbound, duplicate, err)
	}
	inspected, err := InspectMigrationSource(ctx, path)
	if err != nil || inspected.Version != 6 || inspected.Counts.TelegramClaims != 1 || inspected.Counts.TelegramParticipants != 1 || inspected.Counts.TelegramClaimEvents != 1 {
		t.Fatalf("inspect=%#v err=%v", inspected, err)
	}
	prepared, err := PrepareMigrationSource(ctx, path, uuid.NewString(), strings.Repeat("e", 64), inspected.Fingerprint, now.Add(time.Minute))
	if err != nil || prepared.Version != 6 || prepared.Counts.TelegramClaims != 1 {
		t.Fatalf("prepare=%#v err=%v", prepared, err)
	}
	for _, table := range []string{"mail_telegram_claims", "mail_telegram_participants", "mail_telegram_claim_events"} {
		batch, err := ReadMigrationSourceBatch(ctx, path, table, "", 10)
		if err != nil || len(batch.Rows) != 1 || !batch.Done {
			t.Fatalf("table=%s batch=%#v err=%v", table, batch, err)
		}
		hasher, err := NewMigrationTableHasher(table)
		if err != nil {
			t.Fatal(err)
		}
		if err := hasher.Add(batch.Rows[0]); err != nil {
			t.Fatal(err)
		}
		count, digest := hasher.Evidence()
		var expectedCount int64
		var expectedDigest string
		switch table {
		case "mail_telegram_claims":
			expectedCount, expectedDigest = prepared.Counts.TelegramClaims, prepared.TableSHA256.TelegramClaims
		case "mail_telegram_participants":
			expectedCount, expectedDigest = prepared.Counts.TelegramParticipants, prepared.TableSHA256.TelegramParticipants
		case "mail_telegram_claim_events":
			expectedCount, expectedDigest = prepared.Counts.TelegramClaimEvents, prepared.TableSHA256.TelegramClaimEvents
		}
		if count != expectedCount || digest != expectedDigest {
			t.Fatalf("table=%s evidence count=%d digest=%s want count=%d digest=%s", table, count, digest, expectedCount, expectedDigest)
		}
		var payload map[string]any
		if err := json.Unmarshal(batch.Rows[0].Payload, &payload); err != nil {
			t.Fatal(err)
		}
		if payload["conversation_id"] != conversation.ID {
			t.Fatalf("table=%s conversation_id=%v", table, payload["conversation_id"])
		}
	}
	messages, err := ReadMigrationSourceBatch(ctx, path, "mail_messages", "", 10)
	if err != nil || len(messages.Rows) != 1 {
		t.Fatalf("messages batch=%#v err=%v", messages, err)
	}
	var message map[string]any
	if err := json.Unmarshal(messages.Rows[0].Payload, &message); err != nil {
		t.Fatal(err)
	}
	if message["from_participant"] != TelegramUserParticipant || message["in_reply_to_message_id"] != "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" || message["in_reply_to_endpoint"] != "agent/a" || message["telegram_thread_id"] != float64(795446) {
		t.Fatalf("message metadata=%#v", message)
	}
}

func TestInspectMigrationSourceAcceptsTokenReplyIDs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, time.August, 19, 14, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	conversation := createClaimedTelegramConversation(t, store, now)
	const replyID = "legacy-reply-token-1"
	if !ValidRequestToken(replyID) {
		t.Fatalf("fixture reply id %q is not a valid request token", replyID)
	}
	inbound, duplicate, err := store.AppendTelegramInbound(TelegramInboundInput{
		ConversationID: conversation.ID, SenderMachineID: "machine-telegram", FromEndpoint: TelegramGatewayEndpoint,
		FromParticipant: TelegramUserParticipant, Body: "reply", InReplyToMessageID: replyID,
		InReplyToEndpoint: "agent/a", TelegramThreadID: 11, IdempotencyKey: "telegram-update:token-reply", Now: now,
	})
	if err != nil || duplicate || inbound.InReplyToPunaroMessageID != replyID {
		t.Fatalf("inbound=%#v duplicate=%t err=%v", inbound, duplicate, err)
	}
	inspected, err := InspectMigrationSource(ctx, path)
	if err != nil || inspected.Counts.Messages != 1 {
		t.Fatalf("inspect token reply id=%#v err=%v", inspected, err)
	}
	prepared, err := PrepareMigrationSource(ctx, path, uuid.NewString(), strings.Repeat("a", 64), inspected.Fingerprint, now.Add(time.Minute))
	if err != nil || prepared.Counts.Messages != 1 {
		t.Fatalf("prepare token reply id=%#v err=%v", prepared, err)
	}
	batch, err := ReadMigrationSourceBatch(ctx, path, "mail_messages", "", 10)
	if err != nil || len(batch.Rows) != 1 {
		t.Fatalf("messages batch=%#v err=%v", batch, err)
	}
	var message map[string]any
	if err := json.Unmarshal(batch.Rows[0].Payload, &message); err != nil {
		t.Fatal(err)
	}
	if message["in_reply_to_message_id"] != replyID {
		t.Fatalf("exported reply id=%v", message["in_reply_to_message_id"])
	}
}

func TestInspectMigrationSourceExportsDisplayNameIdempotency(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, time.August, 19, 15, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "create-cutover-rename", CreatorEndpoint: "agent/a",
		Members: []Member{{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin}}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, duplicate, err := store.SetConversationDisplayName(SetDisplayNameInput{
		ConversationID: conversation.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a",
		DisplayName: "Alpha", IdempotencyKey: "rename-cutover-a", Now: now,
	}); err != nil || duplicate {
		t.Fatalf("rename err=%v duplicate=%v", err, duplicate)
	}
	inspected, err := InspectMigrationSource(ctx, path)
	if err != nil || inspected.Counts.DisplayNameIdempotency != 1 {
		t.Fatalf("inspect=%#v err=%v", inspected, err)
	}
	prepared, err := PrepareMigrationSource(ctx, path, uuid.NewString(), strings.Repeat("b", 64), inspected.Fingerprint, now.Add(time.Minute))
	if err != nil || prepared.Counts.DisplayNameIdempotency != 1 {
		t.Fatalf("prepare=%#v err=%v", prepared, err)
	}
	batch, err := ReadMigrationSourceBatch(ctx, path, "mail_conversation_display_name_idempotency", "", 10)
	if err != nil || len(batch.Rows) != 1 || !batch.Done {
		t.Fatalf("rename idempotency batch=%#v err=%v", batch, err)
	}
	hasher, err := NewMigrationTableHasher("mail_conversation_display_name_idempotency")
	if err != nil {
		t.Fatal(err)
	}
	if err := hasher.Add(batch.Rows[0]); err != nil {
		t.Fatal(err)
	}
	count, digest := hasher.Evidence()
	if count != prepared.Counts.DisplayNameIdempotency || digest != prepared.TableSHA256.DisplayNameIdempotency {
		t.Fatalf("evidence count=%d digest=%s want count=%d digest=%s", count, digest, prepared.Counts.DisplayNameIdempotency, prepared.TableSHA256.DisplayNameIdempotency)
	}
	var payload map[string]any
	if err := json.Unmarshal(batch.Rows[0].Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["key"] != "rename-cutover-a" || payload["conversation_id"] != conversation.ID {
		t.Fatalf("payload=%#v", payload)
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
