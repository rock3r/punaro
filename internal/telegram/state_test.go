package telegram

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

var testCallbackNow = time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)

func TestStateRecordsCompletedUpdatesAndRequiresExplicitTopicRoute(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	processed, err := state.Processed(42)
	if err != nil || processed {
		t.Fatalf("initial processed=%v err=%v", processed, err)
	}
	if err := state.MarkProcessed(42); err != nil {
		t.Fatal(err)
	}
	processed, err = state.Processed(42)
	if err != nil || !processed {
		t.Fatalf("completed processed=%v err=%v", processed, err)
	}
	if _, found, err := state.Route(100, 7); err != nil || found {
		t.Fatalf("unexpected route found=%v err=%v", found, err)
	}
	if err := state.SetRoute(100, 7, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	conversation, found, err := state.Route(100, 7)
	if err != nil || !found || conversation != "conversation-1" {
		t.Fatalf("route=%q found=%v err=%v", conversation, found, err)
	}
	chat, thread, found, err := state.RouteForConversation("conversation-1")
	if err != nil || !found || chat != 100 || thread != 7 {
		t.Fatalf("reverse route chat=%d thread=%d found=%v err=%v", chat, thread, found, err)
	}
	if err := state.SetRoute(100, 8, "conversation-1"); err == nil {
		t.Fatal("one conversation was mapped to more than one Telegram topic")
	}
}

func TestGatewayHealthSnapshotIsContentFreeAndReadOnly(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	database := filepath.Join(directory, "telegram.db")
	state, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	now := testCallbackNow
	if err := state.RecordGatewayCycle(GatewayCycleRecord{At: now, Offset: 11, PollOK: true, RelayOK: true, TelegramOK: true}); err != nil {
		t.Fatal(err)
	}
	if err := state.RecordGatewayCycle(GatewayCycleRecord{At: now.Add(time.Minute), Offset: 11, Failure: GatewayFailureTransient}); err != nil {
		t.Fatal(err)
	}
	if err := state.SetRoute(55, 7, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	if err := state.AdoptExecution("conversation-1", 7); err != nil {
		t.Fatal(err)
	}
	if err := state.MarkClaimComplete("conversation-1"); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(database) // #nosec G304 -- test-owned database path.
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := InspectGatewayState(t.Context(), database, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(database) // #nosec G304 -- test-owned database path.
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("doctor inspection changed the Telegram database")
	}
	if !snapshot.Integrity || !snapshot.RoutesConsistent || snapshot.RouteCount != 1 || snapshot.IncompleteClaims != 0 || snapshot.LastSuccessAge != 2*time.Minute || snapshot.LastCycleAge != time.Minute || snapshot.ConsecutiveFailures != 1 || snapshot.LastFailure != GatewayFailureTransient {
		t.Fatalf("snapshot=%#v", snapshot)
	}
}

func TestGatewayHealthSeparatesTerminalFailureClassesAndStuckProgress(t *testing.T) {
	t.Parallel()
	database := filepath.Join(t.TempDir(), "telegram.db")
	state, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	now := testCallbackNow
	cycles := []GatewayCycleRecord{
		{At: now, Offset: 8, Failure: GatewayFailureInboundRelayPermanent},
		{At: now.Add(time.Minute), Offset: 8, Failure: GatewayFailureOutboundTelegramPermanent, TerminalOutbound: 1, OutboundTargetEvents: []GatewayOutboundTargetEvent{{ConversationID: "conversation-1", Terminal: true}}},
		{At: now.Add(2 * time.Minute), Offset: 8, Failure: GatewayFailureDeletedTopic, TerminalOutbound: 1, OutboundTargetEvents: []GatewayOutboundTargetEvent{{ConversationID: "conversation-2", Terminal: true}}},
	}
	for _, cycle := range cycles {
		if err := state.RecordGatewayCycle(cycle); err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(3 * time.Minute)
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := InspectGatewayState(t.Context(), database, now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.TerminalInbound != 1 || snapshot.TerminalOutbound != 2 || snapshot.LastFailure != GatewayFailureDeletedTopic || snapshot.ConsecutiveFailures != 3 || !snapshot.StuckHead {
		t.Fatalf("snapshot=%#v", snapshot)
	}
}

func TestGatewayHealthRecordsBothTerminalPlanesFromOneCompletedCycle(t *testing.T) {
	t.Parallel()
	database := filepath.Join(t.TempDir(), "telegram.db")
	state, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	now := testCallbackNow
	if err := state.RecordGatewayCycle(GatewayCycleRecord{
		At: now, Offset: 12, PollOK: true, RelayOK: true,
		Failure:         GatewayFailureOutboundTelegramPermanent,
		TerminalInbound: 1, TerminalOutbound: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := InspectGatewayState(t.Context(), database, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.TerminalInbound != 1 || snapshot.TerminalOutbound != 1 || snapshot.LastFailure != GatewayFailureOutboundTelegramPermanent {
		t.Fatalf("snapshot=%#v", snapshot)
	}
}

func TestGatewayHealthOutboundStallIgnoresInboundOffsetProgress(t *testing.T) {
	t.Parallel()
	database := filepath.Join(t.TempDir(), "telegram.db")
	state, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	now := testCallbackNow
	for cycle := range 3 {
		if err := state.RecordGatewayCycle(GatewayCycleRecord{
			At:              now.Add(time.Duration(cycle) * time.Minute),
			Offset:          int64(8 + cycle),
			PollOK:          true,
			RelayOK:         true,
			Failure:         GatewayFailureOutboundTelegramPermanent,
			OutboundBlocked: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := InspectGatewayState(t.Context(), database, now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.StuckHead {
		t.Fatalf("continuous inbound progress masked a stuck outbound head: %#v", snapshot)
	}
}

func TestGatewayHealthPreservesBlockedHeadAcrossEarlierPhaseFailures(t *testing.T) {
	t.Parallel()
	database := filepath.Join(t.TempDir(), "telegram.db")
	state, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	now := testCallbackNow
	cycles := []GatewayCycleRecord{
		{At: now, Offset: 8, PollOK: true, RelayOK: true, OutboundBlocked: true, Failure: GatewayFailureTransient},
		{At: now.Add(4 * time.Minute), Offset: 9, Failure: GatewayFailureTransient},
		{At: now.Add(9 * time.Minute), Offset: 10, Failure: GatewayFailureTransient},
	}
	for _, cycle := range cycles {
		if err := state.RecordGatewayCycle(cycle); err != nil {
			t.Fatal(err)
		}
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := InspectGatewayState(t.Context(), database, now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.StuckHead {
		t.Fatalf("earlier-phase failures cleared the blocked outbound head age: %#v", snapshot)
	}
}

func TestGatewayHealthSuccessfulCycleClearsPreservedBlockedHead(t *testing.T) {
	t.Parallel()
	database := filepath.Join(t.TempDir(), "telegram.db")
	state, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	now := testCallbackNow
	cycles := []GatewayCycleRecord{
		{At: now, Offset: 8, PollOK: true, RelayOK: true, OutboundBlocked: true, Failure: GatewayFailureTransient},
		{At: now.Add(time.Minute), Offset: 9, Failure: GatewayFailureTransient},
		{At: now.Add(2 * time.Minute), Offset: 9, PollOK: true, RelayOK: true, TelegramOK: true},
	}
	for _, cycle := range cycles {
		if err := state.RecordGatewayCycle(cycle); err != nil {
			t.Fatal(err)
		}
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := InspectGatewayState(t.Context(), database, now.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.StuckHead || snapshot.ConsecutiveFailures != 0 {
		t.Fatalf("successful cycle did not clear the blocked outbound head: %#v", snapshot)
	}
}

func TestOpenMigratesOutboundProgressLedgerInPlace(t *testing.T) {
	t.Parallel()
	database := filepath.Join(t.TempDir(), "telegram.db")
	db, err := sql.Open("sqlite", database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), `CREATE TABLE gateway_health (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		last_cycle_at INTEGER NOT NULL,
		last_success_at INTEGER,
		last_poll_at INTEGER,
		last_relay_at INTEGER,
		last_telegram_at INTEGER,
		last_progress_at INTEGER NOT NULL,
		offset INTEGER NOT NULL,
		consecutive_failures INTEGER NOT NULL,
		last_failure TEXT NOT NULL,
		terminal_inbound INTEGER NOT NULL,
		terminal_outbound INTEGER NOT NULL
	)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	state, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = state.Close() }()
	if err := state.RecordGatewayCycle(GatewayCycleRecord{At: testCallbackNow, Offset: 1, PollOK: true, RelayOK: true, OutboundBlocked: true, Failure: GatewayFailureTransient}); err != nil {
		t.Fatal(err)
	}
	var columns int
	if err := state.db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM pragma_table_info('gateway_health') WHERE name IN ('last_outbound_progress_at','outbound_blocked')`).Scan(&columns); err != nil || columns != 2 {
		t.Fatalf("outbound progress columns=%d err=%v", columns, err)
	}
	var targetTables int
	if err := state.db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='gateway_terminal_outbound_targets'`).Scan(&targetTables); err != nil || targetTables != 1 {
		t.Fatalf("outbound target ledger tables=%d err=%v", targetTables, err)
	}
}

func TestGatewayHealthEmptyCyclePreservesTerminalFailures(t *testing.T) {
	t.Parallel()
	database := filepath.Join(t.TempDir(), "telegram.db")
	state, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	now := testCallbackNow
	for _, class := range []GatewayFailureClass{GatewayFailureInboundRelayPermanent, GatewayFailureOutboundTelegramPermanent, GatewayFailureDeletedTopic} {
		if err := state.RecordGatewayCycle(GatewayCycleRecord{At: now, Offset: 8, Failure: class}); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Minute)
	}
	if err := state.RecordGatewayCycle(GatewayCycleRecord{At: now, Offset: 9, PollOK: true, RelayOK: true, TelegramOK: true}); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := InspectGatewayState(t.Context(), database, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.TerminalInbound != 1 || snapshot.TerminalOutbound != 2 || snapshot.LastFailure != GatewayFailureDeletedTopic || snapshot.ConsecutiveFailures != 3 {
		t.Fatalf("empty cycle cleared terminal state: %#v", snapshot)
	}
}

func TestGatewayHealthClearsTerminalFailuresAfterPlaneRecovery(t *testing.T) {
	t.Parallel()
	database := filepath.Join(t.TempDir(), "telegram.db")
	state, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	now := testCallbackNow
	cycles := []GatewayCycleRecord{
		{At: now, Offset: 8, Failure: GatewayFailureInboundRelayPermanent},
		{At: now.Add(time.Minute), Offset: 8, Failure: GatewayFailureOutboundTelegramPermanent, TerminalOutbound: 1, OutboundTargetEvents: []GatewayOutboundTargetEvent{{ConversationID: "conversation-1", Terminal: true}}},
		{At: now.Add(2 * time.Minute), Offset: 8, Failure: GatewayFailureDeletedTopic, TerminalOutbound: 1, OutboundTargetEvents: []GatewayOutboundTargetEvent{{ConversationID: "conversation-2", Terminal: true}}},
	}
	for _, cycle := range cycles {
		if err := state.RecordGatewayCycle(cycle); err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(3 * time.Minute)
	if err := state.RecordGatewayCycle(GatewayCycleRecord{At: now, Offset: 9, PollOK: true, RelayOK: true, TelegramOK: true, InboundTargetEvents: []GatewayInboundTargetEvent{{ConversationID: "conversation-1"}}}); err != nil {
		t.Fatal(err)
	}
	var terminalInbound, terminalOutbound int
	var lastFailure string
	if err := state.db.QueryRowContext(t.Context(), `SELECT terminal_inbound,terminal_outbound,last_failure FROM gateway_health WHERE id=1`).Scan(&terminalInbound, &terminalOutbound, &lastFailure); err != nil || terminalInbound != 0 || terminalOutbound != 2 || GatewayFailureClass(lastFailure) != GatewayFailureDeletedTopic {
		t.Fatalf("partial recovery inbound=%d outbound=%d failure=%q err=%v", terminalInbound, terminalOutbound, lastFailure, err)
	}
	now = now.Add(time.Minute)
	if err := state.RecordGatewayCycle(GatewayCycleRecord{At: now, Offset: 9, PollOK: true, RelayOK: true, TelegramOK: true, OutboundTargetEvents: []GatewayOutboundTargetEvent{{ConversationID: "conversation-1"}}}); err != nil {
		t.Fatal(err)
	}
	if err := state.db.QueryRowContext(t.Context(), `SELECT terminal_outbound,last_failure FROM gateway_health WHERE id=1`).Scan(&terminalOutbound, &lastFailure); err != nil || terminalOutbound != 1 || GatewayFailureClass(lastFailure) != GatewayFailureDeletedTopic {
		t.Fatalf("first target recovery outbound=%d failure=%q err=%v", terminalOutbound, lastFailure, err)
	}
	now = now.Add(time.Minute)
	if err := state.RecordGatewayCycle(GatewayCycleRecord{At: now, Offset: 9, PollOK: true, RelayOK: true, TelegramOK: true, OutboundTargetEvents: []GatewayOutboundTargetEvent{{ConversationID: "conversation-2"}}}); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := InspectGatewayState(t.Context(), database, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.TerminalInbound != 0 || snapshot.TerminalOutbound != 0 || snapshot.LastFailure != GatewayFailureNone || snapshot.ConsecutiveFailures != 0 || snapshot.StuckHead {
		t.Fatalf("snapshot=%#v", snapshot)
	}
}

func TestGatewayHealthRequiresTargetSpecificOutboundRecovery(t *testing.T) {
	t.Parallel()
	database := filepath.Join(t.TempDir(), "telegram.db")
	state, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	now := testCallbackNow
	if err := state.RecordGatewayCycle(GatewayCycleRecord{
		At: now, Offset: 8, Failure: GatewayFailureDeletedTopic, TerminalOutbound: 1,
		OutboundTargetEvents: []GatewayOutboundTargetEvent{{ConversationID: "broken", Terminal: true}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := state.RecordGatewayCycle(GatewayCycleRecord{
		At: now.Add(time.Minute), Offset: 9, PollOK: true, RelayOK: true, TelegramOK: true,
		OutboundTargetEvents: []GatewayOutboundTargetEvent{{ConversationID: "healthy"}},
	}); err != nil {
		t.Fatal(err)
	}
	var terminalOutbound int
	if err := state.db.QueryRowContext(t.Context(), `SELECT terminal_outbound FROM gateway_health WHERE id=1`).Scan(&terminalOutbound); err != nil || terminalOutbound != 1 {
		t.Fatalf("healthy target cleared broken target: terminal=%d err=%v", terminalOutbound, err)
	}
	if err := state.RecordGatewayCycle(GatewayCycleRecord{
		At: now.Add(2 * time.Minute), Offset: 10, PollOK: true, RelayOK: true, TelegramOK: true,
		OutboundTargetEvents: []GatewayOutboundTargetEvent{{ConversationID: "broken"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := InspectGatewayState(t.Context(), database, now.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.TerminalOutbound != 0 || snapshot.LastFailure != GatewayFailureNone {
		t.Fatalf("matching target did not recover: %#v", snapshot)
	}
}

func TestGatewayHealthRequiresTargetSpecificInboundRecovery(t *testing.T) {
	t.Parallel()
	database := filepath.Join(t.TempDir(), "telegram.db")
	state, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	now := testCallbackNow
	if err := state.RecordGatewayCycle(GatewayCycleRecord{
		At: now, Offset: 8, Failure: GatewayFailureInboundRelayPermanent, TerminalInbound: 1,
		InboundTargetEvents: []GatewayInboundTargetEvent{{ConversationID: "broken", Terminal: true}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := state.RecordGatewayCycle(GatewayCycleRecord{
		At: now.Add(time.Minute), Offset: 9, PollOK: true, RelayOK: true, TelegramOK: true,
		InboundTargetEvents: []GatewayInboundTargetEvent{{ConversationID: "healthy"}},
	}); err != nil {
		t.Fatal(err)
	}
	var terminalInbound int
	if err := state.db.QueryRowContext(t.Context(), `SELECT terminal_inbound FROM gateway_health WHERE id=1`).Scan(&terminalInbound); err != nil || terminalInbound != 1 {
		t.Fatalf("healthy conversation cleared broken conversation: terminal=%d err=%v", terminalInbound, err)
	}
	if err := state.RecordGatewayCycle(GatewayCycleRecord{
		At: now.Add(2 * time.Minute), Offset: 10, PollOK: true, RelayOK: true, TelegramOK: true,
		InboundTargetEvents: []GatewayInboundTargetEvent{{ConversationID: "broken"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := InspectGatewayState(t.Context(), database, now.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.TerminalInbound != 0 || snapshot.LastFailure != GatewayFailureNone {
		t.Fatalf("matching conversation did not recover: %#v", snapshot)
	}
}

func TestOpenMigratesLegacyTerminalCountsIntoRecoverableTargets(t *testing.T) {
	t.Parallel()
	database := filepath.Join(t.TempDir(), "telegram.db")
	state, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.SetRoute(55, 7, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	if err := state.SetRoute(55, 8, "conversation-2"); err != nil {
		t.Fatal(err)
	}
	if err := state.RecordGatewayCycle(GatewayCycleRecord{At: testCallbackNow, Offset: 8, Failure: GatewayFailureDeletedTopic}); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	state, err = Open(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.RecordGatewayCycle(GatewayCycleRecord{At: testCallbackNow.Add(time.Minute), Offset: 9, PollOK: true, RelayOK: true, TelegramOK: true, OutboundTargetEvents: []GatewayOutboundTargetEvent{{ConversationID: "conversation-1"}}}); err != nil {
		t.Fatal(err)
	}
	var terminalOutbound int
	if err := state.db.QueryRowContext(t.Context(), `SELECT terminal_outbound FROM gateway_health WHERE id=1`).Scan(&terminalOutbound); err != nil || terminalOutbound != 1 {
		t.Fatalf("first migrated target recovery terminal=%d err=%v", terminalOutbound, err)
	}
	if err := state.RecordGatewayCycle(GatewayCycleRecord{At: testCallbackNow.Add(2 * time.Minute), Offset: 10, PollOK: true, RelayOK: true, TelegramOK: true, OutboundTargetEvents: []GatewayOutboundTargetEvent{{ConversationID: "conversation-2"}}}); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := InspectGatewayState(t.Context(), database, testCallbackNow.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.TerminalOutbound != 0 || snapshot.DeletedTopicTargets != 0 {
		t.Fatalf("migrated targets did not recover: %#v", snapshot)
	}
}

func TestGatewayHealthRetainsFailureClassPerOutboundTarget(t *testing.T) {
	t.Parallel()
	database := filepath.Join(t.TempDir(), "telegram.db")
	state, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	now := testCallbackNow
	if err := state.RecordGatewayCycle(GatewayCycleRecord{At: now, Offset: 8, Failure: GatewayFailureOutboundTelegramPermanent, TerminalOutbound: 1, OutboundTargetEvents: []GatewayOutboundTargetEvent{{ConversationID: "generic", Terminal: true}}}); err != nil {
		t.Fatal(err)
	}
	if err := state.RecordGatewayCycle(GatewayCycleRecord{At: now.Add(time.Minute), Offset: 9, Failure: GatewayFailureDeletedTopic, TerminalOutbound: 1, OutboundTargetEvents: []GatewayOutboundTargetEvent{{ConversationID: "deleted", Terminal: true}}}); err != nil {
		t.Fatal(err)
	}
	if err := state.RecordGatewayCycle(GatewayCycleRecord{At: now.Add(2 * time.Minute), Offset: 10, PollOK: true, RelayOK: true, TelegramOK: true, OutboundTargetEvents: []GatewayOutboundTargetEvent{{ConversationID: "deleted"}}}); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := InspectGatewayState(t.Context(), database, now.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.TerminalOutbound != 1 || snapshot.DeletedTopicTargets != 0 || snapshot.LastFailure != GatewayFailureOutboundTelegramPermanent {
		t.Fatalf("remaining target class was not retained: %#v", snapshot)
	}
}

func TestGatewayHealthRetainsDeletedClassWhenGenericTargetRecovers(t *testing.T) {
	t.Parallel()
	database := filepath.Join(t.TempDir(), "telegram.db")
	state, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	now := testCallbackNow
	for _, record := range []GatewayCycleRecord{
		{At: now, Offset: 8, Failure: GatewayFailureDeletedTopic, TerminalOutbound: 1, OutboundTargetEvents: []GatewayOutboundTargetEvent{{ConversationID: "deleted", Terminal: true, Failure: GatewayFailureDeletedTopic}}},
		{At: now.Add(time.Minute), Offset: 9, Failure: GatewayFailureOutboundTelegramPermanent, TerminalOutbound: 1, OutboundTargetEvents: []GatewayOutboundTargetEvent{{ConversationID: "generic", Terminal: true, Failure: GatewayFailureOutboundTelegramPermanent}}},
		{At: now.Add(2 * time.Minute), Offset: 10, PollOK: true, RelayOK: true, TelegramOK: true, OutboundTargetEvents: []GatewayOutboundTargetEvent{{ConversationID: "generic"}}},
	} {
		if err := state.RecordGatewayCycle(record); err != nil {
			t.Fatal(err)
		}
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := InspectGatewayState(t.Context(), database, now.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.TerminalOutbound != 1 || snapshot.DeletedTopicTargets != 1 || snapshot.LastFailure != GatewayFailureDeletedTopic {
		t.Fatalf("deleted target class was hidden: %#v", snapshot)
	}
}

func TestStageTerminalOutboundIsIdempotentByDelivery(t *testing.T) {
	t.Parallel()
	database := filepath.Join(t.TempDir(), "telegram.db")
	state, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := state.StageTerminalOutbound("delivery-1", "conversation-1", GatewayFailureDeletedTopic); err != nil {
			t.Fatal(err)
		}
	}
	if err := state.StageTerminalOutbound("delivery-1", "conversation-2", GatewayFailureDeletedTopic); err == nil {
		t.Fatal("delivery identity was rebound to another conversation")
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := InspectGatewayState(t.Context(), database, testCallbackNow)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.TerminalOutbound != 1 || snapshot.DeletedTopicTargets != 1 {
		t.Fatalf("duplicate staging changed terminal health: %#v", snapshot)
	}
}

func TestStageTerminalOutboundReconcilesRetryClassWithoutIncrementing(t *testing.T) {
	t.Parallel()
	database := filepath.Join(t.TempDir(), "telegram.db")
	state, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.StageTerminalOutbound("delivery-1", "conversation-1", GatewayFailureOutboundTelegramPermanent); err != nil {
		t.Fatal(err)
	}
	if err := state.StageTerminalOutbound("delivery-1", "conversation-1", GatewayFailureDeletedTopic); err != nil {
		t.Fatalf("changed retry class was rejected: %v", err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := InspectGatewayState(t.Context(), database, testCallbackNow)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.TerminalOutbound != 1 || snapshot.DeletedTopicTargets != 1 {
		t.Fatalf("retry class was not reconciled without double counting: %#v", snapshot)
	}
	state, err = Open(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.StageTerminalOutbound("delivery-1", "conversation-1", GatewayFailureOutboundTelegramPermanent); err != nil {
		t.Fatalf("changed retry class was rejected: %v", err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot, err = InspectGatewayState(t.Context(), database, testCallbackNow)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.TerminalOutbound != 1 || snapshot.DeletedTopicTargets != 0 {
		t.Fatalf("reverse retry class was not reconciled without double counting: %#v", snapshot)
	}
}

func TestInspectGatewayStateRejectsFutureHealthTimestamps(t *testing.T) {
	t.Parallel()
	database := filepath.Join(t.TempDir(), "telegram.db")
	state, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	now := testCallbackNow
	if err := state.RecordGatewayCycle(GatewayCycleRecord{At: now.Add(time.Minute), Offset: 9, PollOK: true, RelayOK: true, TelegramOK: true}); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectGatewayState(t.Context(), database, now); err == nil {
		t.Fatal("future gateway health timestamps were classified as fresh")
	}
}

func TestInspectGatewayStateHonorsCanceledContext(t *testing.T) {
	database := filepath.Join(t.TempDir(), "telegram.db")
	state, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := InspectGatewayState(ctx, database, testCallbackNow); err == nil {
		t.Fatal("canceled gateway state inspection continued with a fresh deadline")
	}
}

func TestStateIssuesHashedTTLCallbackTokens(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	now := testCallbackNow
	raw, err := state.IssueCallbackToken("conversation-1", now)
	if err != nil || raw == "" || raw == "conversation-1" || len(raw) != 64 {
		t.Fatalf("token=%q err=%v", raw, err)
	}
	conversation, found, consumed, err := state.lookupCallbackToken(raw, now)
	if err != nil || !found || consumed || conversation != "conversation-1" {
		t.Fatalf("lookup conversation=%q found=%v consumed=%v err=%v", conversation, found, consumed, err)
	}
	if stored, err := state.storedCallbackTokenHashes(); err != nil || len(stored) != 1 || stored[0] == raw || stored[0] == "conversation-1" {
		t.Fatalf("stored hashes=%#v err=%v", stored, err)
	}
	if _, found, _, err := state.lookupCallbackToken(raw, now.Add(callbackTokenTTL+time.Second)); err != nil || found {
		t.Fatal("expired token remained valid")
	}
	if _, err := state.IssueCallbackToken("conversation-2", now.Add(callbackTokenTTL+time.Minute)); err != nil {
		t.Fatal(err)
	}
	if hashes, err := state.storedCallbackTokenHashes(); err != nil || len(hashes) != 1 {
		t.Fatalf("expired token was not deleted on insert: hashes=%#v err=%v", hashes, err)
	}
	for i := 0; i < maxCallbackTokens; i++ {
		if _, err := state.IssueCallbackToken("conversation-bound", now.Add(2*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	count, err := state.outstandingCallbackTokens(now.Add(2 * time.Hour))
	if err != nil || count != maxCallbackTokens {
		t.Fatalf("outstanding=%d err=%v", count, err)
	}
	var claimExecutions int
	if err := state.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='claim_executions'`).Scan(&claimExecutions); err != nil || claimExecutions != 1 {
		t.Fatalf("claim_executions missing: count=%d err=%v", claimExecutions, err)
	}
}

func TestStateReservesClaimExecutionBeforeConsumingToken(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	now := testCallbackNow
	raw, err := state.IssueCallbackToken("conversation-1", now)
	if err != nil {
		t.Fatal(err)
	}
	conversation, reserved, err := state.ReserveClaimAndConsumeToken(raw, now)
	if err != nil || !reserved || conversation != "conversation-1" {
		t.Fatalf("reserved conversation=%q reserved=%v err=%v", conversation, reserved, err)
	}
	execution, found, err := state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseReserved || execution.ThreadID != 0 || execution.SkipReserve {
		t.Fatalf("execution=%#v found=%v err=%v", execution, found, err)
	}
	if _, found, consumed, err := state.lookupCallbackToken(raw, now); err != nil || !found || !consumed {
		t.Fatalf("token found=%v consumed=%v err=%v", found, consumed, err)
	}
	if _, reserved, err := state.ReserveClaimAndConsumeToken(raw, now); err != nil || reserved {
		t.Fatalf("replay reserved=%v err=%v", reserved, err)
	}
	if _, reserved, err := state.ReserveClaimAndConsumeToken("missing", now); err != nil || reserved {
		t.Fatalf("missing token reserved=%v err=%v", reserved, err)
	}
}

func TestOpenAddsClaimExecutionChatIDOnExistingDatabase(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "telegram.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(context.Background(), `CREATE TABLE claim_executions (conversation_id TEXT PRIMARY KEY, thread_id INTEGER, phase TEXT NOT NULL, display_name TEXT, skip_reserve INTEGER NOT NULL DEFAULT 0)`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.ExecContext(context.Background(), `INSERT INTO claim_executions(conversation_id, thread_id, phase, skip_reserve) VALUES ('conversation-1', NULL, 'reserved', 0)`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	state, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.PersistClaimThread("conversation-1", 55, 700001); err != nil {
		t.Fatal(err)
	}
	execution, found, err := state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseTopicCreated || execution.ThreadID != 700001 || execution.ChatID != 55 {
		t.Fatalf("upgraded execution=%#v found=%v err=%v", execution, found, err)
	}
}

func TestStatePersistsClaimThreadAndOutboundMap(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if _, err := state.InsertPendingExecution("conversation-1", "How is it going"); err != nil {
		t.Fatal(err)
	}
	if err := state.PersistClaimThread("conversation-1", 55, 700001); err != nil {
		t.Fatal(err)
	}
	execution, found, err := state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseTopicCreated || execution.ThreadID != 700001 || execution.ChatID != 55 || !execution.SkipReserve || execution.DisplayName != "How is it going" {
		t.Fatalf("after thread persist %#v found=%v err=%v", execution, found, err)
	}
	if err := state.PersistClaimRoute(55, 700001, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	if err := state.MarkClaimComplete("conversation-1"); err != nil {
		t.Fatal(err)
	}
	if complete, err := state.ClaimComplete("conversation-1"); err != nil || !complete {
		t.Fatalf("complete=%v err=%v", complete, err)
	}
	if err := state.RecordOutbound(55, 9, "conversation-1", "message-1", "agent/a", testCallbackNow); err != nil {
		t.Fatal(err)
	}
	ref, found, err := state.LookupOutbound(55, 9)
	if err != nil || !found || ref.ConversationID != "conversation-1" || ref.PunaroMessageID != "message-1" || ref.FromEndpoint != "agent/a" {
		t.Fatalf("outbound=%#v found=%v err=%v", ref, found, err)
	}
	if _, found, err := state.LookupOutbound(55, 10); err != nil || found {
		t.Fatal("missing outbound was found")
	}
}

func TestStateOpenAddsClaimExecutionChatID(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "telegram.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(context.Background(), `CREATE TABLE claim_executions (conversation_id TEXT PRIMARY KEY, thread_id INTEGER, phase TEXT NOT NULL, display_name TEXT, skip_reserve INTEGER NOT NULL DEFAULT 0)`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.ExecContext(context.Background(), `INSERT INTO claim_executions(conversation_id, phase, skip_reserve) VALUES ('conversation-1', 'reserved', 0)`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	state, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.PersistClaimThread("conversation-1", 55, 7); err != nil {
		t.Fatal(err)
	}
	execution, found, err := state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseTopicCreated || execution.ThreadID != 7 || execution.ChatID != 55 {
		t.Fatalf("upgraded execution=%#v found=%v err=%v", execution, found, err)
	}
}

func TestStateEvictsOldestOutboundAtCap(t *testing.T) {
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	previous := telegramOutboundLimit
	telegramOutboundLimit = 2
	t.Cleanup(func() { telegramOutboundLimit = previous })
	now := testCallbackNow
	if err := state.RecordOutbound(55, 1, "conversation-1", "message-1", "agent/a", now); err != nil {
		t.Fatal(err)
	}
	if err := state.RecordOutbound(55, 2, "conversation-1", "message-2", "agent/a", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := state.RecordOutbound(55, 3, "conversation-1", "message-3", "agent/a", now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, found, err := state.LookupOutbound(55, 1); err != nil || found {
		t.Fatal("oldest outbound was not evicted")
	}
	if _, found, err := state.LookupOutbound(55, 2); err != nil || !found {
		t.Fatal("kept outbound is missing")
	}
	if _, found, err := state.LookupOutbound(55, 3); err != nil || !found {
		t.Fatal("newest outbound is missing")
	}
}

func TestStateRefusesClaimedRouteRemap(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.SetRoute(55, 7, "conversation-claimed"); err != nil {
		t.Fatal(err)
	}
	if err := state.AdoptExecution("conversation-claimed", 7); err != nil {
		t.Fatal(err)
	}
	if err := state.MarkClaimComplete("conversation-claimed"); err != nil {
		t.Fatal(err)
	}
	if err := state.RouteBlocked(55, 8, "conversation-claimed"); err == nil {
		t.Fatal("claimed conversation remapped")
	}
	if err := state.RouteBlocked(55, 7, "conversation-other"); err == nil {
		t.Fatal("claimed thread stolen")
	}
	if err := state.RouteBlocked(55, 9, "conversation-free"); err != nil {
		t.Fatalf("unclaimed remap blocked: %v", err)
	}
}

func TestStateSetRouteRefusesAfterConcurrentClaimProtectsThread(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.RouteBlocked(55, 7, "conversation-emergency"); err != nil {
		t.Fatalf("unclaimed fence err=%v", err)
	}
	if _, _, err := state.ReserveClaimAndConsumeTokenMust(t, "conversation-claimed"); err != nil {
		t.Fatal(err)
	}
	if err := state.PersistClaimThread("conversation-claimed", 55, 7); err != nil {
		t.Fatal(err)
	}
	if err := state.PersistClaimRoute(55, 7, "conversation-claimed"); err != nil {
		t.Fatal(err)
	}
	if err := state.SetRoute(55, 7, "conversation-emergency"); err == nil {
		t.Fatal("emergency route overwrote a claim-protected thread")
	}
	conversation, found, err := state.Route(55, 7)
	if err != nil || !found || conversation != "conversation-claimed" {
		t.Fatalf("protected route=%q found=%v err=%v", conversation, found, err)
	}
}

func TestBeginClaimCreatingReusesRouteInsertedBeforeCreatingFence(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if _, _, err := state.ReserveClaimAndConsumeTokenMust(t, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	if err := state.SetRoute(55, 7, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	chatID, threadID, creating, err := state.BeginClaimCreating("conversation-1", 55)
	if err != nil || creating || chatID != 55 || threadID != 7 {
		t.Fatalf("creating=%t chat=%d thread=%d err=%v", creating, chatID, threadID, err)
	}
	execution, found, err := state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseTopicCreated || execution.ThreadID != 7 || execution.ChatID != 55 {
		t.Fatalf("execution=%#v found=%v err=%v", execution, found, err)
	}
}

func TestBeginClaimCreatingLeavesReservedWhenRacedRouteIsForeign(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if _, _, err := state.ReserveClaimAndConsumeTokenMust(t, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	if err := state.SetRoute(99, 7, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := state.BeginClaimCreating("conversation-1", 55); err == nil || err.Error() != "telegram_route_persist_failed" {
		t.Fatalf("foreign route err=%v", err)
	}
	execution, found, err := state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseReserved || execution.ThreadID != 0 {
		t.Fatalf("wedged execution=%#v found=%v err=%v", execution, found, err)
	}
	if err := state.RouteBlocked(55, 8, "conversation-1"); err != nil {
		t.Fatalf("reserved execution blocked route correction: %v", err)
	}
}

func TestBeginClaimCreatingDoesNotSplitFromConcurrentSetRoute(t *testing.T) {
	t.Parallel()
	for i := 0; i < 40; i++ {
		state, err := Open(filepath.Join(t.TempDir(), fmt.Sprintf("telegram-create-%d.db", i)))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := state.ReserveClaimAndConsumeTokenMust(t, "conversation-a"); err != nil {
			_ = state.Close()
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _, _, _ = state.BeginClaimCreating("conversation-a", 55)
		}()
		go func() {
			defer wg.Done()
			_ = state.SetRoute(55, 1, "conversation-a")
		}()
		wg.Wait()
		execution, execFound, err := state.ClaimExecution("conversation-a")
		if err != nil || !execFound {
			_ = state.Close()
			t.Fatalf("iter %d missing execution found=%v err=%v", i, execFound, err)
		}
		owner, found, err := state.Route(55, 1)
		if err != nil {
			_ = state.Close()
			t.Fatal(err)
		}
		if found && owner != "conversation-a" {
			_ = state.Close()
			t.Fatalf("iter %d unexpected owner=%q execution=%#v", i, owner, execution)
		}
		if execution.Phase == ClaimPhaseCreating && found {
			_ = state.Close()
			t.Fatalf("iter %d creating after concurrent route owner=%q execution=%#v", i, owner, execution)
		}
		_ = state.Close()
	}
}

func TestStateRouteBlockedTreatsCreatingAndTopicCreatedAsClaimed(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if _, _, err := state.ReserveClaimAndConsumeTokenMust(t, "conversation-creating"); err != nil {
		t.Fatal(err)
	}
	if err := state.PersistClaimCreating("conversation-creating"); err != nil {
		t.Fatal(err)
	}
	if err := state.RouteBlocked(55, 8, "conversation-creating"); err != nil {
		t.Fatalf("unthreaded creating blocked emergency route: %v", err)
	}
	if err := state.SetRoute(55, 8, "conversation-creating"); err != nil {
		t.Fatalf("emergency route during unthreaded creating: %v", err)
	}
	execution, found, err := state.ClaimExecution("conversation-creating")
	if err != nil || !found || execution.Phase != ClaimPhaseTopicCreated || execution.ThreadID != 8 || execution.ChatID != 55 {
		t.Fatalf("bound creating execution=%#v found=%v err=%v", execution, found, err)
	}
	if err := state.RouteBlocked(55, 8, "conversation-other"); err == nil {
		t.Fatal("unthreaded creating thread stolen")
	}
	if _, _, err := state.ReserveClaimAndConsumeTokenMust(t, "conversation-topic"); err != nil {
		t.Fatal(err)
	}
	if err := state.PersistClaimThread("conversation-topic", 55, 7); err != nil {
		t.Fatal(err)
	}
	if err := state.RouteBlocked(55, 8, "conversation-topic"); err == nil {
		t.Fatal("topic_created conversation remapped")
	}
	if err := state.RouteBlocked(55, 9, "conversation-free"); err != nil {
		t.Fatalf("unclaimed remap blocked: %v", err)
	}
}

func TestStateRouteBlockedTreatsRoutePersistedAsClaimed(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if _, _, err := state.ReserveClaimAndConsumeTokenMust(t, "conversation-claimed"); err != nil {
		t.Fatal(err)
	}
	if err := state.PersistClaimThread("conversation-claimed", 55, 7); err != nil {
		t.Fatal(err)
	}
	if err := state.PersistClaimRoute(55, 7, "conversation-claimed"); err != nil {
		t.Fatal(err)
	}
	if err := state.RouteBlocked(55, 8, "conversation-claimed"); err == nil {
		t.Fatal("route_persisted conversation remapped")
	}
	if err := state.RouteBlocked(55, 7, "conversation-other"); err == nil {
		t.Fatal("route_persisted thread stolen")
	}
	if err := state.RouteBlocked(55, 9, "conversation-free"); err != nil {
		t.Fatalf("unclaimed remap blocked: %v", err)
	}
}

func TestStatePersistClaimRouteDoesNotStealAnotherConversationThread(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.SetRoute(55, 7, "conversation-owner"); err != nil {
		t.Fatal(err)
	}
	if err := state.AdoptExecution("conversation-owner", 7); err != nil {
		t.Fatal(err)
	}
	if err := state.MarkClaimComplete("conversation-owner"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := state.ReserveClaimAndConsumeTokenMust(t, "conversation-thief"); err != nil {
		t.Fatal(err)
	}
	if err := state.PersistClaimThread("conversation-thief", 55, 7); err != nil {
		t.Fatal(err)
	}
	if err := state.PersistClaimRoute(55, 7, "conversation-thief"); err == nil {
		t.Fatal("PersistClaimRoute stole another conversation's thread")
	}
	conversation, found, err := state.Route(55, 7)
	if err != nil || !found || conversation != "conversation-owner" {
		t.Fatalf("stolen route conversation=%q found=%v err=%v", conversation, found, err)
	}
}

func TestStatePersistClaimRouteRejectsDifferentChat(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.SetRoute(55, 7, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := state.ReserveClaimAndConsumeTokenMust(t, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	if err := state.PersistClaimThread("conversation-1", 55, 7); err != nil {
		t.Fatal(err)
	}
	if err := state.PersistClaimRoute(99, 1, "conversation-1"); err == nil {
		t.Fatal("PersistClaimRoute reused a route from a different chat")
	}
	conversation, found, err := state.Route(55, 7)
	if err != nil || !found || conversation != "conversation-1" {
		t.Fatalf("original route conversation=%q found=%v err=%v", conversation, found, err)
	}
	if _, found, err := state.Route(99, 1); err != nil || found {
		t.Fatal("wrong-chat route was inserted")
	}
	execution, found, err := state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseTopicCreated || execution.ThreadID != 7 {
		t.Fatalf("execution=%#v found=%v err=%v", execution, found, err)
	}
}

func TestStatePersistClaimRouteReusesExistingConversationThread(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.SetRoute(55, 700001, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := state.ReserveClaimAndConsumeTokenMust(t, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	if err := state.PersistClaimThread("conversation-1", 55, 1); err != nil {
		t.Fatal(err)
	}
	if err := state.PersistClaimRoute(55, 1, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	execution, found, err := state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseRoutePersisted || execution.ThreadID != 700001 {
		t.Fatalf("reuse execution=%#v found=%v err=%v", execution, found, err)
	}
	conversation, found, err := state.Route(55, 700001)
	if err != nil || !found || conversation != "conversation-1" {
		t.Fatalf("kept route conversation=%q found=%v err=%v", conversation, found, err)
	}
	if _, found, err := state.Route(55, 1); err != nil || found {
		t.Fatal("second thread was inserted for the same conversation")
	}
}

func TestAdoptExistingRoutePersistsAdoptingFence(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.SetRoute(55, 700001, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	threadID, err := state.AdoptExistingRoute("conversation-1", 55)
	if err != nil || threadID != 700001 {
		t.Fatalf("adopt fence thread=%d err=%v", threadID, err)
	}
	execution, found, err := state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseAdopting || execution.ThreadID != 700001 || execution.ChatID != 55 || !execution.SkipReserve {
		t.Fatalf("adopting fence execution=%#v found=%v err=%v", execution, found, err)
	}
	if err := state.SetRoute(55, 700001, "conversation-other"); err == nil {
		t.Fatal("adopting fence allowed a remapped route")
	}
	if err := state.PersistClaimAdoptReserved("conversation-1"); err != nil {
		t.Fatal(err)
	}
	execution, found, err = state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseRoutePersisted {
		t.Fatalf("after adopt reserve execution=%#v found=%v err=%v", execution, found, err)
	}
}

func TestAdoptExistingRouteDoesNotSplitFromConcurrentSetRoute(t *testing.T) {
	t.Parallel()
	for i := 0; i < 40; i++ {
		state, err := Open(filepath.Join(t.TempDir(), fmt.Sprintf("telegram-%d.db", i)))
		if err != nil {
			t.Fatal(err)
		}
		if err := state.SetRoute(55, 1, "conversation-a"); err != nil {
			_ = state.Close()
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = state.AdoptExistingRoute("conversation-a", 55)
		}()
		go func() {
			defer wg.Done()
			_ = state.SetRoute(55, 1, "conversation-b")
		}()
		wg.Wait()
		owner, found, err := state.Route(55, 1)
		if err != nil || !found {
			_ = state.Close()
			t.Fatalf("iter %d missing route found=%v err=%v", i, found, err)
		}
		execution, execFound, err := state.ClaimExecution("conversation-a")
		if err != nil {
			_ = state.Close()
			t.Fatal(err)
		}
		if execFound && (execution.Phase == ClaimPhaseAdopting || execution.Phase == ClaimPhaseRoutePersisted || execution.Phase == ClaimPhaseComplete) {
			if owner != "conversation-a" || execution.ThreadID != 1 {
				_ = state.Close()
				t.Fatalf("iter %d split mapping owner=%q execution=%#v", i, owner, execution)
			}
		}
		if owner == "conversation-b" && execFound && (execution.Phase == ClaimPhaseAdopting || execution.Phase == ClaimPhaseRoutePersisted || execution.Phase == ClaimPhaseComplete) {
			_ = state.Close()
			t.Fatalf("iter %d claimed conversation-a while thread belongs to conversation-b: %#v", i, execution)
		}
		_ = state.Close()
	}
}

func TestStateEvictsOldestCallbackTokenAtCap(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	now := testCallbackNow
	tokens := make([]string, maxCallbackTokens)
	for i := range tokens {
		token, err := state.IssueCallbackToken(fmt.Sprintf("conversation-%d", i), now)
		if err != nil {
			t.Fatal(err)
		}
		tokens[i] = token
	}
	newest, err := state.IssueCallbackToken("conversation-new", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, _, err := state.lookupCallbackToken(tokens[0], now); err != nil || found {
		t.Fatal("oldest outstanding token was not evicted")
	}
	for i, token := range tokens[1:] {
		if conversation, found, consumed, err := state.lookupCallbackToken(token, now); err != nil || !found || consumed || conversation != fmt.Sprintf("conversation-%d", i+1) {
			t.Fatalf("kept token %d missing: found=%v consumed=%v conversation=%q err=%v", i+1, found, consumed, conversation, err)
		}
	}
	if conversation, found, consumed, err := state.lookupCallbackToken(newest, now); err != nil || !found || consumed || conversation != "conversation-new" {
		t.Fatalf("just-issued token was evicted: found=%v consumed=%v conversation=%q err=%v", found, consumed, conversation, err)
	}
	count, err := state.outstandingCallbackTokens(now)
	if err != nil || count != maxCallbackTokens {
		t.Fatalf("outstanding=%d err=%v", count, err)
	}
}

func (s *State) lookupCallbackToken(raw string, now time.Time) (string, bool, bool, error) {
	var conversation string
	var expiresAt int64
	var consumedAt sql.NullInt64
	err := s.db.QueryRowContext(context.Background(), `SELECT conversation_id, expires_at, consumed_at FROM callback_tokens WHERE token_hash = ?`, callbackTokenHash(raw)).Scan(&conversation, &expiresAt, &consumedAt)
	if err == sql.ErrNoRows {
		return "", false, false, nil
	}
	if err != nil {
		return "", false, false, err
	}
	if expiresAt <= now.UnixMilli() {
		return conversation, false, consumedAt.Valid, nil
	}
	return conversation, true, consumedAt.Valid, nil
}

func (s *State) storedCallbackTokenHashes() ([]string, error) {
	rows, err := s.db.QueryContext(context.Background(), `SELECT token_hash FROM callback_tokens ORDER BY expires_at`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var hashes []string
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return nil, err
		}
		hashes = append(hashes, hash)
	}
	return hashes, rows.Err()
}

func (s *State) outstandingCallbackTokens(now time.Time) (int, error) {
	var count int
	err := s.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM callback_tokens WHERE consumed_at IS NULL AND expires_at > ?`, now.UnixMilli()).Scan(&count)
	return count, err
}
