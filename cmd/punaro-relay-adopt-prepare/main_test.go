package main

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rock3r/punaro/internal/relay"
	_ "modernc.org/sqlite"
)

func TestRunRequiresYesAndCompleteFlags(t *testing.T) {
	t.Parallel()
	database := filepath.Join(t.TempDir(), "relay.db")
	valid := []string{
		"--relay-db", database,
		"--keeper", "keeper-id",
		"--non-keeper", "non-keeper-id",
		"--non-keeper-name", "Non-keeper topic",
		"--drop-role", relay.TelegramCodexRole,
		"--yes",
	}
	tests := []struct {
		name string
		args []string
	}{
		{name: "empty", args: nil},
		{name: "missing yes", args: withoutFlag(valid, "--yes")},
		{name: "missing relay-db", args: withoutFlag(valid, "--relay-db")},
		{name: "missing keeper", args: withoutFlag(valid, "--keeper")},
		{name: "missing non-keeper", args: withoutFlag(valid, "--non-keeper")},
		{name: "missing non-keeper-name", args: withoutFlag(valid, "--non-keeper-name")},
		{name: "missing drop-role", args: withoutFlag(valid, "--drop-role")},
		{name: "wrong drop-role", args: withFlag(valid, "--drop-role", "role/other")},
		{name: "trailing argument", args: append(append([]string{}, valid...), "unexpected")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var stderr bytes.Buffer
			if code := run(test.args, &bytes.Buffer{}, &stderr); code != 2 {
				t.Fatalf("run()=%d want 2; stderr=%q", code, stderr.String())
			}
		})
	}
}

func TestRunPreparesSharedRoleUnnamedPair(t *testing.T) {
	t.Parallel()
	database := filepath.Join(t.TempDir(), "relay.db")
	store, err := relay.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 16, 18, 0, 0, 0, time.UTC)
	keeper, nonKeeper := createSharedTelegramRolePair(t, store, now)
	if _, _, err := store.AppendMessage(relay.AppendInput{
		ConversationID:  nonKeeper.ID,
		SenderMachineID: "machine-telegram",
		FromEndpoint:    relay.TelegramPrimaryEndpoint,
		Body:            "pending for the shared role",
		IdempotencyKey:  "role-delivery",
		Now:             now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(relay.AppendInput{
		ConversationID:  keeper.ID,
		SenderMachineID: "machine-telegram",
		FromEndpoint:    relay.TelegramPrimaryEndpoint,
		Body:            "pending on the keeper",
		IdempotencyKey:  "keeper-role-delivery",
		Now:             now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--relay-db", database,
		"--keeper", keeper.ID,
		"--non-keeper", nonKeeper.ID,
		"--non-keeper-name", "Non-keeper topic",
		"--drop-role", relay.TelegramCodexRole,
		"--yes",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run()=%d stderr=%q", code, stderr.String())
	}

	store, err = relay.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	visible, err := store.ConversationsForMachine("studio-validation", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(visible) != 1 || visible[0].ID != keeper.ID || visible[0].DisplayName != "Keeper topic" {
		t.Fatalf("role occupancy after prepare=%#v", visible)
	}
	telegramRooms, err := store.ConversationsForMachine("machine-telegram", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !conversationNamed(telegramRooms, nonKeeper.ID, "Non-keeper topic") {
		t.Fatalf("non-keeper after prepare=%#v", telegramRooms)
	}
	if unacked, err := unackedRoleDeliveries(database, nonKeeper.ID); err != nil || unacked != 0 {
		t.Fatalf("leftover role deliveries still unacked count=%d err=%v", unacked, err)
	}
	if keeperUnacked, err := unackedRoleDeliveries(database, keeper.ID); err != nil || keeperUnacked != 1 {
		t.Fatalf("keeper role delivery unacked=%d err=%v", keeperUnacked, err)
	}
	if cursor, nextSequence, err := roleCursorAndNextSequence(database, nonKeeper.ID); err != nil || cursor != nextSequence {
		t.Fatalf("non-keeper role cursor=%d next_sequence=%d err=%v", cursor, nextSequence, err)
	}
	if capabilities, err := telegramPrimaryCapabilities(database, nonKeeper.ID); err != nil || capabilities != relay.CapSend|relay.CapReceive {
		t.Fatalf("telegram/primary capabilities=%d err=%v, want send|receive only", capabilities, err)
	}
}

func TestRunDoesNotTalkToRelayHTTP(t *testing.T) {
	t.Parallel()
	var stderr bytes.Buffer
	if code := run([]string{
		"--relay-db", filepath.Join(t.TempDir(), "relay.db"),
		"--keeper", "keeper-id",
		"--non-keeper", "non-keeper-id",
		"--non-keeper-name", "Non-keeper topic",
		"--drop-role", relay.TelegramCodexRole,
		"--relay-url", "http://127.0.0.1:1",
		"--yes",
	}, &bytes.Buffer{}, &stderr); code != 2 {
		t.Fatalf("run()=%d want 2 for unknown HTTP flag; stderr=%q", code, stderr.String())
	}
}

func TestRunRefusesMissingRelayDBAndPrintsOpenError(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "missing", "relay.db")
	var stderr bytes.Buffer
	code := run([]string{
		"--relay-db", missing,
		"--keeper", "keeper-id",
		"--non-keeper", "non-keeper-id",
		"--non-keeper-name", "Non-keeper topic",
		"--drop-role", relay.TelegramCodexRole,
		"--yes",
	}, &bytes.Buffer{}, &stderr)
	if code != 1 {
		t.Fatalf("run()=%d want 1; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "failed:") || !strings.Contains(stderr.String(), "missing") {
		t.Fatalf("stderr=%q, want printed open/missing error", stderr.String())
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("missing --relay-db created %s err=%v", missing, err)
	}
	if _, err := os.Stat(filepath.Dir(missing)); !os.IsNotExist(err) {
		t.Fatalf("missing --relay-db created parent directory err=%v", err)
	}
}

func createSharedTelegramRolePair(t *testing.T, store *relay.Store, now time.Time) (relay.Conversation, relay.Conversation) {
	t.Helper()
	for machine, endpoint := range map[string]string{
		"machine-creator":   "agent/creator",
		"machine-telegram":  relay.TelegramPrimaryEndpoint,
		"studio-validation": "agent/punaro-studio/validation",
	} {
		if err := store.AdvertiseEndpoints(machine, []string{endpoint}, now, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	members := []relay.Member{
		{Endpoint: "agent/creator", Capabilities: relay.CapSend | relay.CapReceive | relay.CapAdmin},
		{Endpoint: relay.TelegramPrimaryEndpoint, Capabilities: relay.CapSend | relay.CapReceive},
		{Role: relay.TelegramCodexRole, RoleMachineID: "studio-validation", Capabilities: relay.CapSend | relay.CapReceive | relay.CapAdmin},
	}
	keeper, err := store.CreateConversation("agent/creator", members, now)
	if err != nil || keeper.DisplayName != "" {
		t.Fatalf("keeper unnamed=%#v err=%v", keeper, err)
	}
	nonKeeper, err := store.CreateConversation("agent/creator", members, now)
	if err != nil || nonKeeper.DisplayName != "" || nonKeeper.ID == keeper.ID {
		t.Fatalf("non-keeper unnamed=%#v keeper=%#v err=%v", nonKeeper, keeper, err)
	}
	for _, id := range []string{keeper.ID, nonKeeper.ID} {
		if _, _, err := store.ApplyControl(relay.ControlInput{
			ConversationID: id, ActorMachineID: "machine-creator", ActorEndpoint: "agent/creator",
			Operation: relay.ControlRemoveMember, Member: relay.Member{Endpoint: "agent/creator"},
			IdempotencyKey: "remove-creator-" + id, Now: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.BindRoleToSession("studio-validation", relay.TelegramCodexRole, "agent/punaro-studio/validation", now, time.Hour); err != nil {
		t.Fatal(err)
	}
	renamed, _, err := store.SetConversationDisplayName(relay.SetDisplayNameInput{
		ConversationID: keeper.ID, ActorMachineID: "studio-validation", ActorEndpoint: "agent/punaro-studio/validation",
		DisplayName: "Keeper topic", IdempotencyKey: "rename-keeper", Now: now,
	})
	if err != nil || renamed.DisplayName != "Keeper topic" {
		t.Fatalf("rename keeper=%#v err=%v", renamed, err)
	}
	return keeper, nonKeeper
}

func conversationNamed(rooms []relay.Conversation, id, name string) bool {
	for _, room := range rooms {
		if room.ID == id && room.DisplayName == name {
			return true
		}
	}
	return false
}

func unackedRoleDeliveries(database, conversationID string) (int, error) {
	db, err := sql.Open("sqlite", database)
	if err != nil {
		return 0, err
	}
	defer func() { _ = db.Close() }()
	var count int
	err = db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM deliveries
		WHERE recipient_endpoint=? AND acked_at IS NULL
		  AND message_id IN (SELECT id FROM messages WHERE conversation_id=?)`, "\x1erole:"+relay.TelegramCodexRole, conversationID).Scan(&count)
	return count, err
}

func roleCursorAndNextSequence(database, conversationID string) (int64, int64, error) {
	db, err := sql.Open("sqlite", database)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = db.Close() }()
	var cursor, nextSequence int64
	if err := db.QueryRowContext(context.Background(), "SELECT sequence FROM recipient_cursors WHERE recipient_endpoint=? AND conversation_id=?", "\x1erole:"+relay.TelegramCodexRole, conversationID).Scan(&cursor); err != nil {
		return 0, 0, err
	}
	if err := db.QueryRowContext(context.Background(), "SELECT next_sequence FROM conversations WHERE id=?", conversationID).Scan(&nextSequence); err != nil {
		return 0, 0, err
	}
	return cursor, nextSequence, nil
}

func telegramPrimaryCapabilities(database, conversationID string) (relay.Capability, error) {
	db, err := sql.Open("sqlite", database)
	if err != nil {
		return 0, err
	}
	defer func() { _ = db.Close() }()
	var capabilities relay.Capability
	err = db.QueryRowContext(context.Background(), "SELECT capabilities FROM memberships WHERE conversation_id=? AND endpoint=?", conversationID, relay.TelegramPrimaryEndpoint).Scan(&capabilities)
	return capabilities, err
}

func withoutFlag(arguments []string, flagName string) []string {
	result := make([]string, 0, len(arguments))
	for index := 0; index < len(arguments); index++ {
		if arguments[index] == flagName {
			if flagName != "--yes" && index+1 < len(arguments) && !strings.HasPrefix(arguments[index+1], "--") {
				index++
			}
			continue
		}
		result = append(result, arguments[index])
	}
	return result
}

func withFlag(arguments []string, flagName, value string) []string {
	result := append([]string{}, arguments...)
	for index := 0; index < len(result); index++ {
		if result[index] == flagName && index+1 < len(result) {
			result[index+1] = value
			return result
		}
	}
	return append(result, flagName, value)
}
