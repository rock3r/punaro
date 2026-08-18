package relay

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStoreRegistersCanonicalRoleAndExactRetry(t *testing.T) {
	t.Parallel()
	store := openRoleProfileStore(t)
	now := time.Date(2026, time.August, 18, 16, 0, 0, 0, time.UTC)
	input := RegisterRoleInput{
		MachineID:      "machine-a",
		Role:           "role/machine-a/reviewer",
		DisplayName:    "  Plan Reviewer  ",
		IdempotencyKey: "register-1",
		Now:            now,
	}
	first, created, err := store.RegisterRoleProfile(input)
	if err != nil || !created {
		t.Fatalf("first register=%#v created=%t err=%v", first, created, err)
	}
	if first.Role != "role/machine-a/reviewer" || first.DisplayName != "Plan Reviewer" || first.DirectAddressable || !first.UpdatedAt.Equal(now) {
		t.Fatalf("first profile=%#v", first)
	}
	retry, created, err := store.RegisterRoleProfile(input)
	if err != nil || created || retry != first {
		t.Fatalf("retry=%#v created=%t err=%v", retry, created, err)
	}
	changed := input
	changed.DisplayName = "Other"
	if _, _, err := store.RegisterRoleProfile(changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed-body retry err=%v", err)
	}
	read, err := store.RoleProfile("role/machine-a/reviewer")
	if err != nil || read != first {
		t.Fatalf("read=%#v err=%v", read, err)
	}
}

func TestStoreRoleRegistrationRejectsInvalidHandlesAndDisplayNames(t *testing.T) {
	t.Parallel()
	store := openRoleProfileStore(t)
	now := time.Date(2026, time.August, 18, 16, 0, 0, 0, time.UTC)
	base := RegisterRoleInput{MachineID: "machine-a", Role: "role/machine-a/reviewer", IdempotencyKey: "invalid-1", Now: now}
	tests := []struct {
		name  string
		input RegisterRoleInput
	}{
		{name: "wrong machine prefix", input: withRoleRegister(base, func(input *RegisterRoleInput) { input.Role = "role/machine-b/reviewer" })},
		{name: "legacy role name", input: withRoleRegister(base, func(input *RegisterRoleInput) { input.Role = "role/plan-reviewer" })},
		{name: "uppercase slug", input: withRoleRegister(base, func(input *RegisterRoleInput) { input.Role = "role/machine-a/Reviewer" })},
		{name: "invalid slug", input: withRoleRegister(base, func(input *RegisterRoleInput) { input.Role = "role/machine-a/_bad" })},
		{name: "empty slug", input: withRoleRegister(base, func(input *RegisterRoleInput) { input.Role = "role/machine-a/" })},
		{name: "oversized display name", input: withRoleRegister(base, func(input *RegisterRoleInput) { input.DisplayName = strings.Repeat("n", 129) })},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := store.RegisterRoleProfile(test.input)
			if err == nil || errors.Is(err, ErrForbidden) || errors.Is(err, ErrConflict) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestStoreRoleRegistrationRejectsOwnershipTakeover(t *testing.T) {
	t.Parallel()
	store := openRoleProfileStore(t)
	now := time.Date(2026, time.August, 18, 16, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateConversation("agent/a", []Member{
		{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
		{Role: "role/machine-a/reviewer", RoleMachineID: "machine-b", Capabilities: CapReceive},
	}, now); err != nil {
		t.Fatal(err)
	}
	_, _, err := store.RegisterRoleProfile(RegisterRoleInput{
		MachineID: "machine-a", Role: "role/machine-a/reviewer", IdempotencyKey: "takeover-1", Now: now,
	})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("takeover err=%v", err)
	}
	if _, err := store.RoleProfile("role/machine-a/reviewer"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unregistered takeover target was visible: %v", err)
	}
}

func TestStoreRoleRegistrationUpdatesMetadataWithoutChangingOwnerOrHandle(t *testing.T) {
	t.Parallel()
	store := openRoleProfileStore(t)
	now := time.Date(2026, time.August, 18, 16, 0, 0, 0, time.UTC)
	first, created, err := store.RegisterRoleProfile(RegisterRoleInput{
		MachineID: "machine-a", Role: "role/machine-a/reviewer", DisplayName: "Reviewer", IdempotencyKey: "register-1", Now: now,
	})
	if err != nil || !created {
		t.Fatalf("first=%#v created=%t err=%v", first, created, err)
	}
	later := now.Add(time.Minute)
	updated, created, err := store.RegisterRoleProfile(RegisterRoleInput{
		MachineID: "machine-a", Role: "role/machine-a/reviewer", DisplayName: "Lead Reviewer", DirectAddressable: true, IdempotencyKey: "update-1", Now: later,
	})
	if err != nil || created {
		t.Fatalf("update=%#v created=%t err=%v", updated, created, err)
	}
	if updated.Role != first.Role || updated.DisplayName != "Lead Reviewer" || !updated.DirectAddressable || !updated.UpdatedAt.Equal(later) {
		t.Fatalf("updated=%#v first=%#v", updated, first)
	}
}

func TestStoreRoleRegistrationAddressabilityDefaultsFalseAndToggles(t *testing.T) {
	t.Parallel()
	store := openRoleProfileStore(t)
	now := time.Date(2026, time.August, 18, 16, 0, 0, 0, time.UTC)
	first, _, err := store.RegisterRoleProfile(RegisterRoleInput{
		MachineID: "machine-a", Role: "role/machine-a/reviewer", IdempotencyKey: "register-1", Now: now,
	})
	if err != nil || first.DirectAddressable {
		t.Fatalf("default addressable=%#v err=%v", first, err)
	}
	enabled, _, err := store.RegisterRoleProfile(RegisterRoleInput{
		MachineID: "machine-a", Role: "role/machine-a/reviewer", DirectAddressable: true, IdempotencyKey: "enable-1", Now: now.Add(time.Second),
	})
	if err != nil || !enabled.DirectAddressable {
		t.Fatalf("enabled=%#v err=%v", enabled, err)
	}
	disabled, _, err := store.RegisterRoleProfile(RegisterRoleInput{
		MachineID: "machine-a", Role: "role/machine-a/reviewer", DirectAddressable: false, IdempotencyKey: "disable-1", Now: now.Add(2 * time.Second),
	})
	if err != nil || disabled.DirectAddressable {
		t.Fatalf("disabled=%#v err=%v", disabled, err)
	}
}

func TestStoreLegacyRoleRemainsHiddenUntilCanonicalRegistration(t *testing.T) {
	t.Parallel()
	store := openRoleProfileStore(t)
	now := time.Date(2026, time.August, 18, 16, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateConversation("agent/a", []Member{
		{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
		{Role: "role/plan-reviewer", RoleMachineID: "machine-b", Capabilities: CapReceive},
	}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RoleProfile("role/plan-reviewer"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("legacy role was visible before registration: %v", err)
	}
	if err := store.BindRoleToSession("machine-b", "role/plan-reviewer", "agent/b", now, time.Hour); err != nil {
		t.Fatalf("legacy role binding: %v", err)
	}
	registered, created, err := store.RegisterRoleProfile(RegisterRoleInput{
		MachineID: "machine-b", Role: "role/machine-b/reviewer", DirectAddressable: true, IdempotencyKey: "register-canonical", Now: now,
	})
	if err != nil || !created || registered.Role != "role/machine-b/reviewer" {
		t.Fatalf("canonical register=%#v created=%t err=%v", registered, created, err)
	}
	if _, err := store.RoleProfile("role/plan-reviewer"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("legacy role was renamed or exposed: %v", err)
	}
	if err := store.BindRoleToSession("machine-b", "role/plan-reviewer", "agent/b", now.Add(time.Second), time.Hour); err != nil {
		t.Fatalf("legacy role binding after canonical register: %v", err)
	}
}

func TestStoreRoleProfileSurvivesRestart(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 18, 16, 0, 0, 0, time.UTC)
	first, _, err := store.RegisterRoleProfile(RegisterRoleInput{
		MachineID: "machine-a", Role: "role/machine-a/reviewer", DisplayName: "Reviewer", DirectAddressable: true, IdempotencyKey: "register-1", Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	read, err := reopened.RoleProfile("role/machine-a/reviewer")
	if err != nil || read.Role != first.Role || read.DisplayName != first.DisplayName || read.DirectAddressable != first.DirectAddressable || !read.UpdatedAt.Equal(first.UpdatedAt) {
		t.Fatalf("restart profile=%#v want=%#v err=%v", read, first, err)
	}
	retry, created, err := reopened.RegisterRoleProfile(RegisterRoleInput{
		MachineID: "machine-a", Role: "role/machine-a/reviewer", DisplayName: "Reviewer", DirectAddressable: true, IdempotencyKey: "register-1", Now: now.Add(time.Hour),
	})
	if err != nil || created || retry.Role != first.Role || retry.DisplayName != first.DisplayName || !retry.UpdatedAt.Equal(first.UpdatedAt) {
		t.Fatalf("restart retry=%#v created=%t err=%v", retry, created, err)
	}
}

func TestStoreMessageBodyCannotCreateOrRenameRoleProfile(t *testing.T) {
	t.Parallel()
	store := openRoleProfileStore(t)
	now := time.Date(2026, time.August, 18, 16, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversation("agent/a", []Member{
		{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(AppendInput{
		ConversationID: conversation.ID, SenderMachineID: "machine-a", FromEndpoint: "agent/a",
		Body: "register role/machine-a/reviewer", IdempotencyKey: "send-1", Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RoleProfile("role/machine-a/reviewer"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("message body created a role profile: %v", err)
	}
}

func openRoleProfileStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func withRoleRegister(base RegisterRoleInput, mutate func(*RegisterRoleInput)) RegisterRoleInput {
	mutate(&base)
	return base
}
