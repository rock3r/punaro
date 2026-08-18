package relay

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestStoreListsOnlyOptedInRolesWithStablePagination(t *testing.T) {
	t.Parallel()
	store := openRoleProfileStore(t)
	now := time.Date(2026, time.August, 18, 17, 0, 0, 0, time.UTC)
	registerAddressable(t, store, "machine-a", "role/machine-a/zeta", "Zeta", true, "reg-zeta", now)
	registerAddressable(t, store, "machine-a", "role/machine-a/alpha", "Alpha", true, "reg-alpha", now)
	registerAddressable(t, store, "machine-b", "role/machine-b/mu", "", true, "reg-mu", now)
	registerAddressable(t, store, "machine-a", "role/machine-a/hidden", "Hidden", false, "reg-hidden", now)
	page, err := store.ListAddressableRoles(RoleListInput{Cursor: "", Limit: 2, Now: now})
	if err != nil || len(page.Roles) != 2 || page.NextCursor == "" {
		t.Fatalf("first page=%#v err=%v", page, err)
	}
	if page.Roles[0].Role != "role/machine-a/alpha" || page.Roles[0].DisplayName != "Alpha" || page.Roles[0].MachineID != "machine-a" || page.Roles[0].Online {
		t.Fatalf("first row=%#v", page.Roles[0])
	}
	if page.Roles[1].Role != "role/machine-a/zeta" {
		t.Fatalf("second row=%#v", page.Roles[1])
	}
	second, err := store.ListAddressableRoles(RoleListInput{Cursor: page.NextCursor, Limit: 2, Now: now})
	if err != nil || len(second.Roles) != 1 || second.NextCursor != "" || second.Roles[0].Role != "role/machine-b/mu" {
		t.Fatalf("second page=%#v err=%v", second, err)
	}
	if encoded, err := json.Marshal(page); err != nil || strings.Contains(string(encoded), "agent/") || strings.Contains(string(encoded), "conversation") {
		t.Fatalf("list leaked inventory: %s err=%v", encoded, err)
	}
}

func TestStoreRoleDirectoryOnlineRequiresCurrentBindingAndGeneration(t *testing.T) {
	t.Parallel()
	store := openRoleProfileStore(t)
	now := time.Date(2026, time.August, 18, 17, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a/session"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	registerAddressable(t, store, "machine-a", "role/machine-a/live", "Live", true, "reg-live", now)
	registerAddressable(t, store, "machine-a", "role/machine-a/never", "", true, "reg-never", now)
	if err := store.BindRoleToSession("machine-a", "role/machine-a/live", "agent/a/session", now, time.Hour); err != nil {
		t.Fatal(err)
	}
	page, err := store.ListAddressableRoles(RoleListInput{Limit: 10, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	byRole := contactsByRole(page.Roles)
	if !byRole["role/machine-a/live"].Online || byRole["role/machine-a/never"].Online {
		t.Fatalf("online state=%#v", byRole)
	}
	later := now.Add(2 * time.Hour)
	expired, err := store.ListAddressableRoles(RoleListInput{Limit: 10, Now: later})
	if err != nil || contactsByRole(expired.Roles)["role/machine-a/live"].Online {
		t.Fatalf("expired still online: %#v err=%v", expired, err)
	}
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a/session"}, now.Add(time.Minute), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a/other"}, now.Add(2*time.Minute), time.Hour); err != nil {
		t.Fatal(err)
	}
	detached, err := store.ListAddressableRoles(RoleListInput{Limit: 10, Now: now.Add(2 * time.Minute)})
	if err != nil || contactsByRole(detached.Roles)["role/machine-a/live"].Online {
		t.Fatalf("detached still online: %#v err=%v", detached, err)
	}
	if err := store.BindRoleToSession("machine-a", "role/machine-a/live", "agent/a/other", now.Add(3*time.Minute), time.Hour); err != nil {
		t.Fatal(err)
	}
	rebound, err := store.ListAddressableRoles(RoleListInput{Limit: 10, Now: now.Add(3 * time.Minute)})
	if err != nil || !contactsByRole(rebound.Roles)["role/machine-a/live"].Online {
		t.Fatalf("rebound offline: %#v err=%v", rebound, err)
	}
}

func TestStoreResolvesQualifiedUniqueAndAmbiguousNames(t *testing.T) {
	t.Parallel()
	store := openRoleProfileStore(t)
	now := time.Date(2026, time.August, 18, 17, 0, 0, 0, time.UTC)
	registerAddressable(t, store, "machine-a", "role/machine-a/reviewer", "Plan Reviewer", true, "reg-a", now)
	registerAddressable(t, store, "machine-b", "role/machine-b/reviewer", "Other Reviewer", true, "reg-b", now)
	registerAddressable(t, store, "machine-a", "role/machine-a/unique", "Unique", true, "reg-u", now)
	registerAddressable(t, store, "machine-a", "role/machine-a/hidden", "Plan Reviewer", false, "reg-h", now)
	exact, err := store.ResolveAddressableRole(RoleResolveInput{Name: "role/machine-a/reviewer", Now: now})
	if err != nil || exact.Status != RoleResolveResolved || exact.Role != "role/machine-a/reviewer" || exact.MachineID != "machine-a" {
		t.Fatalf("exact=%#v err=%v", exact, err)
	}
	unique, err := store.ResolveAddressableRole(RoleResolveInput{Name: "unique", Now: now})
	if err != nil || unique.Status != RoleResolveResolved || unique.Role != "role/machine-a/unique" {
		t.Fatalf("unique=%#v err=%v", unique, err)
	}
	ambiguous, err := store.ResolveAddressableRole(RoleResolveInput{Name: "reviewer", Now: now})
	if err != nil || ambiguous.Status != RoleResolveAmbiguous || len(ambiguous.Matches) != 2 {
		t.Fatalf("ambiguous=%#v err=%v", ambiguous, err)
	}
	if ambiguous.Matches[0].Role != "role/machine-a/reviewer" || ambiguous.Matches[0].MachineID != "" || ambiguous.Matches[0].Online {
		t.Fatalf("ambiguous match leaked fields: %#v", ambiguous.Matches[0])
	}
	missing, err := store.ResolveAddressableRole(RoleResolveInput{Name: "role/machine-a/hidden", Now: now})
	if err != nil || missing.Status != RoleResolveNotFound {
		t.Fatalf("hidden=%#v err=%v", missing, err)
	}
	byDisplay, err := store.ResolveAddressableRole(RoleResolveInput{Name: "Plan Reviewer", Now: now})
	if err != nil || byDisplay.Status != RoleResolveNotFound {
		t.Fatalf("display name resolved: %#v err=%v", byDisplay, err)
	}
	legacy, err := store.ResolveAddressableRole(RoleResolveInput{Name: "role/plan-reviewer", Now: now})
	if err != nil || legacy.Status != RoleResolveNotFound {
		t.Fatalf("legacy=%#v err=%v", legacy, err)
	}
}

func TestStoreRoleResolveCapsAmbiguityAtTwenty(t *testing.T) {
	t.Parallel()
	store := openRoleProfileStore(t)
	now := time.Date(2026, time.August, 18, 17, 0, 0, 0, time.UTC)
	for i := 0; i < 21; i++ {
		machine := "machine-" + string(rune('a'+i))
		role := "role/" + machine + "/shared"
		registerAddressable(t, store, machine, role, "", true, "reg-"+machine, now)
	}
	result, err := store.ResolveAddressableRole(RoleResolveInput{Name: "shared", Now: now})
	if err != nil || result.Status != RoleResolveAmbiguous || len(result.Matches) != 20 {
		t.Fatalf("cap=%#v err=%v", result, err)
	}
}

func registerAddressable(t *testing.T, store *Store, machine, role, display string, addressable bool, key string, now time.Time) {
	t.Helper()
	if _, _, err := store.RegisterRoleProfile(RegisterRoleInput{
		MachineID: machine, Role: role, DisplayName: display, DirectAddressable: addressable, IdempotencyKey: key, Now: now,
	}); err != nil {
		t.Fatal(err)
	}
}

func contactsByRole(contacts []RoleContact) map[string]RoleContact {
	out := make(map[string]RoleContact, len(contacts))
	for _, contact := range contacts {
		out[contact.Role] = contact
	}
	return out
}

func TestStoreRoleListRejectsInvalidCursorAndLimit(t *testing.T) {
	t.Parallel()
	store := openRoleProfileStore(t)
	now := time.Date(2026, time.August, 18, 17, 0, 0, 0, time.UTC)
	if _, err := store.ListAddressableRoles(RoleListInput{Limit: 0, Now: now}); err == nil {
		t.Fatal("limit 0 accepted")
	}
	if _, err := store.ListAddressableRoles(RoleListInput{Limit: 101, Now: now}); err == nil {
		t.Fatal("limit 101 accepted")
	}
	if _, err := store.ListAddressableRoles(RoleListInput{Cursor: "not-a-cursor", Limit: 10, Now: now}); err == nil {
		t.Fatal("opaque garbage cursor accepted")
	}
}
