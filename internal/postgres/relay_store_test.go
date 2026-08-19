package postgres

import (
	"os"
	"slices"
	"strings"
	"testing"
)

func TestRelayInspectSQLComparesMessageMetadataCheckKeysByEquality(t *testing.T) {
	body, err := os.ReadFile("relay_store.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	if strings.Contains(src, "column_keys=ANY(ARRAY[ARRAY[") {
		t.Fatal("relay inspect SQL compares smallint[] to smallint via ANY")
	}
	want := "expected.column_keys=ARRAY[7]::smallint[] OR expected.column_keys=ARRAY[8]::smallint[] OR expected.column_keys=ARRAY[9]::smallint[] OR expected.column_keys=ARRAY[10]::smallint[]"
	if !strings.Contains(src, want) {
		t.Fatal("relay inspect SQL missing equality filters for message metadata check keys")
	}
}

func TestPostgresLeaseMessageColumnsIncludeMetadataWhenPresent(t *testing.T) {
	if got := postgresLeaseMessageColumns(false); strings.Contains(got, "from_participant") || strings.Contains(got, "telegram_thread_id") {
		t.Fatalf("pre-046 lease columns included metadata: %s", got)
	}
	got := postgresLeaseMessageColumns(true)
	last := -1
	for _, column := range []string{"from_participant", "in_reply_to_message_id", "in_reply_to_endpoint", "telegram_thread_id"} {
		idx := strings.Index(got, "message."+column)
		if idx < 0 || idx < last {
			t.Fatalf("lease columns missing or out of order %s: %s", column, got)
		}
		last = idx
	}
}

func TestPostgresConversationEndpointLockOrder(t *testing.T) {
	endpoints := map[string]struct{}{
		"agent/z": {},
		"agent/a": {},
		"agent/m": {},
	}
	want := []string{"agent/a", "agent/m", "agent/z"}
	if got := postgresSortedEndpoints(endpoints); !slices.Equal(got, want) {
		t.Fatalf("endpoint lock order=%v, want %v", got, want)
	}
}

func TestPostgresConversationSQLOmitsDisplayNameUntilColumnExists(t *testing.T) {
	if got := postgresConversationInsertSQL(false); strings.Contains(got, "display_name") {
		t.Fatalf("pre-045 insert referenced display_name: %s", got)
	}
	if got := postgresConversationByIDSQL(false); strings.Contains(got, "display_name") {
		t.Fatalf("pre-045 by-id referenced display_name: %s", got)
	}
	if got := postgresConversationListSQL(false, false); strings.Contains(got, "display_name") {
		t.Fatalf("pre-045 list referenced display_name: %s", got)
	}
	if got := postgresConversationInsertSQL(true); !strings.Contains(got, "display_name") {
		t.Fatalf("v45 insert omitted display_name: %s", got)
	}
	if got := postgresConversationListSQL(true, true); !strings.Contains(got, "display_name") {
		t.Fatalf("v45 list omitted display_name: %s", got)
	}
}

func TestPostgresExclusiveConversationPredicateRequiresDisplayName(t *testing.T) {
	if got := postgresExclusiveConversationPredicate("conversation", false, false); got != "FALSE" {
		t.Fatalf("pre-045 exclusive predicate=%s", got)
	}
	got := postgresExclusiveConversationPredicate("conversation", true, false)
	if !strings.Contains(got, "conversation.display_name") || strings.Contains(got, "UNIQUE") {
		t.Fatalf("exclusive predicate=%s", got)
	}
	claimed := postgresExclusiveConversationPredicate("conversation", true, true)
	if !strings.Contains(claimed, "mail_telegram_claims") || !strings.Contains(claimed, "conversation.display_name") {
		t.Fatalf("claimed exclusive predicate=%s", claimed)
	}
}

func TestPostgresOccupancySQLUsesNullableUUIDExclude(t *testing.T) {
	if postgresNullableUUID("") != nil {
		t.Fatal("empty exclude must bind NULL, not text")
	}
	if got := postgresNullableUUID("019f7f07-4b88-7c12-a394-b663274a6555"); got != "019f7f07-4b88-7c12-a394-b663274a6555" {
		t.Fatalf("uuid exclude=%v", got)
	}
	for _, rolesAvailable := range []bool{false, true} {
		query := postgresSessionOccupiesOtherExclusiveConversationSQL(true, rolesAvailable, true)
		compact := strings.ReplaceAll(query, " ", "")
		if strings.Contains(query, "$2 = ''") || strings.Contains(compact, "$2=''") {
			t.Fatalf("occupancy SQL overloads $2 as text: %s", query)
		}
		if !strings.Contains(query, "$2::uuid IS NULL") || !strings.Contains(query, "membership.conversation_id <> $2::uuid") {
			t.Fatalf("occupancy SQL missing nullable uuid exclude: %s", query)
		}
	}
}

func TestPostgresOccupancyLockSQLUsesForUpdateInStableOrder(t *testing.T) {
	if !strings.Contains(postgresConversationOccupancyLockSQL(), "FOR UPDATE") {
		t.Fatalf("conversation occupancy lock omitted FOR UPDATE: %s", postgresConversationOccupancyLockSQL())
	}
	if !strings.Contains(postgresEndpointOccupancyLockSQL(), "FOR UPDATE") {
		t.Fatalf("endpoint occupancy lock omitted FOR UPDATE: %s", postgresEndpointOccupancyLockSQL())
	}
	conversations, endpoints := postgresOccupancyLockOrder([]string{"b", "a", "a"}, map[string]struct{}{"agent/z": {}, "agent/a": {}})
	if !slices.Equal(conversations, []string{"a", "b"}) {
		t.Fatalf("conversation lock order=%v", conversations)
	}
	if !slices.Equal(endpoints, []string{"agent/a", "agent/z"}) {
		t.Fatalf("endpoint lock order=%v", endpoints)
	}
}

func TestPostgresControlMemberLeaseSQLDoesNotLockEndpoint(t *testing.T) {
	// Bind locks exclusive conversations then the session. Control must take
	// occupancy (conversation then endpoint) before any member-lease lock.
	if strings.Contains(postgresControlMemberLeaseSQL(), "FOR UPDATE") {
		t.Fatalf("control member lease must not lock the endpoint before occupancy: %s", postgresControlMemberLeaseSQL())
	}
	if !strings.Contains(postgresControlMemberLeaseSQL(), "lease_until") {
		t.Fatalf("control member lease omitted live-lease read: %s", postgresControlMemberLeaseSQL())
	}
}
