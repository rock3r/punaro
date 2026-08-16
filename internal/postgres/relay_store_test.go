package postgres

import (
	"slices"
	"strings"
	"testing"
)

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
	if got := postgresExclusiveConversationPredicate("conversation", false); got != "FALSE" {
		t.Fatalf("pre-045 exclusive predicate=%s", got)
	}
	got := postgresExclusiveConversationPredicate("conversation", true)
	if !strings.Contains(got, "conversation.display_name") || strings.Contains(got, "UNIQUE") {
		t.Fatalf("exclusive predicate=%s", got)
	}
}
