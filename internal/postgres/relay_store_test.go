package postgres

import (
	"slices"
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
