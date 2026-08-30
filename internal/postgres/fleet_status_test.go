package postgres

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestExpireFleetClientStateMarksStaleReportsOffline(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	if got := ExpireFleetClientState("current", now.Add(-time.Minute), now); got != "current" {
		t.Fatalf("fresh=%s", got)
	}
	if got := ExpireFleetClientState("current", now.Add(-11*time.Minute), now); got != "offline" {
		t.Fatalf("stale=%s", got)
	}
	if got := ExpireFleetClientState("", now, now); got != "offline" {
		t.Fatalf("missing=%s", got)
	}
	if got := ExpireFleetClientState("current", time.Time{}, now); got != "offline" {
		t.Fatalf("zero=%s", got)
	}
}

func TestListFleetClientStatusReadsMachineReports(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile("fleet_config.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	if strings.Contains(source, "status.client_id") {
		t.Fatal("client status list still joins client_installations by client_id")
	}
	if !strings.Contains(source, "FROM fleet.client_status") || !strings.Contains(source, "reported_at") || !strings.Contains(source, "ExpireFleetClientState") {
		t.Fatal("client status list does not expire stale machine reports")
	}
}
