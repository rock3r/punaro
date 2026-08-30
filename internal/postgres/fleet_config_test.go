package postgres

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/rock3r/punaro/internal/fleetconfig"
)

func TestFleetPutClientStatusLocksReportGeneration(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile("migrations/059_fleet_config_client_status.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(body)
	if !strings.Contains(sql, "FOR UPDATE") || !strings.Contains(sql, "report_generation < EXCLUDED.report_generation") {
		t.Fatal("client status upsert is not fenced by report generation")
	}
}

func TestFleetPutClientStatusSerializesIdempotencyLookup(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile("migrations/059_fleet_config_client_status.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(body)
	if strings.Contains(sql, "client_installations") {
		t.Fatal("status writes require a client installation")
	}
	if !strings.Contains(sql, "machine_id text PRIMARY KEY") {
		t.Fatal("status is not keyed by the authenticated machine id")
	}
	if !strings.Contains(sql, "pg_advisory_xact_lock") {
		t.Fatal("concurrent first-status retries are not serialized before the idempotency lookup")
	}
}

func TestFleetClientStatusControlsDenyApplicationMutations(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile("fleet_config_schema.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	required := []string{
		"AND NOT has_table_privilege('punaro_app', 'fleet.client_status', 'DELETE')",
		"AND NOT has_table_privilege('punaro_app', 'fleet.client_status', 'TRUNCATE')",
		"AND NOT has_table_privilege('punaro_app', 'fleet.client_status', 'REFERENCES')",
		"AND NOT has_table_privilege('punaro_app', 'fleet.client_status', 'TRIGGER')",
		"AND NOT has_table_privilege('punaro_app', 'fleet.client_status_idempotency', 'SELECT')",
		"AND NOT has_table_privilege('punaro_app', 'fleet.client_status_idempotency', 'INSERT')",
		"AND NOT has_table_privilege('punaro_app', 'fleet.client_status_idempotency', 'UPDATE')",
		"AND NOT has_table_privilege('punaro_app', 'fleet.client_status_idempotency', 'DELETE')",
		"AND NOT has_table_privilege('punaro_app', 'fleet.client_status_idempotency', 'TRUNCATE')",
		"AND NOT has_table_privilege('punaro_app', 'fleet.client_status_idempotency', 'REFERENCES')",
		"AND NOT has_table_privilege('punaro_app', 'fleet.client_status_idempotency', 'TRIGGER')",
		"AND NOT has_function_privilege('public', put_oid, 'EXECUTE')",
		"prosecdef",
		"search_path=pg_catalog",
	}
	for _, want := range required {
		if !strings.Contains(source, want) {
			t.Fatalf("status inspect omitted %s", want)
		}
	}
}

func TestPublishFleetReleaseRefusesInvalidInput(t *testing.T) {
	t.Parallel()
	var admin *Administration
	if _, err := admin.PublishFleetRelease(context.Background(), fleetconfig.Release{}, "hash", FleetDesired{}); err == nil {
		t.Fatal("nil store accepted a release")
	}
	admin = &Administration{}
	if _, err := admin.PublishFleetRelease(context.Background(), fleetconfig.Release{Digest: "x", Archive: []byte("a")}, "hash", FleetDesired{}); err == nil {
		t.Fatal("accepted a non-data-only release")
	}
}
