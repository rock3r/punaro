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
