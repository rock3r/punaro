package postgres

import (
	"context"
	"testing"

	"github.com/rock3r/punaro/internal/fleetconfig"
)

func TestPublishFleetReleaseRefusesInvalidInput(t *testing.T) {
	t.Parallel()
	var admin *Administration
	if _, err := admin.PublishFleetRelease(context.Background(), fleetconfig.Release{}, "hash"); err == nil {
		t.Fatal("nil store accepted a release")
	}
	admin = &Administration{}
	if _, err := admin.PublishFleetRelease(context.Background(), fleetconfig.Release{Digest: "x", Archive: []byte("a")}, "hash"); err == nil {
		t.Fatal("accepted a non-data-only release")
	}
}
