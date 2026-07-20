package relay_test

import (
	"path/filepath"
	"testing"

	"github.com/rock3r/punaro/internal/relay"
	"github.com/rock3r/punaro/internal/relay/contracttest"
)

func TestSQLiteStoreConformance(t *testing.T) {
	store, err := relay.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	contracttest.Run(t, store, "sqlite-contract")
}
