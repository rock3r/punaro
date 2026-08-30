package canopi

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/rock3r/punaro/canopi/protocol"
)

func TestEncodeFleetConvergenceOmitsConfigurationContents(t *testing.T) {
	t.Parallel()
	digest := strings.Repeat("ab", 32)
	body, err := EncodeFleetConvergence(4, digest, "current")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, `"fleet_state":"current"`) || !strings.Contains(text, `"fleet_generation":4`) {
		t.Fatalf("body=%s", text)
	}
	if strings.Contains(text, "AGENTS.md") || strings.Contains(text, "# fleet") || strings.Contains(text, "/Users/") {
		t.Fatalf("leaked contents: %s", text)
	}
	event, err := protocol.DecodeEvent(bytes.NewReader(body), 32<<10)
	if err != nil {
		t.Fatalf("decode=%v body=%s", err, text)
	}
	if event.Metadata["fleet_digest"] != digest || event.Metadata["fleet_state"] != "current" {
		t.Fatalf("event=%#v", event)
	}
}

func TestStoreAppliesFleetConvergenceEvent(t *testing.T) {
	t.Parallel()
	store := NewStore(Config{WorkingTTL: time.Hour, DoneRetention: 2 * time.Hour})
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	result, err := store.ApplyFleetConvergence(4, strings.Repeat("ab", 32), "current", now)
	if err != nil || !result.Applied {
		t.Fatalf("apply=%#v err=%v", result, err)
	}
	again, err := store.ApplyFleetConvergence(4, strings.Repeat("ab", 32), "failed", now)
	if err != nil || !again.Applied {
		t.Fatalf("state change=%#v err=%v", again, err)
	}
}
