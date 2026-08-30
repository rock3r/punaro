package fleetconfig

import (
	"bytes"
	"strings"
	"testing"
)

func TestApplyAgentsCreatesAndPreservesTrailer(t *testing.T) {
	t.Parallel()
	created, result, err := ApplyAgents([]byte("# fleet v1\n"), nil, false, "")
	if err != nil || result.Collision || result.State != "present" {
		t.Fatalf("create result=%#v err=%v", result, err)
	}
	if !bytes.Contains(created, []byte(TrailerStart)) || !bytes.Contains(created, []byte(TrailerEnd)) {
		t.Fatalf("missing trailer markers: %s", created)
	}
	if _, _, ok := SplitAgents(created); !ok {
		t.Fatal("created file missing trailer")
	}
	withLocal := ComposeAgents([]byte("# fleet v1\n"), []byte("\nmachine note\n"))
	updated, result, err := ApplyAgents([]byte("# fleet v2\n"), withLocal, true, DigestBytes([]byte("# fleet v1")))
	if err != nil || result.Collision || result.Drift {
		t.Fatalf("update result=%#v err=%v", result, err)
	}
	_, trailer, ok := SplitAgents(updated)
	if !ok || !strings.Contains(string(trailer), "machine note") || !strings.Contains(string(updated), "# fleet v2") {
		t.Fatalf("trailer lost: %s", updated)
	}
	if bytes.Contains(updated, []byte("# fleet v1\n# fleet v2")) {
		t.Fatal("merged prefixes")
	}
}

func TestApplyAgentsReportsDriftAndCollision(t *testing.T) {
	t.Parallel()
	existing := ComposeAgents([]byte("# edited prefix\n"), []byte("\nkeep me\n"))
	next, result, err := ApplyAgents([]byte("# fleet v2\n"), existing, true, DigestBytes([]byte("# fleet v1")))
	if err != nil || !result.Drift || result.Collision {
		t.Fatalf("drift result=%#v err=%v", result, err)
	}
	_, trailer, ok := SplitAgents(next)
	if !ok || !strings.Contains(string(trailer), "keep me") {
		t.Fatal("drift apply dropped trailer")
	}
	collision, result, err := ApplyAgents([]byte("# fleet\n"), []byte("# unmanaged\n"), true, "")
	if err != nil || !result.Collision || result.State != "collision" || collision != nil {
		t.Fatalf("collision result=%#v next=%s err=%v", result, collision, err)
	}
}

func TestApplyAgentsOmitsTrailerFromFleetPrefix(t *testing.T) {
	t.Parallel()
	next, _, err := ApplyAgents([]byte("# fleet\n"), nil, false, "")
	if err != nil {
		t.Fatal(err)
	}
	prefix, _, ok := SplitAgents(next)
	if !ok || bytes.Contains(prefix, []byte(TrailerStart)) {
		t.Fatalf("trailer leaked into prefix %q", prefix)
	}
}
