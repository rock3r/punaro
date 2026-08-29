package adapter

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rock3r/punaro/internal/fleetconfig"
	"github.com/rock3r/punaro/internal/relay"
)

func TestHTTPRelayClientFetchesFleetDesiredAndRelease(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	archive := bytesRepeat('A', 200)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		timestamp, parseErr := time.Parse(time.RFC3339Nano, r.Header.Get("X-Punaro-Timestamp"))
		signature, signatureErr := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Punaro-Signature"))
		signed := relay.SignedRequest{MachineID: r.Header.Get("X-Punaro-Machine"), Method: r.Method, Path: r.URL.Path, Body: body, Timestamp: timestamp, Nonce: r.Header.Get("X-Punaro-Nonce")}
		if parseErr != nil || signatureErr != nil || !ed25519.Verify(public, relay.CanonicalRequest(signed), signature) {
			t.Fatal("fleet-config request was not machine-signed")
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/fleet-config/desired":
			if len(body) != 0 {
				t.Fatalf("desired GET had body %q", body)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"generation": 4, "digest": digest, "source_commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"skill_count": 1, "total_bytes": 12,
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/fleet-config/releases/"+digest:
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(archive)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	client, err := NewHTTPRelayClient(server.URL, "machine-a", private, server.Client(), AccessServiceToken{})
	if err != nil {
		t.Fatal(err)
	}
	desired, err := client.FleetDesired(context.Background())
	if err != nil || desired.Generation != 4 || desired.Digest != digest || desired.SkillCount != 1 {
		t.Fatalf("desired=%#v err=%v", desired, err)
	}
	got, err := client.FleetRelease(context.Background(), digest)
	if err != nil || string(got) != string(archive) {
		t.Fatalf("archive=%q err=%v", got, err)
	}
}

func TestHTTPRelayClientPutsFleetStatusIdempotently(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/v1/fleet-config/status" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		keys = append(keys, r.Header.Get("Idempotency-Key"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"recorded"}`))
	}))
	defer server.Close()
	client, err := NewHTTPRelayClient(server.URL, "machine-a", private, server.Client(), AccessServiceToken{})
	if err != nil {
		t.Fatal(err)
	}
	report := relay.FleetStatusReport{Generation: 1, AppliedDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", State: "current", ReportGeneration: 1, IdempotencyKey: "status-1"}
	if err := client.PutFleetStatus(context.Background(), report); err != nil {
		t.Fatal(err)
	}
	if err := client.PutFleetStatus(context.Background(), report); err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0] != "status-1" || keys[1] != "status-1" {
		t.Fatalf("keys=%v", keys)
	}
}

func TestHTTPRelayClientFleetReleaseRejectsUnauthorized(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer server.Close()
	client, err := NewHTTPRelayClient(server.URL, "machine-revoked", private, server.Client(), AccessServiceToken{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.FleetDesired(context.Background()); err == nil {
		t.Fatal("revoked client fetched desired")
	}
	if _, err := client.FleetRelease(context.Background(), digest); err == nil {
		t.Fatal("revoked client fetched release")
	}
}

func TestReconcileFleetOnceFetchesAppliesAndReports(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tree := fleetconfig.Tree{Files: []fleetconfig.File{
		{Path: "AGENTS.md", Data: []byte("# fleet\n")},
		{Path: "projects/punaro/AGENTS.md", Data: []byte("# punaro\n")},
		{Path: "projects/other/AGENTS.md", Data: []byte("# other\n")},
	}}
	release, err := fleetconfig.Materialize(tree, "0123456789abcdef0123456789abcdef01234567")
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	base := filepath.Join(home, "src")
	if err := os.MkdirAll(filepath.Join(base, "punaro"), 0o700); err != nil {
		t.Fatal(err)
	}
	var reported []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/fleet-config/desired":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"generation": 2, "digest": release.Digest, "source_commit": release.SourceCommit,
				"skill_count": release.SkillCount, "total_bytes": release.TotalBytes,
			})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/fleet-config/releases/"):
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(release.Archive)
		case r.Method == http.MethodPut && r.URL.Path == "/v1/fleet-config/status":
			body, _ := io.ReadAll(r.Body)
			reported = append(reported, string(body))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"recorded"}`))
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	client, err := NewHTTPRelayClient(server.URL, "machine-a", private, server.Client(), AccessServiceToken{})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	result, err := ReconcileFleetOnce(context.Background(), FleetReconcileRequest{
		Client: client,
		Root:   root,
		Home:   home,
		Local:  fleetconfig.LocalConfig{Schema: 1, ProjectBasePath: base},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.State != "current" || result.AppliedDigest != release.Digest {
		t.Fatalf("result=%#v", result)
	}
	live, err := os.ReadFile(filepath.Join(root, "current", "AGENTS.md")) //nolint:gosec // G304: test fixture under t.TempDir.
	if err != nil || !strings.Contains(string(live), "# fleet") {
		t.Fatalf("managed tree=%q err=%v", live, err)
	}
	project, err := os.ReadFile(filepath.Join(base, "punaro", "AGENTS.md")) //nolint:gosec // G304: test fixture under t.TempDir.
	if err != nil || !strings.Contains(string(project), "# punaro") {
		t.Fatalf("project apply=%q err=%v", project, err)
	}
	if _, err := os.Stat(filepath.Join(base, "other", "AGENTS.md")); !os.IsNotExist(err) {
		t.Fatal("applied unmatched project tree")
	}
	if len(reported) == 0 || !strings.Contains(strings.Join(reported, ""), `"current"`) {
		t.Fatalf("status writes=%v", reported)
	}
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
