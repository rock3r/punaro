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
	if err := os.WriteFile(filepath.Join(home, "AGENTS.md"), []byte("# unmanaged\n"), 0o600); err != nil { //nolint:gosec // G306: test fixture under t.TempDir.
		t.Fatal(err)
	}
	result, err = ReconcileFleetOnce(context.Background(), FleetReconcileRequest{
		Client: client,
		Root:   root,
		Home:   home,
		Local:  fleetconfig.LocalConfig{Schema: 1, ProjectBasePath: base},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.State == "current" || result.TrailerState != "collision" {
		t.Fatalf("unmanaged AGENTS.md reported as current: %#v", result)
	}
	unmanaged, err := os.ReadFile(filepath.Join(home, "AGENTS.md")) //nolint:gosec // G304: test fixture under t.TempDir.
	if err != nil || !strings.Contains(string(unmanaged), "unmanaged") {
		t.Fatalf("overwrote unmanaged AGENTS.md: %q err=%v", unmanaged, err)
	}
}

func TestReconcileFleetOnceProjectsClaudeAliasesAndUnsupportedHarness(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tree := fleetconfig.Tree{Files: []fleetconfig.File{
		{Path: "AGENTS.md", Data: []byte("# fleet\n")},
		{Path: "skills/demo/SKILL.md", Data: []byte("---\nname: demo\ndescription: Demo skill.\n---\n# demo\n")},
		{Path: "projects/punaro/AGENTS.md", Data: []byte("# punaro\n")},
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
	if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o700); err != nil {
		t.Fatal(err)
	}
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
	result, err := ReconcileFleetOnce(context.Background(), FleetReconcileRequest{
		Client: client,
		Root:   t.TempDir(),
		Home:   home,
		Local:  fleetconfig.LocalConfig{Schema: 1, ProjectBasePath: base, ClaudeAliases: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.State != "unsupported" {
		t.Fatalf("result=%#v", result)
	}
	claude := filepath.Join(home, "CLAUDE.md")
	info, err := os.Lstat(claude)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("global CLAUDE.md must be a regular file info=%v err=%v", info, err)
	}
	body, err := os.ReadFile(claude) //nolint:gosec // G304: test fixture under t.TempDir.
	if err != nil || !strings.Contains(string(body), "# fleet") {
		t.Fatalf("CLAUDE.md missing AGENTS.md text: %q err=%v", body, err)
	}
	projectClaude := filepath.Join(base, "punaro", "CLAUDE.md")
	info, err = os.Lstat(projectClaude)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("project CLAUDE.md must be a regular file info=%v err=%v", info, err)
	}
}

func TestReconcileFleetOncePersistsReportGenerationAcrossCurrentAndNextDigest(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	first, err := fleetconfig.Materialize(fleetconfig.Tree{Files: []fleetconfig.File{{Path: "AGENTS.md", Data: []byte("# a\n")}}}, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	second, err := fleetconfig.Materialize(fleetconfig.Tree{Files: []fleetconfig.File{{Path: "AGENTS.md", Data: []byte("# b\n")}}}, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	var bodies []string
	seen := map[string]string{}
	desired := first
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/fleet-config/desired":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"generation": 2, "digest": desired.Digest, "source_commit": desired.SourceCommit,
				"skill_count": desired.SkillCount, "total_bytes": desired.TotalBytes,
			})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/fleet-config/releases/"):
			w.Header().Set("Content-Type", "application/octet-stream")
			if strings.HasSuffix(r.URL.Path, second.Digest) {
				_, _ = w.Write(second.Archive)
				return
			}
			_, _ = w.Write(first.Archive)
		case r.Method == http.MethodPut && r.URL.Path == "/v1/fleet-config/status":
			body, _ := io.ReadAll(r.Body)
			key := r.Header.Get("Idempotency-Key")
			if previous, ok := seen[key]; ok && previous != string(body) {
				http.Error(w, "conflict", http.StatusConflict)
				return
			}
			seen[key] = string(body)
			keys = append(keys, key)
			bodies = append(bodies, string(body))
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
	home := t.TempDir()
	root := t.TempDir()
	req := FleetReconcileRequest{Client: client, Root: root, Home: home, Local: fleetconfig.LocalConfig{Schema: 1, ProjectBasePath: filepath.Join(home, "src")}}
	if _, err := ReconcileFleetOnce(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if _, err := ReconcileFleetOnce(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	desired = second
	if _, err := ReconcileFleetOnce(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if len(keys) != 3 || keys[0] == keys[1] || keys[1] == keys[2] {
		t.Fatalf("reused status idempotency keys: %v bodies=%v", keys, bodies)
	}
	state := loadFleetApplyState(root)
	if state.ReportGeneration != 3 {
		t.Fatalf("report_generation=%d", state.ReportGeneration)
	}
}

func TestReconcileFleetOnceCurrentPathLiveFailureReportsFailed(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	release, err := fleetconfig.Materialize(fleetconfig.Tree{Files: []fleetconfig.File{{Path: "AGENTS.md", Data: []byte("# fleet\n")}}}, "0123456789abcdef0123456789abcdef01234567")
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	var states []string
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
			keys = append(keys, r.Header.Get("Idempotency-Key"))
			var payload map[string]any
			_ = json.Unmarshal(body, &payload)
			if state, _ := payload["state"].(string); state != "" {
				states = append(states, state)
			}
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
	home := t.TempDir()
	root := t.TempDir()
	req := FleetReconcileRequest{Client: client, Root: root, Home: home, Local: fleetconfig.LocalConfig{Schema: 1, ProjectBasePath: filepath.Join(home, "src")}}
	if _, err := ReconcileFleetOnce(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(home, "AGENTS.md")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "missing"), filepath.Join(home, "AGENTS.md")); err != nil {
		t.Fatal(err)
	}
	result, err := ReconcileFleetOnce(context.Background(), req)
	if err == nil {
		t.Fatal("live apply failure was not reported")
	}
	if result.State != "failed" {
		t.Fatalf("result=%#v", result)
	}
	if len(states) < 2 || states[len(states)-1] != "failed" {
		t.Fatalf("status states=%v", states)
	}
	if len(keys) < 2 || keys[0] == keys[1] {
		t.Fatalf("reused status key after live failure: %v", keys)
	}
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
