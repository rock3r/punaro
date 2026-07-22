package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/rock3r/punaro/internal/memoryclient"
)

const (
	cliProject  = "11111111-1111-4111-8111-111111111111"
	cliItem     = "22222222-2222-4222-8222-222222222222"
	cliProposal = "33333333-3333-4333-8333-333333333333"
	cliKey      = "44444444-4444-4444-8444-444444444444"
	cliETag     = `"m1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`
)

type recordingClient struct {
	op   string
	args []string
	body json.RawMessage
	err  error
}

func (c *recordingClient) record(op string, body json.RawMessage, args ...string) (memoryclient.Result, error) {
	c.op, c.args, c.body = op, args, append(json.RawMessage(nil), body...)
	return memoryclient.Result{JSON: json.RawMessage(`{"ok":true}`)}, c.err
}

func (c *recordingClient) Resolve(_ context.Context, kind, locator string) (memoryclient.Result, error) {
	return c.record("resolve", nil, kind, locator)
}
func (c *recordingClient) Get(_ context.Context, project, item string) (memoryclient.Result, error) {
	return c.record("get", nil, project, item)
}
func (c *recordingClient) Search(_ context.Context, project, query string, limit int) (memoryclient.Result, error) {
	return c.record("search", nil, project, query, strconv.Itoa(limit))
}
func (c *recordingClient) Brief(_ context.Context, project, query string) (memoryclient.Result, error) {
	return c.record("brief", nil, project, query)
}
func (c *recordingClient) Changes(_ context.Context, project string, cursor json.RawMessage, limit int) (memoryclient.Result, error) {
	return c.record("changes", cursor, project, strconv.Itoa(limit))
}
func (c *recordingClient) Create(_ context.Context, project, key string, body json.RawMessage) (memoryclient.Result, error) {
	return c.record("create", body, project, key)
}
func (c *recordingClient) Update(_ context.Context, project, item, key, etag string, body json.RawMessage) (memoryclient.Result, error) {
	return c.record("update", body, project, item, key, etag)
}
func (c *recordingClient) SetArchived(_ context.Context, project, item, key, etag string, archived bool) (memoryclient.Result, error) {
	return c.record("state", nil, project, item, key, etag, map[bool]string{true: "archive", false: "restore"}[archived])
}
func (c *recordingClient) Delete(_ context.Context, project, item, key, etag string) (memoryclient.Result, error) {
	return c.record("delete", nil, project, item, key, etag)
}
func (c *recordingClient) CreateProposal(_ context.Context, project, key string, body json.RawMessage) (memoryclient.Result, error) {
	return c.record("propose", body, project, key)
}
func (c *recordingClient) GetProposal(_ context.Context, project, proposal string) (memoryclient.Result, error) {
	return c.record("proposal-get", nil, project, proposal)
}
func (c *recordingClient) DecideProposal(_ context.Context, project, proposal, key, etag string, approve bool) (memoryclient.Result, error) {
	return c.record("proposal-decision", nil, project, proposal, key, etag, map[bool]string{true: "approve", false: "reject"}[approve])
}

func TestRunDispatchesReadsMutationsAndProposalsWithoutPersistingState(t *testing.T) {
	directory := resolvedTempDir(t)
	input := filepath.Join(directory, "input.json")
	if err := os.WriteFile(input, []byte(`{"document":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	credential := filepath.Join(directory, "credential")
	previousLoader, previousFactory := loadCredential, newMemoryClient
	t.Cleanup(func() { loadCredential, newMemoryClient = previousLoader, previousFactory })
	loadCredential = func(path string) (string, error) {
		if path != credential {
			t.Fatalf("credential path=%q", path)
		}
		return "device-secret", nil
	}

	tests := []struct {
		name string
		args []string
		op   string
	}{
		{"read", []string{"get", "--origin", "https://punaro.test", "--credential-file", credential, "--project", cliProject, "--item", cliItem}, "get"},
		{"mutation", []string{"update", "--origin", "https://punaro.test", "--credential-file", credential, "--project", cliProject, "--item", cliItem, "--idempotency-key", cliKey, "--etag", cliETag, "--input", input}, "update"},
		{"proposal", []string{"proposal-reject", "--origin", "https://punaro.test", "--credential-file", credential, "--project", cliProject, "--proposal", cliProposal, "--idempotency-key", cliKey, "--etag", strings.Replace(cliETag, "m1-", "p1-", 1)}, "proposal-decision"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &recordingClient{}
			newMemoryClient = func(origin, value string) (client, error) {
				if origin != "https://punaro.test" || value != "device-secret" {
					t.Fatalf("factory origin=%q credential=%q", origin, value)
				}
				return fake, nil
			}
			var stdout, stderr strings.Builder
			if code := run(test.args, &stdout, &stderr); code != 0 {
				t.Fatalf("code=%d stderr=%q", code, stderr.String())
			}
			if fake.op != test.op || stdout.String() != "{\"ok\":true}\n" || stderr.Len() != 0 {
				t.Fatalf("op=%q stdout=%q stderr=%q", fake.op, stdout.String(), stderr.String())
			}
		})
	}
}

func TestRunClassifiesUsageAndFailuresWithoutEchoingSensitiveData(t *testing.T) {
	credential := filepath.Join(t.TempDir(), "credential")
	previousLoader, previousFactory := loadCredential, newMemoryClient
	t.Cleanup(func() { loadCredential, newMemoryClient = previousLoader, previousFactory })
	loadCredential = func(string) (string, error) { return "device-secret", nil }
	fake := &recordingClient{err: errors.New("server body contains a secret")}
	newMemoryClient = func(string, string) (client, error) { return fake, nil }

	var stdout, stderr strings.Builder
	missingItem := []string{"get", "--origin", "https://punaro.test", "--credential-file", credential, "--project", cliProject}
	if code := run(missingItem, &stdout, &stderr); code != 2 || fake.op != "" {
		t.Fatalf("missing usage code=%d op=%q", code, fake.op)
	}
	stderr.Reset()
	request := append([]string(nil), missingItem...)
	request = append(request, "--item", cliItem)
	if code := run(request, &stdout, &stderr); code != 1 || strings.Contains(stderr.String(), "secret") || stderr.String() != "punaro-memory: request failed\n" {
		t.Fatalf("request code/stderr=%q", stderr.String())
	}
}

func TestRunRejectsIrrelevantAndDuplicateFlags(t *testing.T) {
	credential := filepath.Join(t.TempDir(), "credential")
	for _, args := range [][]string{
		{"get", "--origin", "https://punaro.test", "--credential-file", credential, "--project", cliProject, "--item", cliItem, "--query", "irrelevant"},
		{"get", "--origin", "https://punaro.test", "--origin", "https://other.test", "--credential-file", credential, "--project", cliProject, "--item", cliItem},
	} {
		var stdout, stderr strings.Builder
		if code := run(args, &stdout, &stderr); code != 2 {
			t.Fatalf("args=%v code=%d", args, code)
		}
	}
}

func TestReadInputRejectsSymlinkAndOversize(t *testing.T) {
	directory := resolvedTempDir(t)
	target := filepath.Join(directory, "target.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readInput(link, 64); err == nil {
		t.Fatal("symlink input accepted")
	}
	linkedDirectory := filepath.Join(directory, "linked-directory")
	if err := os.Symlink(directory, linkedDirectory); err != nil {
		t.Fatal(err)
	}
	if _, err := readInput(filepath.Join(linkedDirectory, "target.json"), 64); err == nil {
		t.Fatal("input below symlinked directory accepted")
	}
	large := filepath.Join(directory, "large.json")
	if err := os.WriteFile(large, []byte(`{"value":"too large"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readInput(large, 4); err == nil {
		t.Fatal("oversize input accepted")
	}
}

func resolvedTempDir(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return directory
}
