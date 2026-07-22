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

func TestRunAcceptsFlagLikeValuesWithEquals(t *testing.T) {
	credential := filepath.Join(t.TempDir(), "credential")
	previousLoader, previousFactory := loadCredential, newMemoryClient
	t.Cleanup(func() { loadCredential, newMemoryClient = previousLoader, previousFactory })
	loadCredential = func(string) (string, error) { return "device-secret", nil }
	fake := &recordingClient{}
	newMemoryClient = func(string, string) (client, error) { return fake, nil }

	var stdout, stderr strings.Builder
	args := []string{"search", "--origin", "https://punaro.test", "--credential-file", credential, "--project", cliProject, "--query=-starts-with-dash", "--limit", "5"}
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if fake.op != "search" || len(fake.args) != 3 || fake.args[1] != "-starts-with-dash" {
		t.Fatalf("op=%q args=%v", fake.op, fake.args)
	}
}

func TestRunBoundsCreateInputBelowProposalLimit(t *testing.T) {
	directory := resolvedTempDir(t)
	input := filepath.Join(directory, "input.json")
	largeJSON := []byte(`{"value":"` + strings.Repeat("a", 264<<10) + `"}`)
	if err := os.WriteFile(input, largeJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	credential := filepath.Join(directory, "credential")
	previousLoader, previousFactory := loadCredential, newMemoryClient
	t.Cleanup(func() { loadCredential, newMemoryClient = previousLoader, previousFactory })
	loadCredential = func(string) (string, error) { return "device-secret", nil }
	fake := &recordingClient{}
	newMemoryClient = func(string, string) (client, error) { return fake, nil }

	base := []string{"--origin", "https://punaro.test", "--credential-file", credential, "--project", cliProject, "--idempotency-key", cliKey, "--input", input}
	var stdout, stderr strings.Builder
	if code := run(append([]string{"create"}, base...), &stdout, &stderr); code != 1 || fake.op != "" || stderr.String() != "punaro-memory: request failed\n" {
		t.Fatalf("create code=%d op=%q stderr=%q", code, fake.op, stderr.String())
	}
	stderr.Reset()
	if code := run(append([]string{"propose"}, base...), &stdout, &stderr); code != 0 || fake.op != "propose" {
		t.Fatalf("propose code=%d op=%q stderr=%q", code, fake.op, stderr.String())
	}
}

func TestRunUsesProtectedProfileDefaultsWithoutStoringCredential(t *testing.T) {
	directory := resolvedTempDir(t)
	profilePath := filepath.Join(directory, "profile.json")
	credential := filepath.Join(directory, "credential")
	if err := saveProfile(profilePath, profile{Origin: "https://profile.test", CredentialFile: credential, Project: cliProject}); err != nil {
		t.Fatal(err)
	}
	rawProfile, err := os.ReadFile(profilePath) // #nosec G304 -- test reads the profile path created under its resolved temp directory.
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawProfile), "device-secret") {
		t.Fatal("profile stored credential secret")
	}
	previousLoader, previousFactory := loadCredential, newMemoryClient
	t.Cleanup(func() { loadCredential, newMemoryClient = previousLoader, previousFactory })
	loadCredential = func(path string) (string, error) {
		if path != credential {
			t.Fatalf("credential path=%q", path)
		}
		return "device-secret", nil
	}
	fake := &recordingClient{}
	newMemoryClient = func(origin, value string) (client, error) {
		if origin != "https://profile.test" || value != "device-secret" {
			t.Fatalf("factory origin=%q credential=%q", origin, value)
		}
		return fake, nil
	}

	var stdout, stderr strings.Builder
	args := []string{"get", "--profile", profilePath, "--item", cliItem}
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if fake.op != "get" || len(fake.args) != 2 || fake.args[0] != cliProject {
		t.Fatalf("op=%q args=%v", fake.op, fake.args)
	}
}

func TestRunExplicitProjectOverridesProfile(t *testing.T) {
	directory := resolvedTempDir(t)
	profilePath := filepath.Join(directory, "profile.json")
	credential := filepath.Join(directory, "credential")
	if err := saveProfile(profilePath, profile{Origin: "https://profile.test", CredentialFile: credential, Project: cliProject}); err != nil {
		t.Fatal(err)
	}
	previousLoader, previousFactory := loadCredential, newMemoryClient
	t.Cleanup(func() { loadCredential, newMemoryClient = previousLoader, previousFactory })
	loadCredential = func(string) (string, error) { return "device-secret", nil }
	fake := &recordingClient{}
	newMemoryClient = func(string, string) (client, error) { return fake, nil }

	override := "55555555-5555-4555-8555-555555555555"
	var stdout, stderr strings.Builder
	args := []string{"get", "--profile", profilePath, "--project", override, "--item", cliItem}
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if fake.op != "get" || fake.args[0] != override {
		t.Fatalf("op=%q args=%v", fake.op, fake.args)
	}
}

func TestRunExplicitOriginAndCredentialOverrideProfile(t *testing.T) {
	directory := resolvedTempDir(t)
	profilePath := filepath.Join(directory, "profile.json")
	profileCredential := filepath.Join(directory, "profile-credential")
	overrideCredential := filepath.Join(directory, "override-credential")
	if err := saveProfile(profilePath, profile{Origin: "https://profile.test", CredentialFile: profileCredential, Project: cliProject}); err != nil {
		t.Fatal(err)
	}
	previousLoader, previousFactory := loadCredential, newMemoryClient
	t.Cleanup(func() { loadCredential, newMemoryClient = previousLoader, previousFactory })
	loadCredential = func(path string) (string, error) {
		if path != overrideCredential {
			t.Fatalf("credential path=%q", path)
		}
		return "override-secret", nil
	}
	fake := &recordingClient{}
	newMemoryClient = func(origin, value string) (client, error) {
		if origin != "https://override.test" || value != "override-secret" {
			t.Fatalf("factory origin=%q credential=%q", origin, value)
		}
		return fake, nil
	}

	var stdout, stderr strings.Builder
	args := []string{"get", "--profile", profilePath, "--origin", "https://override.test", "--credential-file", overrideCredential, "--item", cliItem}
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if fake.op != "get" || fake.args[0] != cliProject {
		t.Fatalf("op=%q args=%v", fake.op, fake.args)
	}
}

func TestRunProfileWritePersistsProtectedDefaults(t *testing.T) {
	directory := resolvedTempDir(t)
	profilePath := filepath.Join(directory, "profile.json")
	credential := filepath.Join(directory, "credential")
	var stdout, stderr strings.Builder
	args := []string{"profile-write", "--profile", profilePath, "--origin", "https://profile.test", "--credential-file", credential, "--project", cliProject}
	if code := run(args, &stdout, &stderr); code != 0 || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	info, err := os.Lstat(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("profile mode=%o", info.Mode().Perm())
	}
	loaded, err := loadProfile(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Origin != "https://profile.test" || loaded.CredentialFile != credential || loaded.Project != cliProject {
		t.Fatalf("profile=%#v", loaded)
	}
}

func TestRunProfileWriteRejectsCredentialClobber(t *testing.T) {
	directory := resolvedTempDir(t)
	credential := filepath.Join(directory, "credential")
	if err := os.WriteFile(credential, []byte("device-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr strings.Builder
	args := []string{"profile-write", "--profile", credential, "--origin", "https://profile.test", "--credential-file", credential}
	if code := run(args, &stdout, &stderr); code != 2 || stdout.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	raw, err := os.ReadFile(credential) // #nosec G304 -- test verifies the explicitly created credential fixture was not overwritten.
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "device-secret" {
		t.Fatalf("credential was clobbered: %q", string(raw))
	}
}

func TestRunProfileWriteRejectsInvalidDefaultsAsUsage(t *testing.T) {
	directory := resolvedTempDir(t)
	credential := filepath.Join(directory, "credential")
	tests := [][]string{
		{"profile-write", "--profile", "relative.json", "--origin", "https://profile.test", "--credential-file", credential},
		{"profile-write", "--profile", filepath.Join(directory, "profile.json"), "--origin", "http://profile.test", "--credential-file", credential},
		{"profile-write", "--profile", filepath.Join(directory, "profile.json"), "--origin", "https://user@profile.test", "--credential-file", credential},
		{"profile-write", "--profile", filepath.Join(directory, "profile.json"), "--origin", "https://profile.test/path", "--credential-file", credential},
		{"profile-write", "--profile", filepath.Join(directory, "profile.json"), "--origin", "https://profile.test", "--credential-file", credential, "--project", "not-a-uuid"},
	}
	for _, args := range tests {
		var stdout, stderr strings.Builder
		if code := run(args, &stdout, &stderr); code != 2 || stdout.Len() != 0 {
			t.Fatalf("args=%v code=%d stdout=%q stderr=%q", args, code, stdout.String(), stderr.String())
		}
	}
}

func TestLoadProfileRejectsUnsafeProfileFiles(t *testing.T) {
	directory := resolvedTempDir(t)
	credential := filepath.Join(directory, "credential")
	tests := []struct {
		name string
		raw  string
		mode os.FileMode
	}{
		{"group readable", `{"version":1,"origin":"https://profile.test","credential_file":"` + credential + `"}`, 0o640},
		{"unknown field", `{"version":1,"origin":"https://profile.test","credential_file":"` + credential + `","secret":"device-secret"}`, 0o600},
		{"duplicate field", `{"version":1,"origin":"https://first.test","origin":"https://second.test","credential_file":"` + credential + `"}`, 0o600},
		{"relative credential", `{"version":1,"origin":"https://profile.test","credential_file":"relative"}`, 0o600},
		{"unsafe origin", `{"version":1,"origin":"https://user@profile.test","credential_file":"` + credential + `"}`, 0o600},
		{"invalid project", `{"version":1,"origin":"https://profile.test","credential_file":"` + credential + `","project":"not-a-uuid"}`, 0o600},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profilePath := filepath.Join(directory, strings.ReplaceAll(test.name, " ", "-")+".json")
			if err := os.WriteFile(profilePath, []byte(test.raw), test.mode); err != nil {
				t.Fatal(err)
			}
			if _, err := loadProfile(profilePath); err == nil {
				t.Fatal("unsafe profile accepted")
			}
		})
	}
}

func TestRunProfileFailureIsSanitized(t *testing.T) {
	directory := resolvedTempDir(t)
	profilePath := filepath.Join(directory, "profile.json")
	if err := os.WriteFile(profilePath, []byte(`{"version":1,"origin":"https://profile.test","credential_file":"/tmp/device-secret"}`), 0o644); err != nil { // #nosec G306 -- test deliberately creates an over-permissive profile fixture.
		t.Fatal(err)
	}
	var stdout, stderr strings.Builder
	args := []string{"get", "--profile", profilePath, "--item", cliItem}
	if code := run(args, &stdout, &stderr); code != 1 || stdout.Len() != 0 || stderr.String() != "punaro-memory: profile failed\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stderr.String(), "device-secret") || strings.Contains(stderr.String(), profilePath) {
		t.Fatalf("sensitive profile detail leaked: %q", stderr.String())
	}

	missingParentProfile := filepath.Join(directory, "missing", "profile.json")
	stdout.Reset()
	stderr.Reset()
	args = []string{"get", "--profile", missingParentProfile, "--item", cliItem}
	if code := run(args, &stdout, &stderr); code != 1 || stdout.Len() != 0 || stderr.String() != "punaro-memory: profile failed\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stderr.String(), missingParentProfile) {
		t.Fatalf("sensitive profile detail leaked: %q", stderr.String())
	}
}

func TestRunRejectsProfileBelowWritableParent(t *testing.T) {
	directory := resolvedTempDir(t)
	writableDirectory := filepath.Join(directory, "writable")
	if err := os.Mkdir(writableDirectory, 0o777); err != nil { // #nosec G301 -- test deliberately creates an unsafe writable parent directory.
		t.Fatal(err)
	}
	if err := os.Chmod(writableDirectory, 0o777); err != nil { // #nosec G302 -- test deliberately creates an unsafe writable parent directory.
		t.Fatal(err)
	}
	profilePath := filepath.Join(writableDirectory, "profile.json")
	raw := `{"version":1,"origin":"https://profile.test","credential_file":"` + filepath.Join(directory, "credential") + `","project":"` + cliProject + `"}`
	if err := os.WriteFile(profilePath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr strings.Builder
	args := []string{"get", "--profile", profilePath, "--item", cliItem}
	if code := run(args, &stdout, &stderr); code != 1 || stdout.Len() != 0 || stderr.String() != "punaro-memory: profile failed\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
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
	if err := os.Chmod(directory, 0o700); err != nil { // #nosec G302 -- profile tests require an owner-only temporary directory.
		t.Fatal(err)
	}
	if privateProfilePath(filepath.Join(directory, "profile.json")) {
		return directory
	}
	directory, err = os.MkdirTemp(".", ".punaro-memory-profile-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil { // #nosec G304 -- test removes the private temporary directory it created.
			t.Errorf("remove temporary profile directory: %v", err)
		}
	})
	directory, err = filepath.Abs(directory)
	if err != nil {
		t.Fatal(err)
	}
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	if !privateProfilePath(filepath.Join(directory, "profile.json")) {
		t.Fatal("temporary profile directory has unsafe ancestry")
	}
	return directory
}
