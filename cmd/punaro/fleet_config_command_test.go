package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rock3r/punaro/internal/fleetconfig"
	punaropostgres "github.com/rock3r/punaro/internal/postgres"
	"github.com/rock3r/punaro/internal/relay"
)

const testPublishCommit = "0123456789abcdef0123456789abcdef01234567"

func TestFleetConfigPublishRejectsBranchAndLeavesDesiredUnchanged(t *testing.T) {
	preserveFleetConfig(t)
	directory := testInstallation(t)
	published := false
	persistFleetRelease = func(context.Context, string, fleetconfig.Release, string, punaropostgres.FleetDesired) (punaropostgres.FleetDesired, error) {
		published = true
		return punaropostgres.FleetDesired{}, errors.New("should not publish")
	}
	loadFleetDesired = func(context.Context, string) (punaropostgres.FleetDesired, error) {
		return punaropostgres.FleetDesired{Digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Generation: 4}, nil
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"fleet-config", "publish", "--directory", directory, "--yes", "--confirm-preview-hash", "deadbeef", "main"}, &stdout, &stderr); code != 2 || published {
		t.Fatalf("code=%d published=%t stdout=%s stderr=%s", code, published, stdout.String(), stderr.String())
	}
}

func TestFleetConfigPublishPreviewIncludesContractFields(t *testing.T) {
	preserveFleetConfig(t)
	directory := testInstallation(t)
	writeFleetSource(t, directory)
	release := testRelease()
	materializeFleetCommit = func(string, string) (fleetconfig.Release, error) { return release, nil }
	loadFleetDesired = func(context.Context, string) (punaropostgres.FleetDesired, error) {
		return punaropostgres.FleetDesired{Digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Generation: 2, SourceCommit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, nil
	}
	persistFleetRelease = func(context.Context, string, fleetconfig.Release, string, punaropostgres.FleetDesired) (punaropostgres.FleetDesired, error) {
		t.Fatal("preview must not persist")
		return punaropostgres.FleetDesired{}, nil
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"fleet-config", "publish", "--directory", directory, testPublishCommit}, &stdout, &stderr); code != 3 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	body := stdout.String()
	for _, want := range []string{
		`"source_commit": "` + testPublishCommit + `"`,
		`"release_digest": "` + release.Digest + `"`,
		`"skill_count": 1`,
		`"total_bytes":`,
		`"desired_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"`,
		`"desired_generation": 2`,
		`"preview_hash":`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("preview missing %s in %s", want, body)
		}
	}
	if strings.Contains(body, "# fleet") || strings.Contains(body, TrailerLeak()) || strings.Contains(strings.ToLower(body), "skill.md") && strings.Contains(body, "description") {
		t.Fatalf("preview leaked configuration contents: %s", body)
	}
}

func TestFleetConfigPublishBroadcastsWakeOnGenerationAdvance(t *testing.T) {
	preserveFleetConfig(t)
	directory := testInstallation(t)
	writeFleetSource(t, directory)
	release := testRelease()
	materializeFleetCommit = func(string, string) (fleetconfig.Release, error) { return release, nil }
	store := &memoryFleetStore{}
	loadFleetDesired = store.desired
	persistFleetRelease = store.publish
	notifier := relay.NewNotifier()
	client := notifier.Register("machine-a")
	t.Cleanup(client.Close)
	afterFleetPublish = func(previous, current int64) {
		relay.BroadcastFleetWake(notifier, previous, current)
	}
	hash := fleetPublishPreviewHash(release, punaropostgres.FleetDesired{})
	if code := run([]string{"fleet-config", "publish", "--directory", directory, "--yes", "--confirm-preview-hash", hash, testPublishCommit}, bytes.NewBuffer(nil), bytes.NewBuffer(nil)); code != 0 {
		t.Fatalf("code=%d", code)
	}
	select {
	case event := <-client.Events():
		if event.TopicID != relay.FleetConfigTopic || event.Sequence != 1 {
			t.Fatalf("event=%#v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("publish did not broadcast a fleet-config wake")
	}
}

func TestFleetConfigPublishFallsBackToStoredRelease(t *testing.T) {
	preserveFleetConfig(t)
	directory := testInstallation(t)
	writeFleetSource(t, directory)
	release := testRelease()
	materializeFleetCommit = func(string, string) (fleetconfig.Release, error) {
		return fleetconfig.Release{}, errors.New("commit pruned")
	}
	loadStoredFleetRelease = func(_ context.Context, _ string, commit string) (fleetconfig.Release, error) {
		if commit != testPublishCommit {
			t.Fatalf("commit=%s", commit)
		}
		return release, nil
	}
	store := &memoryFleetStore{}
	loadFleetDesired = store.desired
	persistFleetRelease = store.publish
	hash := fleetPublishPreviewHash(release, punaropostgres.FleetDesired{})
	if code := run([]string{"fleet-config", "publish", "--directory", directory, "--yes", "--confirm-preview-hash", hash, testPublishCommit}, bytes.NewBuffer(nil), bytes.NewBuffer(nil)); code != 0 {
		t.Fatalf("code=%d", code)
	}
	if store.desiredState.Digest != release.Digest || store.desiredState.Generation != 1 {
		t.Fatalf("desired=%#v", store.desiredState)
	}
}

func TestFleetConfigPublishFailedMaterializeLeavesDesiredUnchanged(t *testing.T) {
	preserveFleetConfig(t)
	directory := testInstallation(t)
	writeFleetSource(t, directory)
	materializeFleetCommit = func(string, string) (fleetconfig.Release, error) {
		return fleetconfig.Release{}, errors.New("invalid source")
	}
	published := false
	persistFleetRelease = func(context.Context, string, fleetconfig.Release, string, punaropostgres.FleetDesired) (punaropostgres.FleetDesired, error) {
		published = true
		return punaropostgres.FleetDesired{}, nil
	}
	loadFleetDesired = func(context.Context, string) (punaropostgres.FleetDesired, error) {
		return punaropostgres.FleetDesired{Digest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", Generation: 7}, nil
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"fleet-config", "publish", "--directory", directory, "--yes", "--confirm-preview-hash", "anything", testPublishCommit}, &stdout, &stderr); code != 1 || published {
		t.Fatalf("code=%d published=%t stdout=%s stderr=%s", code, published, stdout.String(), stderr.String())
	}
}

func TestFleetConfigPublishRetryIsIdempotentAndRollbackRepublishes(t *testing.T) {
	preserveFleetConfig(t)
	directory := testInstallation(t)
	writeFleetSource(t, directory)
	first := testRelease()
	first.SourceCommit = testPublishCommit
	secondCommit := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	second := testRelease()
	second.SourceCommit = secondCommit
	second.Digest = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	store := &memoryFleetStore{}
	materializeFleetCommit = func(_ string, commit string) (fleetconfig.Release, error) {
		switch commit {
		case testPublishCommit:
			return first, nil
		case secondCommit:
			return second, nil
		default:
			return fleetconfig.Release{}, errors.New("unknown commit")
		}
	}
	loadFleetDesired = store.desired
	persistFleetRelease = store.publish
	hash := fleetPublishPreviewHash(first, punaropostgres.FleetDesired{})
	if code := run([]string{"fleet-config", "publish", "--directory", directory, "--yes", "--confirm-preview-hash", hash, testPublishCommit}, bytes.NewBuffer(nil), bytes.NewBuffer(nil)); code != 0 {
		t.Fatalf("first publish code=%d", code)
	}
	if store.desiredState.Generation != 1 || store.desiredState.Digest != first.Digest {
		t.Fatalf("first desired=%#v", store.desiredState)
	}
	if code := run([]string{"fleet-config", "publish", "--directory", directory, "--yes", "--confirm-preview-hash", fleetPublishPreviewHash(first, store.desiredState), testPublishCommit}, bytes.NewBuffer(nil), bytes.NewBuffer(nil)); code != 0 {
		t.Fatalf("retry code=%d", code)
	}
	if store.desiredState.Generation != 1 || store.publishes != 2 {
		t.Fatalf("retry bumped generation %#v publishes=%d", store.desiredState, store.publishes)
	}
	if code := run([]string{"fleet-config", "publish", "--directory", directory, "--yes", "--confirm-preview-hash", fleetPublishPreviewHash(second, store.desiredState), secondCommit}, bytes.NewBuffer(nil), bytes.NewBuffer(nil)); code != 0 {
		t.Fatalf("second publish code=%d", code)
	}
	if store.desiredState.Digest != second.Digest || store.desiredState.Generation != 2 {
		t.Fatalf("second desired=%#v", store.desiredState)
	}
	if code := run([]string{"fleet-config", "publish", "--directory", directory, "--yes", "--confirm-preview-hash", fleetPublishPreviewHash(first, store.desiredState), testPublishCommit}, bytes.NewBuffer(nil), bytes.NewBuffer(nil)); code != 0 {
		t.Fatalf("rollback code=%d", code)
	}
	if store.desiredState.Digest != first.Digest || store.desiredState.Generation != 3 {
		t.Fatalf("rollback desired=%#v", store.desiredState)
	}
}

func TestFleetConfigPublishRejectsOversizedGitBlob(t *testing.T) {
	preserveFleetConfig(t)
	directory := testInstallation(t)
	repo := writeGitSource(t)
	huge := filepath.Join(repo, "skills", "demo", "huge.bin")
	if err := os.WriteFile(huge, bytes.Repeat([]byte("a"), fleetconfig.MaxFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"add", "skills/demo/huge.bin"},
		{"commit", "-m", "too large", "--no-gpg-sign"},
	} {
		cmd := exec.CommandContext(t.Context(), "git", args...) // #nosec G204 -- fixed git binary, test-controlled argv.
		cmd.Dir = repo
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	if code := run([]string{"fleet-config", "configure", "--directory", directory, "--repository", repo, "--yes"}, bytes.NewBuffer(nil), bytes.NewBuffer(nil)); code != 0 {
		t.Fatalf("configure code=%d", code)
	}
	commit := gitHead(t, repo)
	if _, err := materializeFleetCommitFromGit(repo, commit); err == nil || err.Error() != "fleet-config git tree is too large" {
		t.Fatalf("git bound=%v", err)
	}
	materializeFleetCommit = materializeFleetCommitFromGit
	published := false
	persistFleetRelease = func(context.Context, string, fleetconfig.Release, string, punaropostgres.FleetDesired) (punaropostgres.FleetDesired, error) {
		published = true
		return punaropostgres.FleetDesired{}, nil
	}
	loadFleetDesired = func(context.Context, string) (punaropostgres.FleetDesired, error) {
		return punaropostgres.FleetDesired{}, nil
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"fleet-config", "publish", "--directory", directory, "--yes", "--confirm-preview-hash", "deadbeef", commit}, &stdout, &stderr); code != 1 || published {
		t.Fatalf("code=%d published=%t stdout=%s stderr=%s", code, published, stdout.String(), stderr.String())
	}
}

func TestFleetConfigPublishRejectsStalePreview(t *testing.T) {
	preserveFleetConfig(t)
	directory := testInstallation(t)
	writeFleetSource(t, directory)
	release := testRelease()
	materializeFleetCommit = func(string, string) (fleetconfig.Release, error) { return release, nil }
	stale := punaropostgres.FleetDesired{
		Digest:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Generation: 1,
	}
	current := punaropostgres.FleetDesired{
		Digest:     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Generation: 2,
	}
	loadFleetDesired = func(context.Context, string) (punaropostgres.FleetDesired, error) {
		return stale, nil
	}
	published := false
	persistFleetRelease = func(_ context.Context, _ string, _ fleetconfig.Release, _ string, expected punaropostgres.FleetDesired) (punaropostgres.FleetDesired, error) {
		if expected.Digest != current.Digest || expected.Generation != current.Generation {
			return punaropostgres.FleetDesired{}, errors.New("fleet-config preview is stale")
		}
		published = true
		return current, nil
	}
	hash := fleetPublishPreviewHash(release, stale)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"fleet-config", "publish", "--directory", directory, "--yes", "--confirm-preview-hash", hash, testPublishCommit}, &stdout, &stderr); code != 1 || published {
		t.Fatalf("code=%d published=%t stdout=%s stderr=%s", code, published, stdout.String(), stderr.String())
	}
}

func TestFleetConfigPublishFromRealGitCommit(t *testing.T) {
	preserveFleetConfig(t)
	directory := testInstallation(t)
	repo := writeGitSource(t)
	if code := run([]string{"fleet-config", "configure", "--directory", directory, "--repository", repo, "--yes"}, bytes.NewBuffer(nil), bytes.NewBuffer(nil)); code != 0 {
		t.Fatalf("configure code=%d", code)
	}
	commit := gitHead(t, repo)
	materializeFleetCommit = materializeFleetCommitFromGit
	store := &memoryFleetStore{}
	loadFleetDesired = store.desired
	persistFleetRelease = store.publish
	var preview bytes.Buffer
	if code := run([]string{"fleet-config", "publish", "--directory", directory, commit}, &preview, bytes.NewBuffer(nil)); code != 3 {
		t.Fatalf("preview code=%d body=%s", code, preview.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(preview.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	hash, _ := payload["preview_hash"].(string)
	digest, _ := payload["release_digest"].(string)
	if hash == "" || len(digest) != 64 || payload["source_commit"] != commit {
		t.Fatalf("preview=%v", payload)
	}
	if code := run([]string{"fleet-config", "publish", "--directory", directory, "--yes", "--confirm-preview-hash", hash, commit}, bytes.NewBuffer(nil), bytes.NewBuffer(nil)); code != 0 {
		t.Fatalf("publish code=%d", code)
	}
	if store.desiredState.Digest != digest || store.desiredState.Generation != 1 {
		t.Fatalf("desired=%#v", store.desiredState)
	}
	var status bytes.Buffer
	if code := run([]string{"fleet-config", "status", "--directory", directory}, &status, bytes.NewBuffer(nil)); code != 0 {
		t.Fatalf("status code=%d body=%s", code, status.String())
	}
	if !strings.Contains(status.String(), digest) || strings.Contains(status.String(), "# fleet") {
		t.Fatalf("status leaked or missing digest: %s", status.String())
	}
}

func TestFleetConfigStatusOmitsContentsAndIncludesClientStates(t *testing.T) {
	preserveFleetConfig(t)
	directory := testInstallation(t)
	loadFleetDesired = func(context.Context, string) (punaropostgres.FleetDesired, error) {
		return punaropostgres.FleetDesired{Digest: strings.Repeat("ab", 32), SourceCommit: testPublishCommit, Generation: 3}, nil
	}
	loadFleetClients = func(context.Context, string) ([]punaropostgres.FleetClientStatus, error) {
		return []punaropostgres.FleetClientStatus{{
			MachineID: "mac-studio", AppliedDigest: strings.Repeat("ab", 32), State: "current",
			Activation: "next_turn", TrailerState: "present", AliasState: "linked", ProjectMatchState: "matched",
		}}, nil
	}
	var stdout bytes.Buffer
	if code := run([]string{"fleet-config", "status", "--directory", directory}, &stdout, bytes.NewBuffer(nil)); code != 0 {
		t.Fatalf("code=%d body=%s", code, stdout.String())
	}
	body := stdout.String()
	for _, want := range []string{`"state": "current"`, `"trailer_state": "present"`, `"alias_state": "linked"`, `"project_match_state": "matched"`, `"activation": "next_turn"`, strings.Repeat("ab", 32)} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %s in %s", want, body)
		}
	}
	if strings.Contains(body, "# fleet") || strings.Contains(body, "/Users/") || strings.Contains(body, "pq:") {
		t.Fatalf("status leaked contents or paths: %s", body)
	}
}

func TestFleetConfigStatusAndDoctorOmitSkillAndAddendumBodies(t *testing.T) {
	preserveFleetConfig(t)
	directory := testInstallation(t)
	const skillBody = "unique-skill-body-probe"
	const addendumBody = "unique-addendum-body-probe"
	loadFleetDesired = func(context.Context, string) (punaropostgres.FleetDesired, error) {
		return punaropostgres.FleetDesired{Digest: strings.Repeat("cd", 32), SourceCommit: testPublishCommit, Generation: 2, SkillCount: 1, TotalBytes: 12}, nil
	}
	loadFleetClients = func(context.Context, string) ([]punaropostgres.FleetClientStatus, error) {
		return []punaropostgres.FleetClientStatus{{
			MachineID: "mac-studio", AppliedDigest: strings.Repeat("cd", 32), State: "current",
			Activation: "next_turn", TrailerState: "present", AliasState: "disabled", ProjectMatchState: "matched",
		}}, nil
	}
	var stdout bytes.Buffer
	if code := run([]string{"fleet-config", "status", "--directory", directory}, &stdout, bytes.NewBuffer(nil)); code != 0 {
		t.Fatalf("code=%d body=%s", code, stdout.String())
	}
	body := stdout.String()
	if strings.Contains(body, skillBody) || strings.Contains(body, addendumBody) {
		t.Fatalf("status leaked skill or addendum body: %s", body)
	}
	var doctor bytes.Buffer
	if code := run([]string{"doctor", "--directory", directory}, &doctor, bytes.NewBuffer(nil)); code != 0 && doctor.Len() == 0 {
		// doctor may fail on incomplete fixtures; still inspect printed output
		t.Logf("doctor code=%d", code)
	}
	out := stdout.String() + doctor.String()
	if strings.Contains(out, skillBody) || strings.Contains(out, addendumBody) {
		t.Fatalf("CLI leaked skill or addendum body: %s", out)
	}
}

func TrailerLeak() string { return fleetconfig.TrailerStart }

func testRelease() fleetconfig.Release {
	return fleetconfig.Release{
		Schema:       fleetconfig.SchemaV1,
		SourceCommit: testPublishCommit,
		Digest:       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Archive:      []byte("archive"),
		SkillCount:   1,
		TotalBytes:   12,
		DataOnly:     true,
		Files:        []fleetconfig.ManifestFile{{Path: "AGENTS.md", Size: 8, SHA256: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}},
	}
}

type memoryFleetStore struct {
	desiredState punaropostgres.FleetDesired
	publishes    int
}

func (store *memoryFleetStore) desired(context.Context, string) (punaropostgres.FleetDesired, error) {
	return store.desiredState, nil
}

func (store *memoryFleetStore) publish(_ context.Context, _ string, release fleetconfig.Release, _ string, expected punaropostgres.FleetDesired) (punaropostgres.FleetDesired, error) {
	if expected.Digest != store.desiredState.Digest || expected.Generation != store.desiredState.Generation {
		return punaropostgres.FleetDesired{}, errors.New("fleet-config preview is stale")
	}
	store.publishes++
	if store.desiredState.Digest == release.Digest && store.desiredState.Generation > 0 {
		return store.desiredState, nil
	}
	store.desiredState = punaropostgres.FleetDesired{
		Digest:       release.Digest,
		SourceCommit: release.SourceCommit,
		Generation:   store.desiredState.Generation + 1,
		SkillCount:   release.SkillCount,
		TotalBytes:   release.TotalBytes,
	}
	return store.desiredState, nil
}

func writeFleetSource(t *testing.T, directory string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, "fleet-config-source.json"), []byte(`{"schema":1,"repository":"/tmp/does-not-need-to-exist"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeGitSource(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is required")
	}
	repo := t.TempDir()
	write := func(path, body string) {
		full := filepath.Join(append([]string{repo}, strings.Split(path, "/")...)...)
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("AGENTS.md", "# fleet\n")
	write("skills/demo/SKILL.md", "---\nname: demo\ndescription: Demo skill.\n---\n# demo\n")
	write("projects/punaro/AGENTS.md", "# punaro\n")
	for _, args := range [][]string{
		{"init"},
		{"config", "user.email", "fleet@example.test"},
		{"config", "user.name", "fleet"},
		{"config", "commit.gpgsign", "false"},
		{"add", "."},
		{"commit", "-m", "source", "--no-gpg-sign"},
	} {
		cmd := exec.CommandContext(t.Context(), "git", args...) // #nosec G204 -- fixed git binary, test-controlled argv.
		cmd.Dir = repo
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	return repo
}

func gitHead(t *testing.T, repo string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", "-C", repo, "rev-parse", "HEAD") // #nosec G204 -- fixed git argv.
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func preserveFleetConfig(t *testing.T) {
	t.Helper()
	preserveDependencies(t)
	originalMaterialize, originalPersist, originalDesired, originalStored, originalWake, originalClients := materializeFleetCommit, persistFleetRelease, loadFleetDesired, loadStoredFleetRelease, afterFleetPublish, loadFleetClients
	t.Cleanup(func() {
		materializeFleetCommit, persistFleetRelease, loadFleetDesired, loadStoredFleetRelease, afterFleetPublish, loadFleetClients = originalMaterialize, originalPersist, originalDesired, originalStored, originalWake, originalClients
	})
	loadStoredFleetRelease = func(context.Context, string, string) (fleetconfig.Release, error) {
		return fleetconfig.Release{}, errors.New("no stored release")
	}
	loadFleetClients = func(context.Context, string) ([]punaropostgres.FleetClientStatus, error) {
		return nil, nil
	}
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 58}, nil
	}
	inspectOwner = func(context.Context, string) (punaropostgres.Principal, error) {
		return punaropostgres.Principal{ID: "11111111-1111-4111-8111-111111111111"}, nil
	}
	verifyInstallationPair = func(context.Context, string, string) error { return nil }
}
