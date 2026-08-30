package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	punarorelease "github.com/rock3r/punaro/internal/release"
)

const (
	testCompose  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testMigrate  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testKeyID    = "punaro-release-1"
	testArtifact = "adapter-bytes-for-bootstrap"
)

func privateDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "bootstrap")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestUpdateInstallsSignedPlatformArtifacts(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH})
	dir := privateDir(t)
	result, err := Update(Request{
		Directory: dir,
		Origin:    origin.URL,
		Keys:      origin.Keys,
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
		Now:       time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Release != "v0.1.0" || result.Sequence != 1 {
		t.Fatalf("result=%#v", result)
	}
	installed := filepath.Join(dir, "current", artifactName("punaro-adapter", runtime.GOOS, runtime.GOARCH))
	body, err := os.ReadFile(installed) // #nosec G304 -- path is under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != testArtifact {
		t.Fatalf("installed=%q", body)
	}
	status, err := Status(dir)
	if err != nil {
		t.Fatal(err)
	}
	if status.Current != "v0.1.0" || status.CurrentSequence != 1 || status.Previous != "" {
		t.Fatalf("status=%#v", status)
	}
}

func TestUpdateReportsContentFreeDownloadPhase(t *testing.T) {
	name := artifactName("punaro-adapter", runtime.GOOS, runtime.GOARCH)
	for _, test := range []struct {
		name     string
		failPath string
		phase    string
	}{
		{name: "catalog", failPath: punarorelease.CatalogReleaseName + "/" + punarorelease.CatalogFile, phase: "catalog"},
		{name: "catalog signature", failPath: punarorelease.CatalogReleaseName + "/" + punarorelease.CatalogSignatureFile, phase: "signature"},
		{name: "manifest", failPath: "v0.1.0/" + punarorelease.ReleaseManifestFile, phase: "manifest"},
		{name: "artifact", failPath: "v0.1.0/" + name, phase: "artifact"},
	} {
		t.Run(test.name, func(t *testing.T) {
			origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH})
			fetcher := &recordingFetcher{files: origin.Files, failPath: test.failPath}
			_, err := Update(Request{
				Directory: privateDir(t),
				Origin:    origin.URL,
				Keys:      origin.Keys,
				GOOS:      runtime.GOOS,
				GOARCH:    runtime.GOARCH,
				Now:       time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC),
				HTTP:      fetcher,
			})
			want := "release download failed: phase=" + test.phase + " category=transport"
			if err == nil || err.Error() != want {
				t.Fatalf("err=%v want=%q", err, want)
			}
			if strings.Contains(err.Error(), test.failPath) || fetcher.calls[test.failPath] != 1 {
				t.Fatalf("err=%v calls=%d", err, fetcher.calls[test.failPath])
			}
		})
	}
}

func TestUpdateAppliesOneOverallDownloadDeadline(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH})
	fetcher := &recordingFetcher{files: origin.Files, waitForCancel: true}
	started := time.Now()
	_, err := Update(Request{
		Directory:       privateDir(t),
		Origin:          origin.URL,
		Keys:            origin.Keys,
		GOOS:            runtime.GOOS,
		GOARCH:          runtime.GOARCH,
		Now:             time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC),
		HTTP:            fetcher,
		DownloadTimeout: 20 * time.Millisecond,
	})
	if err == nil || err.Error() != "release download failed: phase=catalog category=timeout" {
		t.Fatalf("err=%v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("overall deadline took %s", elapsed)
	}
}

func TestUpdateDoesNotRetryVerificationFailure(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH})
	name := artifactName("punaro-adapter", runtime.GOOS, runtime.GOARCH)
	path := "v0.1.0/" + name
	files := cloneFiles(origin.Files)
	files[path] = []byte(strings.Repeat("x", len(testArtifact)))
	fetcher := &recordingFetcher{files: files}
	_, err := Update(Request{
		Directory: privateDir(t),
		Origin:    origin.URL,
		Keys:      origin.Keys,
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
		Now:       time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC),
		HTTP:      fetcher,
	})
	if err == nil || err.Error() != "release artifact digest mismatch" {
		t.Fatalf("err=%v", err)
	}
	if fetcher.calls[path] != 1 {
		t.Fatalf("verification failure fetched artifact %d times", fetcher.calls[path])
	}
}

func TestFailedArtifactDownloadPreservesPublishedSlotsAndValidJournal(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: "first", goos: runtime.GOOS, goarch: runtime.GOARCH})
	dir := privateDir(t)
	req := Request{Directory: dir, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}
	if _, err := Update(req); err != nil {
		t.Fatal(err)
	}
	currentBefore, err := os.ReadFile(filepath.Join(dir, currentSlot, slotRecord)) // #nosec G304 -- fixed fixture path under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	acceptedBefore, err := os.ReadFile(filepath.Join(dir, acceptedFile)) // #nosec G304 -- fixed fixture path under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	origin.republish(t, originSpec{payload: "second", goos: runtime.GOOS, goarch: runtime.GOARCH, release: "v0.2.0", sequence: 2, catalogSequence: 2})
	artifactPath := "v0.2.0/" + artifactName("punaro-adapter", runtime.GOOS, runtime.GOARCH)
	req.HTTP = &recordingFetcher{files: origin.Files, failPath: artifactPath}
	if _, err := Update(req); err == nil {
		t.Fatal("failed artifact download succeeded")
	}
	currentAfter, err := os.ReadFile(filepath.Join(dir, currentSlot, slotRecord)) // #nosec G304 -- fixed fixture path under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	acceptedAfter, err := os.ReadFile(filepath.Join(dir, acceptedFile)) // #nosec G304 -- fixed fixture path under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(currentBefore, currentAfter) || !bytes.Equal(acceptedBefore, acceptedAfter) {
		t.Fatal("failed download changed published current or accepted state")
	}
	if _, err := os.Lstat(filepath.Join(dir, previousSlot)); !os.IsNotExist(err) {
		t.Fatal("failed download published a previous slot")
	}
	record, err := readJournal(dir)
	if err != nil || record.Phase != "staging" || record.Release != "v0.2.0" {
		t.Fatalf("journal=%#v err=%v", record, err)
	}
}

func TestUpdateQuarantinesInvalidCurrentNode(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH})
	dir := privateDir(t)
	if err := os.WriteFile(filepath.Join(dir, currentSlot), []byte("not-a-slot"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Update(Request{
		Directory: dir,
		Origin:    origin.URL,
		Keys:      origin.Keys,
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
		Now:       time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Release != "v0.1.0" || result.Sequence != 1 {
		t.Fatalf("result=%#v", result)
	}
	status, err := Status(dir)
	if err != nil {
		t.Fatal(err)
	}
	if status.Current != "v0.1.0" {
		t.Fatalf("status=%#v", status)
	}
}

func TestUpdatePromotesCurrentToPrevious(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: "first", goos: runtime.GOOS, goarch: runtime.GOARCH})
	dir := privateDir(t)
	req := Request{Directory: dir, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}
	if _, err := Update(req); err != nil {
		t.Fatal(err)
	}
	origin.republish(t, originSpec{payload: "second", goos: runtime.GOOS, goarch: runtime.GOARCH, release: "v0.2.0", sequence: 2, catalogSequence: 2})
	if _, err := Update(req); err != nil {
		t.Fatal(err)
	}
	status, err := Status(dir)
	if err != nil {
		t.Fatal(err)
	}
	if status.Current != "v0.2.0" || status.CurrentSequence != 2 || status.Previous != "v0.1.0" || status.PreviousSequence != 1 {
		t.Fatalf("status=%#v", status)
	}
	current, err := os.ReadFile(filepath.Join(dir, "current", artifactName("punaro-adapter", runtime.GOOS, runtime.GOARCH))) // #nosec G304 -- path is under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	previous, err := os.ReadFile(filepath.Join(dir, "previous", artifactName("punaro-adapter", runtime.GOOS, runtime.GOARCH))) // #nosec G304 -- path is under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != "second" || string(previous) != "first" {
		t.Fatalf("current=%q previous=%q", current, previous)
	}
}

func TestUpdateSameIdentityQuarantinesCorruptPrevious(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: "first", goos: runtime.GOOS, goarch: runtime.GOARCH})
	dir := privateDir(t)
	req := Request{Directory: dir, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}
	if _, err := Update(req); err != nil {
		t.Fatal(err)
	}
	origin.republish(t, originSpec{payload: "second", goos: runtime.GOOS, goarch: runtime.GOARCH, release: "v0.2.0", sequence: 2, catalogSequence: 2})
	if _, err := Update(req); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, previousSlot, slotRecord), []byte(`{"schema":1`), 0o600); err != nil {
		t.Fatal(err)
	}
	writeRecoveryOnly(t, dir)
	if _, err := Update(req); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, previousSlot)); !os.IsNotExist(err) {
		t.Fatal("same-identity update left a corrupt previous slot")
	}
	if recoveryOnly(t, dir) {
		t.Fatal("same-identity update left recovery-only")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, RunRequest{
			Directory:     dir,
			HealthTimeout: 20 * time.Millisecond,
			Start: func(ctx context.Context, spec ChildSpec) (Process, error) {
				if err := writeReady(spec.Env); err != nil {
					return nil, err
				}
				return blockingProcess(ctx), nil
			},
		})
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	if err := <-errCh; errors.Is(err, ErrRecoveryOnly) {
		t.Fatal("quarantined previous still entered recovery-only")
	}
}

func TestUpdateDoesNotRotateIdenticalCurrent(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH})
	dir := privateDir(t)
	req := Request{Directory: dir, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}
	if _, err := Update(req); err != nil {
		t.Fatal(err)
	}
	if _, err := Update(req); err != nil {
		t.Fatal(err)
	}
	status, err := Status(dir)
	if err != nil {
		t.Fatal(err)
	}
	if status.Current != "v0.1.0" || status.Previous != "" {
		t.Fatalf("identical update rotated slots: %#v", status)
	}
}

func TestUpdateRepairsCurrentWithoutRotatingPrevious(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: "first", goos: runtime.GOOS, goarch: runtime.GOARCH})
	dir := privateDir(t)
	req := Request{Directory: dir, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}
	if _, err := Update(req); err != nil {
		t.Fatal(err)
	}
	origin.republish(t, originSpec{payload: "second", goos: runtime.GOOS, goarch: runtime.GOARCH, release: "v0.2.0", sequence: 2, catalogSequence: 2})
	if _, err := Update(req); err != nil {
		t.Fatal(err)
	}
	// #nosec G306 -- the regression plants a still-executable damaged artifact.
	if err := os.WriteFile(filepath.Join(dir, currentSlot, artifactName("punaro-adapter", runtime.GOOS, runtime.GOARCH)), []byte("damaged"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Update(req); err != nil {
		t.Fatal(err)
	}
	status, err := Status(dir)
	if err != nil {
		t.Fatal(err)
	}
	if status.Current != "v0.2.0" || status.Previous != "v0.1.0" {
		t.Fatalf("repair rotated slots: %#v", status)
	}
	body, err := os.ReadFile(filepath.Join(dir, currentSlot, artifactName("punaro-adapter", runtime.GOOS, runtime.GOARCH))) // #nosec G304 -- path is under t.TempDir.
	if err != nil || string(body) != "second" {
		t.Fatalf("repaired current=%q err=%v", body, err)
	}
}

func TestRollbackSwapsPublishedSlots(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: "first", goos: runtime.GOOS, goarch: runtime.GOARCH})
	dir := privateDir(t)
	req := Request{Directory: dir, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}
	if _, err := Update(req); err != nil {
		t.Fatal(err)
	}
	origin.republish(t, originSpec{payload: "second", goos: runtime.GOOS, goarch: runtime.GOARCH, release: "v0.2.0", sequence: 2, catalogSequence: 2})
	if _, err := Update(req); err != nil {
		t.Fatal(err)
	}
	result, err := Rollback(dir)
	if err != nil {
		t.Fatal(err)
	}
	if result.Release != "v0.1.0" || result.Sequence != 1 {
		t.Fatalf("rollback=%#v", result)
	}
	status, err := Status(dir)
	if err != nil {
		t.Fatal(err)
	}
	if status.Current != "v0.1.0" || status.Previous != "v0.2.0" {
		t.Fatalf("status=%#v", status)
	}
	if _, err := Update(req); err != nil {
		t.Fatal(err)
	}
	status, err = Status(dir)
	if err != nil {
		t.Fatal(err)
	}
	if status.Current != "v0.2.0" || status.Previous != "v0.1.0" {
		t.Fatalf("reupdate status=%#v", status)
	}
}

func TestRollbackSucceedsAfterAutoRollbackDirectoryNode(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: "first", goos: runtime.GOOS, goarch: runtime.GOARCH})
	dir := privateDir(t)
	req := Request{Directory: dir, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}
	if _, err := Update(req); err != nil {
		t.Fatal(err)
	}
	origin.republish(t, originSpec{payload: "second", goos: runtime.GOOS, goarch: runtime.GOARCH, release: "v0.2.0", sequence: 2, catalogSequence: 2})
	if _, err := Update(req); err != nil {
		t.Fatal(err)
	}
	writeNonFileMarker(t, filepath.Join(dir, autoRollbackFile))
	result, err := Rollback(dir)
	if err != nil {
		t.Fatal(err)
	}
	if result.Release != "v0.1.0" || result.Sequence != 1 {
		t.Fatalf("rollback=%#v", result)
	}
	info, err := os.Lstat(filepath.Join(dir, autoRollbackFile))
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("auto-rollback directory survived rollback: info=%v err=%v", info, err)
	}
	if _, err := os.Lstat(filepath.Join(dir, journalFile)); !os.IsNotExist(err) {
		t.Fatal("rolling-back journal survived after replacing auto-rollback")
	}
}

func TestRollbackRequiresPreviousSlot(t *testing.T) {
	dir := privateDir(t)
	if _, err := Rollback(dir); err == nil {
		t.Fatal("rollback without slots accepted")
	}
}

func TestUpdateRejectsUnsignedCatalog(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH})
	delete(origin.Files, punarorelease.CatalogReleaseName+"/"+punarorelease.CatalogSignatureFile)
	dir := privateDir(t)
	if _, err := Update(Request{Directory: dir, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}); err == nil {
		t.Fatal("unsigned catalog accepted")
	}
}

func TestUpdateRejectsUnsignedManifest(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH})
	delete(origin.Files, "v0.1.0/"+punarorelease.ReleaseSignatureFile)
	dir := privateDir(t)
	if _, err := Update(Request{Directory: dir, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}); err == nil {
		t.Fatal("unsigned manifest accepted")
	}
}

func TestUpdateRejectsAlteredArtifactBytes(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH})
	name := artifactName("punaro-adapter", runtime.GOOS, runtime.GOARCH)
	origin.Files["v0.1.0/"+name] = []byte("tampered-adapter-bytes")
	dir := privateDir(t)
	if _, err := Update(Request{Directory: dir, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}); err == nil {
		t.Fatal("altered artifact accepted")
	}
}

func TestUpdateRejectsStaleCatalog(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH})
	dir := privateDir(t)
	if _, err := Update(Request{Directory: dir, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: time.Date(2026, 8, 24, 0, 0, 0, 0, time.UTC)}); err == nil {
		t.Fatal("expired catalog accepted")
	}
}

func TestUpdateRejectsCriticalBlock(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH})
	catalogPath := punarorelease.CatalogReleaseName + "/" + punarorelease.CatalogFile
	catalog := string(origin.Files[catalogPath])
	blocked := strings.Replace(catalog, `"critical_blocks":[]`, `"critical_blocks":[1]`, 1)
	if blocked == catalog {
		t.Fatal("catalog critical blocks field unavailable")
	}
	signature, err := punarorelease.Sign([]byte(blocked), testKeyID, origin.priv)
	if err != nil {
		t.Fatal(err)
	}
	signatureJSON, err := punarorelease.EncodeEnvelope(signature)
	if err != nil {
		t.Fatal(err)
	}
	origin.Files[catalogPath] = []byte(blocked)
	origin.Files[punarorelease.CatalogReleaseName+"/"+punarorelease.CatalogSignatureFile] = signatureJSON
	dir := privateDir(t)
	if _, err := Update(Request{Directory: dir, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}); err == nil {
		t.Fatal("critically blocked release accepted")
	}
}

func TestUpdateRejectsReleaseSequenceDowngrade(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH})
	dir := privateDir(t)
	req := Request{Directory: dir, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}
	if _, err := Update(req); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, acceptedFile), []byte(`{"schema":1,"release":"v9.9.9","release_sequence":9,"catalog_sequence":9,"manifest_sha256":"`+strings.Repeat("c", 64)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Update(req); err == nil {
		t.Fatal("sequence downgrade accepted")
	}
}

func TestUpdateRejectsCatalogSequenceDowngrade(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH})
	dir := privateDir(t)
	req := Request{Directory: dir, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}
	if _, err := Update(req); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, acceptedFile), []byte(`{"schema":1,"release":"v0.1.0","release_sequence":1,"catalog_sequence":9,"manifest_sha256":"`+strings.Repeat("c", 64)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Update(req); err == nil {
		t.Fatal("catalog sequence downgrade accepted")
	}
}

func TestUpdateRejectsPathTraversalAsset(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "..") {
			t.Fatal("bootstrap requested a parent path")
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(origin.Close)
	dir := privateDir(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if _, err := Update(Request{Directory: dir, Origin: origin.URL + "/../evil", Keys: map[string]ed25519.PublicKey{testKeyID: pub}, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}); err == nil {
		t.Fatal("origin with parent path accepted")
	}
}

func TestUpdateRejectsNonLocalHTTPOrigin(t *testing.T) {
	dir := privateDir(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if _, err := Update(Request{Directory: dir, Origin: "http://example.com/releases", Keys: map[string]ed25519.PublicKey{testKeyID: pub}, Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}); err == nil {
		t.Fatal("cleartext remote origin accepted")
	}
}

func TestUpdateSelectsOnlyRequestedPlatform(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: "linux", goarch: "amd64"})
	dir := privateDir(t)
	if _, err := Update(Request{Directory: dir, Origin: origin.URL, Keys: origin.Keys, GOOS: "windows", GOARCH: "amd64", Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}); err == nil {
		t.Fatal("missing platform artifacts accepted")
	}
}

func TestUpdateRejectsWritableAncestor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("writable-ancestor policy is Unix-specific")
	}
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH})
	parent := filepath.Join(t.TempDir(), "open")
	if err := os.Mkdir(parent, 0o777); err != nil { // #nosec G301 -- the regression creates a world-writable ancestor.
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o777); err != nil { // #nosec G302 -- the regression creates a world-writable ancestor.
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Update(Request{Directory: dir, Origin: origin.URL, Keys: origin.Keys, Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}); err == nil {
		t.Fatal("writable ancestor accepted")
	}
}

func TestStatusRejectsCorruptSlot(t *testing.T) {
	dir := privateDir(t)
	current := filepath.Join(dir, currentSlot)
	if err := os.Mkdir(current, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(current, slotRecord), []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Status(dir); err == nil {
		t.Fatal("corrupt slot accepted")
	}
}

func TestUpdateCreatesNestedDirectory(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH})
	dir := filepath.Join(t.TempDir(), "nested", "bootstrap")
	if _, err := Update(Request{Directory: dir, Origin: origin.URL, Keys: origin.Keys, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateRejectsRelativeDirectory(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH})
	if _, err := Update(Request{Directory: "relative-state", Origin: origin.URL, Keys: origin.Keys, Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)}); err == nil {
		t.Fatal("relative directory accepted")
	}
}

func TestSignedDocumentDigestMatchesCatalog(t *testing.T) {
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: "linux", goarch: "amd64"})
	sum := sha256.Sum256(origin.Files["v0.1.0/"+punarorelease.ReleaseManifestFile])
	catalog, err := punarorelease.ParseCatalog(origin.Files[punarorelease.CatalogReleaseName+"/"+punarorelease.CatalogFile])
	if err != nil {
		t.Fatal(err)
	}
	if !catalog.Allows("v0.1.0", 1, hex.EncodeToString(sum[:])) {
		t.Fatal("test catalog does not bind the assembled manifest")
	}
}

type originSpec struct {
	payload         string
	goos            string
	goarch          string
	release         string
	sequence        int64
	catalogSequence int64
	criticalBlocks  []int64
	expiresAt       time.Time
}

type signedOrigin struct {
	URL   string
	Keys  map[string]ed25519.PublicKey
	Files map[string][]byte
	priv  ed25519.PrivateKey
}

type recordingFetcher struct {
	files         map[string][]byte
	failPath      string
	waitForCancel bool
	calls         map[string]int
}

func (fetcher *recordingFetcher) Get(ctx context.Context, relative string, limit int64) ([]byte, error) {
	if fetcher.calls == nil {
		fetcher.calls = map[string]int{}
	}
	fetcher.calls[relative]++
	if fetcher.waitForCancel {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if relative == fetcher.failPath {
		return nil, &downloadFailure{category: downloadCategoryTransport, cause: errors.New("private transport detail")}
	}
	body, ok := fetcher.files[relative]
	if !ok {
		return nil, &downloadFailure{category: downloadCategoryHTTP, cause: errors.New("missing fixture")}
	}
	if int64(len(body)) > limit {
		return nil, &downloadFailure{category: downloadCategoryLength, cause: errors.New("fixture exceeds bound")}
	}
	return append([]byte(nil), body...), nil
}

func cloneFiles(source map[string][]byte) map[string][]byte {
	cloned := make(map[string][]byte, len(source))
	for name, body := range source {
		cloned[name] = append([]byte(nil), body...)
	}
	return cloned
}

func newSignedOrigin(t *testing.T, spec originSpec) *signedOrigin {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := files[strings.TrimPrefix(r.URL.Path, "/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	origin := &signedOrigin{
		URL:   server.URL,
		Keys:  map[string]ed25519.PublicKey{testKeyID: pub},
		Files: files,
		priv:  priv,
	}
	origin.republish(t, spec)
	return origin
}

func (origin *signedOrigin) republish(t *testing.T, spec originSpec) {
	t.Helper()
	if spec.release == "" {
		spec.release = "v0.1.0"
	}
	if spec.sequence == 0 {
		spec.sequence = 1
	}
	if spec.catalogSequence == 0 {
		spec.catalogSequence = 1
	}
	if spec.expiresAt.IsZero() {
		spec.expiresAt = time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	}
	build := t.TempDir()
	name := artifactName("punaro-adapter", spec.goos, spec.goarch)
	if err := os.WriteFile(filepath.Join(build, name), []byte(spec.payload), 0o600); err != nil {
		t.Fatal(err)
	}
	assembled, err := punarorelease.Assemble(punarorelease.AssembleRequest{
		Directory:               build,
		Release:                 spec.release,
		Sequence:                spec.sequence,
		PublishedAt:             time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC),
		ExpiresAt:               spec.expiresAt,
		MinimumSafeSequence:     1,
		CatalogSequence:         spec.catalogSequence,
		ComposeSHA256:           testCompose,
		MigrationManifestSHA256: testMigrate,
		Database:                punarorelease.SchemaRange{Min: 10, Max: 44, Target: 44, RollbackFloor: 10},
		PostgreSQLMajor:         18,
		GatewayProtocol:         punarorelease.ProtocolRange{Min: 1, Max: 1},
		ClientProtocol:          punarorelease.ProtocolRange{Min: 1, Max: 1},
		MinimumRecoveryProtocol: 1,
		MinimumBootstrapRelease: "v0.1.0",
		CriticalBlocks:          spec.criticalBlocks,
	})
	if err != nil {
		t.Fatal(err)
	}
	catalogSig, err := punarorelease.Sign(assembled.CatalogJSON, testKeyID, origin.priv)
	if err != nil {
		t.Fatal(err)
	}
	catalogSigJSON, err := punarorelease.EncodeEnvelope(catalogSig)
	if err != nil {
		t.Fatal(err)
	}
	manifestSig, err := punarorelease.Sign(assembled.ManifestJSON, testKeyID, origin.priv)
	if err != nil {
		t.Fatal(err)
	}
	manifestSigJSON, err := punarorelease.EncodeEnvelope(manifestSig)
	if err != nil {
		t.Fatal(err)
	}
	for key := range origin.Files {
		delete(origin.Files, key)
	}
	origin.Files[punarorelease.CatalogReleaseName+"/"+punarorelease.CatalogFile] = assembled.CatalogJSON
	origin.Files[punarorelease.CatalogReleaseName+"/"+punarorelease.CatalogSignatureFile] = catalogSigJSON
	origin.Files[spec.release+"/"+punarorelease.ReleaseManifestFile] = assembled.ManifestJSON
	origin.Files[spec.release+"/"+punarorelease.ReleaseSignatureFile] = manifestSigJSON
	origin.Files[spec.release+"/"+name] = []byte(spec.payload)
}
