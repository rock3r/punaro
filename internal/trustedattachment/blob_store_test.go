package trustedattachment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testArtifactID = "019f8031-1a62-7abc-9def-0123456789ab"

func TestBlobStorePublishesExactOpaqueBlob(t *testing.T) {
	root := privateBlobRoot(t)
	store, err := OpenBlobStore(root)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("trusted attachment body")
	digest := sha256.Sum256(body)
	claim := UploadClaim{ArtifactID: testArtifactID, AttemptGeneration: 3, SizeBytes: int64(len(body)), SHA256: digest}

	published, err := store.Publish(context.Background(), claim, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if published.StoragePath != "ready/"+testArtifactID+".blob" || published.SizeBytes != int64(len(body)) || published.SHA256 != digest {
		t.Fatalf("published=%#v", published)
	}
	if strings.Contains(published.StoragePath, "trusted attachment body") || filepath.IsAbs(published.StoragePath) {
		t.Fatalf("unsafe storage path %q", published.StoragePath)
	}
	info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(published.StoragePath)))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("info=%#v err=%v", info, err)
	}
	if err := store.Verify(published); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestBlobStoreRejectsStreamBoundaryFailuresWithoutFinalBlob(t *testing.T) {
	body := []byte("expected body")
	digest := sha256.Sum256(body)
	tests := []struct {
		name   string
		claim  UploadClaim
		input  []byte
		cancel bool
	}{
		{name: "short", claim: UploadClaim{ArtifactID: testArtifactID, AttemptGeneration: 1, SizeBytes: int64(len(body)), SHA256: digest}, input: body[:len(body)-1]},
		{name: "long", claim: UploadClaim{ArtifactID: testArtifactID, AttemptGeneration: 1, SizeBytes: int64(len(body)), SHA256: digest}, input: append(append([]byte(nil), body...), 'x')},
		{name: "digest", claim: UploadClaim{ArtifactID: testArtifactID, AttemptGeneration: 1, SizeBytes: int64(len(body)), SHA256: sha256.Sum256([]byte("different"))}, input: body},
		{name: "cancelled", claim: UploadClaim{ArtifactID: testArtifactID, AttemptGeneration: 1, SizeBytes: int64(len(body)), SHA256: digest}, input: body, cancel: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := privateBlobRoot(t)
			store, err := OpenBlobStore(root)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if test.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := store.Publish(ctx, test.claim, bytes.NewReader(test.input)); err == nil {
				t.Fatal("invalid stream published")
			}
			if _, err := os.Lstat(filepath.Join(root, "ready", testArtifactID+".blob")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("final blob exists: %v", err)
			}
		})
	}
}

func TestBlobStoreNeverOverwritesExistingFinal(t *testing.T) {
	root := privateBlobRoot(t)
	store, err := OpenBlobStore(root)
	if err != nil {
		t.Fatal(err)
	}
	original := []byte("original")
	originalDigest := sha256.Sum256(original)
	claim := UploadClaim{ArtifactID: testArtifactID, AttemptGeneration: 1, SizeBytes: int64(len(original)), SHA256: originalDigest}
	published, err := store.Publish(context.Background(), claim, bytes.NewReader(original))
	if err != nil {
		t.Fatal(err)
	}
	if retried, err := store.Publish(context.Background(), UploadClaim{ArtifactID: testArtifactID, AttemptGeneration: 2, SizeBytes: int64(len(original)), SHA256: originalDigest}, bytes.NewReader(original)); err != nil || retried != published {
		t.Fatalf("exact retry=%#v err=%v", retried, err)
	}
	changed := []byte("changed!")
	if _, err := store.Publish(context.Background(), UploadClaim{ArtifactID: testArtifactID, AttemptGeneration: 3, SizeBytes: int64(len(changed)), SHA256: sha256.Sum256(changed)}, bytes.NewReader(changed)); err == nil {
		t.Fatal("changed bytes replaced immutable final")
	}
	actual, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(published.StoragePath))) // #nosec G304 -- published path is server-derived and asserted above.
	if err != nil || !bytes.Equal(actual, original) {
		t.Fatalf("actual=%q err=%v", actual, err)
	}
}

func TestBlobStoreRejectsUnsafeRootAndArtifactID(t *testing.T) {
	unsafeRoot := t.TempDir()
	if err := os.Chmod(unsafeRoot, 0o755); err != nil { // #nosec G302 -- the test intentionally creates an unsafe root.
		t.Fatal(err)
	}
	if _, err := OpenBlobStore(unsafeRoot); err == nil {
		t.Fatal("world-readable root accepted")
	}
	root := privateBlobRoot(t)
	store, err := OpenBlobStore(root)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("body")
	if _, err := store.Publish(context.Background(), UploadClaim{ArtifactID: "../../escape", AttemptGeneration: 1, SizeBytes: int64(len(body)), SHA256: sha256.Sum256(body)}, bytes.NewReader(body)); err == nil {
		t.Fatal("path-shaped artifact ID accepted")
	}
}

func TestBlobStoreRetryKeepsClaimStagesIsolatedAndAdoptsExactFinal(t *testing.T) {
	root := privateBlobRoot(t)
	store, err := OpenBlobStore(root)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("durable final")
	digest := sha256.Sum256(body)
	claim := UploadClaim{ArtifactID: testArtifactID, AttemptGeneration: 1, SizeBytes: int64(len(body)), SHA256: digest}
	published, err := store.Publish(context.Background(), claim, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	stageDir := filepath.Join(root, "staging", testArtifactID)
	if err := os.Mkdir(stageDir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
	stage := filepath.Join(stageDir, "1.part")
	if err := os.WriteFile(stage, []byte("crash residue"), 0o600); err != nil {
		t.Fatal(err)
	}
	if retried, err := store.Publish(context.Background(), UploadClaim{ArtifactID: testArtifactID, AttemptGeneration: 2, SizeBytes: int64(len(body)), SHA256: digest}, bytes.NewReader(nil)); err != nil || retried != published {
		t.Fatalf("retried=%#v err=%v", retried, err)
	}
	if _, err := os.Lstat(stage); err != nil {
		t.Fatalf("retry disturbed prior claim stage: %v", err)
	}
	if err := store.RemoveStages(testArtifactID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stageDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fenced stage namespace remains: %v", err)
	}
}

func TestBlobStoreRemoveUnpublishedRetiresBothNamespaces(t *testing.T) {
	root := privateBlobRoot(t)
	store, err := OpenBlobStore(root)
	if err != nil {
		t.Fatal(err)
	}
	stageDir := filepath.Join(root, "staging", testArtifactID)
	if err := os.Mkdir(stageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string]string{
		filepath.Join(stageDir, "7.part"):                    "partial",
		filepath.Join(root, "ready", testArtifactID+".blob"): "hidden final",
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.RemoveUnpublished(testArtifactID); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{stageDir, filepath.Join(root, "ready", testArtifactID+".blob")} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("path remains %s: %v", path, err)
		}
	}
}

func TestBlobStoreVerifyRequiresArtifactDerivedReadyPath(t *testing.T) {
	root := privateBlobRoot(t)
	store, err := OpenBlobStore(root)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("body")
	if err := os.WriteFile(filepath.Join(root, "ready", "not-an-artifact.blob"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Verify(PublishedBlob{StoragePath: "ready/not-an-artifact.blob", SizeBytes: int64(len(body)), SHA256: sha256.Sum256(body)}); err == nil {
		t.Fatal("non-artifact READY path accepted")
	}
}

func TestBlobStoreOverlappingStaleAndFreshClaimsCannotTouchEachOthersStages(t *testing.T) {
	root := privateBlobRoot(t)
	store, err := OpenBlobStore(root)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("same immutable reservation body")
	digest := sha256.Sum256(body)
	started := make(chan struct{})
	release := make(chan struct{})
	staleResult := make(chan error, 1)
	go func() {
		_, publishErr := store.Publish(context.Background(), UploadClaim{ArtifactID: testArtifactID, AttemptGeneration: 1, SizeBytes: int64(len(body)), SHA256: digest}, &gatedReader{body: body, started: started, release: release})
		staleResult <- publishErr
	}()
	<-started
	if _, err := store.Publish(context.Background(), UploadClaim{ArtifactID: testArtifactID, AttemptGeneration: 2, SizeBytes: int64(len(body)), SHA256: digest}, bytes.NewReader(body)); err != nil {
		t.Fatalf("fresh claim: %v", err)
	}
	close(release)
	if err := <-staleResult; err != nil {
		t.Fatalf("stale claim exact adoption: %v", err)
	}
	published := PublishedBlob{StoragePath: "ready/" + testArtifactID + ".blob", SizeBytes: int64(len(body)), SHA256: digest}
	if err := store.Verify(published); err != nil {
		t.Fatalf("overlap changed immutable final: %v", err)
	}
}

type gatedReader struct {
	body    []byte
	started chan struct{}
	release chan struct{}
	done    bool
}

func (reader *gatedReader) Read(destination []byte) (int, error) {
	if reader.done {
		return 0, io.EOF
	}
	close(reader.started)
	<-reader.release
	reader.done = true
	return copy(destination, reader.body), nil
}

func privateBlobRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "blobs")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}
