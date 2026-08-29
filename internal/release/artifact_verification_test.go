package release

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyArtifactDirectoryRequiresEveryExactRegularArtifact(t *testing.T) {
	directory := t.TempDir()
	body := []byte("verified artifact")
	digest := sha256.Sum256(body)
	manifest := ReleaseManifest{
		Release: "v0.1.0-alpha.1",
		Artifacts: []Artifact{{
			Component: "punaro-adapter", OS: "linux", Arch: "amd64",
			Path: "v0.1.0-alpha.1/punaro-adapter-linux-amd64", Length: int64(len(body)), Mode: 0o755, SHA256: hex.EncodeToString(digest[:]),
		}},
	}
	artifact := filepath.Join(directory, "punaro-adapter-linux-amd64")
	if err := os.WriteFile(artifact, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifactDirectory(directory, manifest); err != nil {
		t.Fatalf("exact artifact rejected: %v", err)
	}
	if err := os.WriteFile(artifact, []byte("tampered artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifactDirectory(directory, manifest); err == nil {
		t.Fatal("tampered artifact accepted")
	}
	if err := os.Remove(artifact); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifactDirectory(directory, manifest); err == nil {
		t.Fatal("missing artifact accepted")
	}
}
