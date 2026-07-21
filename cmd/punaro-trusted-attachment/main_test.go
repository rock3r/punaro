package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rock3r/punaro/internal/trustedattachmentclient"
)

const (
	cliProjectID   = "11111111-1111-4111-8111-111111111111"
	cliArtifactID  = "22222222-2222-4222-8222-222222222222"
	cliIdempotency = "33333333-3333-4333-8333-333333333333"
)

type fakeClient struct {
	sendRequest trustedattachmentclient.SendRequest
	receiveID   string
	receiveRoot string
	deleteID    string
	deleteKey   string
}

func (client *fakeClient) Send(_ context.Context, request trustedattachmentclient.SendRequest) (trustedattachmentclient.Artifact, error) {
	client.sendRequest = request
	return trustedattachmentclient.Artifact{ArtifactID: cliArtifactID, ProjectID: cliProjectID, SizeBytes: 4, SHA256: sha256.Sum256([]byte("body")), State: "ready"}, nil
}

func (client *fakeClient) Receive(_ context.Context, artifactID, root string) (string, error) {
	client.receiveID, client.receiveRoot = artifactID, root
	return "report.txt", nil
}

func (client *fakeClient) Delete(_ context.Context, artifactID, key string) (trustedattachmentclient.Deletion, error) {
	client.deleteID, client.deleteKey = artifactID, key
	return trustedattachmentclient.Deletion{ArtifactID: artifactID, ProjectID: cliProjectID, State: "tombstoned"}, nil
}

func TestRunUsesProtectedCredentialFileWithoutEchoingIt(t *testing.T) {
	original := newClient
	t.Cleanup(func() { newClient = original })
	fake := &fakeClient{}
	newClient = func(origin, credential string) (attachmentClient, error) {
		if origin != "https://punaro.test" || credential != "secret-credential" {
			t.Fatalf("origin=%q credential=%q", origin, credential)
		}
		return fake, nil
	}
	root := t.TempDir()
	credential := filepath.Join(root, "credential")
	if err := os.WriteFile(credential, []byte("secret-credential\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "source.txt")
	if err := os.WriteFile(source, []byte("body"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"send", "--origin", "https://punaro.test", "--credential-file", credential, "--project", cliProjectID, "--idempotency-key", cliIdempotency, "--file", source, "--name", "report.txt", "--media-type", "text/plain"}, &stdout, &stderr)
	if code != 0 || fake.sendRequest.Path != source || fake.sendRequest.ProjectID != cliProjectID || !strings.Contains(stdout.String(), cliArtifactID) || strings.Contains(stdout.String()+stderr.String(), "secret-credential") {
		t.Fatalf("code=%d request=%#v stdout=%q stderr=%q", code, fake.sendRequest, stdout.String(), stderr.String())
	}
}

func TestRunReceiveAndDeleteUseExplicitStableInputs(t *testing.T) {
	original := newClient
	t.Cleanup(func() { newClient = original })
	fake := &fakeClient{}
	newClient = func(string, string) (attachmentClient, error) { return fake, nil }
	root := t.TempDir()
	credential := filepath.Join(root, "credential")
	if err := os.WriteFile(credential, []byte("secret-credential"), 0o600); err != nil {
		t.Fatal(err)
	}
	downloads := filepath.Join(root, "downloads")
	if err := os.Mkdir(downloads, 0o700); err != nil {
		t.Fatal(err)
	}
	common := []string{"--origin", "https://punaro.test", "--credential-file", credential}
	var stdout, stderr bytes.Buffer
	args := append([]string{"receive"}, common...)
	args = append(args, "--artifact", cliArtifactID, "--download-root", downloads)
	if code := run(args, &stdout, &stderr); code != 0 || fake.receiveID != cliArtifactID || fake.receiveRoot != downloads || !strings.Contains(stdout.String(), "report.txt") {
		t.Fatalf("receive code=%d id=%q root=%q stdout=%q stderr=%q", code, fake.receiveID, fake.receiveRoot, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	args = append([]string{"delete"}, common...)
	args = append(args, "--artifact", cliArtifactID, "--idempotency-key", cliIdempotency)
	if code := run(args, &stdout, &stderr); code != 0 || fake.deleteID != cliArtifactID || fake.deleteKey != cliIdempotency || !strings.Contains(stdout.String(), "tombstoned") {
		t.Fatalf("delete code=%d id=%q key=%q stdout=%q stderr=%q", code, fake.deleteID, fake.deleteKey, stdout.String(), stderr.String())
	}
}
