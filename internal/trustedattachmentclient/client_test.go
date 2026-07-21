package trustedattachmentclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	httpProjectID   = "33333333-3333-4333-8333-333333333333"
	httpArtifactID  = "44444444-4444-4444-8444-444444444444"
	httpIdempotency = "55555555-5555-4555-8555-555555555555"
	httpExpiresAt   = "2026-07-21T18:00:00Z"
	httpReadyAt     = "2026-07-21T17:00:00Z"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func httpResponse(status int, body string, headers http.Header) *http.Response {
	if headers == nil {
		headers = make(http.Header)
	}
	if headers.Get("Content-Type") == "" {
		headers.Set("Content-Type", "application/json")
	}
	return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(body)), ContentLength: -1}
}

func TestClientDisablesEnvironmentProxyForCredentialTraffic(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:65535")
	for _, provided := range []*http.Client{nil, {}} {
		client, err := New("http://127.0.0.1:8080", "credential", provided)
		if err != nil {
			t.Fatal(err)
		}
		transport, ok := client.http.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("transport=%T", client.http.Transport)
		}
		if transport.Proxy != nil {
			t.Fatal("default client retained environment proxying")
		}
	}
	proxying := http.DefaultTransport.(*http.Transport).Clone()
	proxying.Proxy = http.ProxyFromEnvironment
	client, err := New("http://127.0.0.1:8080", "credential", &http.Client{Transport: proxying})
	if err != nil {
		t.Fatal(err)
	}
	if transport := client.http.Transport.(*http.Transport); transport.Proxy != nil {
		t.Fatal("provided standard transport retained environment proxying")
	}
}

func TestClientReservesThenStreamsExactFile(t *testing.T) {
	body := []byte("native sender body")
	file := filepath.Join(t.TempDir(), "report.txt")
	if err := os.WriteFile(file, body, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	requests := 0
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.Header.Get("Authorization") != "Bearer credential" {
			t.Fatalf("authorization=%q", request.Header.Get("Authorization"))
		}
		switch requests {
		case 1:
			if request.Method != http.MethodPost || request.URL.Path != "/v1/trusted-attachments" {
				t.Fatalf("reserve request=%s %s", request.Method, request.URL)
			}
			encoded, _ := io.ReadAll(request.Body)
			if !bytes.Contains(encoded, []byte(hex.EncodeToString(digest[:]))) || !bytes.Contains(encoded, []byte(httpIdempotency)) {
				t.Fatalf("reservation body=%s", encoded)
			}
			return httpResponse(http.StatusCreated, `{"artifact_id":"`+httpArtifactID+`","project_id":"`+httpProjectID+`","size_bytes":18,"sha256":"`+hex.EncodeToString(digest[:])+`","display_name":"report.txt","media_type":"text/plain","state":"reserved","expires_at":"`+httpExpiresAt+`"}`, nil), nil
		case 2:
			if request.Method != http.MethodPut || request.URL.Path != "/v1/trusted-attachments/"+httpArtifactID+"/content" || request.ContentLength != int64(len(body)) {
				t.Fatalf("upload request=%s %s length=%d", request.Method, request.URL, request.ContentLength)
			}
			got, _ := io.ReadAll(request.Body)
			if !bytes.Equal(got, body) {
				t.Fatalf("upload body=%q", got)
			}
			return httpResponse(http.StatusOK, `{"artifact_id":"`+httpArtifactID+`","project_id":"`+httpProjectID+`","size_bytes":18,"sha256":"`+hex.EncodeToString(digest[:])+`","state":"ready","ready_at":"`+httpReadyAt+`"}`, nil), nil
		default:
			t.Fatalf("unexpected request %d", requests)
			return nil, nil
		}
	})
	client, err := New("https://punaro.test", "credential", &http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := client.Send(context.Background(), SendRequest{ProjectID: httpProjectID, IdempotencyKey: httpIdempotency, Path: file, DisplayName: "report.txt", MediaType: "text/plain"})
	if err != nil || artifact.ArtifactID != httpArtifactID || artifact.SHA256 != digest || requests != 2 {
		t.Fatalf("artifact=%#v requests=%d err=%v", artifact, requests, err)
	}
}

func TestClientReadyReservationClosesResponseLossWithoutReupload(t *testing.T) {
	body := []byte("already uploaded")
	file := filepath.Join(t.TempDir(), "report.txt")
	if err := os.WriteFile(file, body, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	requests := 0
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return httpResponse(http.StatusCreated, `{"artifact_id":"`+httpArtifactID+`","project_id":"`+httpProjectID+`","size_bytes":16,"sha256":"`+hex.EncodeToString(digest[:])+`","display_name":"report.txt","media_type":"text/plain","state":"ready","expires_at":"`+httpExpiresAt+`"}`, nil), nil
	})
	client, _ := New("https://punaro.test", "credential", &http.Client{Transport: transport})
	artifact, err := client.Send(context.Background(), SendRequest{ProjectID: httpProjectID, IdempotencyKey: httpIdempotency, Path: file, DisplayName: "report.txt", MediaType: "text/plain"})
	if err != nil || artifact.State != "ready" || requests != 1 {
		t.Fatalf("artifact=%#v requests=%d err=%v", artifact, requests, err)
	}
}

func TestClientReceivesAuthenticatedMetadataIntoSafeRoot(t *testing.T) {
	body := []byte("downloaded")
	digest := sha256.Sum256(body)
	headers := http.Header{"Content-Type": []string{"text/plain"}, "Content-Length": []string{"10"}, "X-Punaro-Artifact-Id": []string{httpArtifactID}, "X-Punaro-Sha256": []string{hex.EncodeToString(digest[:])}, "X-Punaro-Display-Name": []string{"cmVwb3J0LnR4dA"}}
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.Path != "/v1/trusted-attachments/"+httpArtifactID {
			t.Fatalf("download request=%s %s", request.Method, request.URL)
		}
		return httpResponse(http.StatusOK, string(body), headers), nil
	})
	client, _ := New("https://punaro.test", "credential", &http.Client{Transport: transport})
	root := t.TempDir()
	name, err := client.Receive(context.Background(), httpArtifactID, root)
	if err != nil || name != "report.txt" {
		t.Fatalf("name=%q err=%v", name, err)
	}
	// #nosec G304 -- name is the client's validated basename inside t.TempDir.
	got, _ := os.ReadFile(filepath.Join(root, name))
	if !bytes.Equal(got, body) {
		t.Fatalf("body=%q", got)
	}
}

func TestClientRejectsRedirectsAndMalformedIntegrityMetadata(t *testing.T) {
	redirectTransport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return httpResponse(http.StatusTemporaryRedirect, "", http.Header{"Location": []string{"https://attacker.test/file"}}), nil
	})
	client, _ := New("https://punaro.test", "credential", &http.Client{Transport: redirectTransport})
	if _, err := client.Receive(context.Background(), httpArtifactID, t.TempDir()); err == nil {
		t.Fatal("redirect was accepted")
	}
	malformedTransport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return httpResponse(http.StatusOK, "body", http.Header{"Content-Type": []string{"text/plain"}, "Content-Length": []string{"4"}, "X-Punaro-Artifact-Id": []string{httpArtifactID}, "X-Punaro-Sha256": []string{"bad"}, "X-Punaro-Display-Name": []string{"cmVwb3J0LnR4dA"}}), nil
	})
	client, _ = New("https://punaro.test", "credential", &http.Client{Transport: malformedTransport})
	if _, err := client.Receive(context.Background(), httpArtifactID, t.TempDir()); err == nil {
		t.Fatal("malformed digest was accepted")
	}
}

func TestClientBoundsConcurrentReceivesAcrossReceiverInstances(t *testing.T) {
	body := []byte("bounded")
	digest := sha256.Sum256(body)
	entered := make(chan struct{}, maxConcurrentReceivers+1)
	release := make(chan struct{})
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		entered <- struct{}{}
		<-release
		headers := http.Header{"Content-Type": []string{"text/plain"}, "Content-Length": []string{"7"}, "X-Punaro-Artifact-Id": []string{httpArtifactID}, "X-Punaro-Sha256": []string{hex.EncodeToString(digest[:])}, "X-Punaro-Display-Name": []string{"cmVwb3J0LnR4dA"}}
		return httpResponse(http.StatusOK, string(body), headers), nil
	})
	client, _ := New("https://punaro.test", "credential", &http.Client{Transport: transport})
	var wait sync.WaitGroup
	errorsSeen := make(chan error, maxConcurrentReceivers+1)
	for range maxConcurrentReceivers + 1 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := client.Receive(context.Background(), httpArtifactID, t.TempDir())
			errorsSeen <- err
		}()
	}
	for range maxConcurrentReceivers {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("receive did not enter transport")
		}
	}
	select {
	case <-entered:
		t.Fatal("client admitted more than the receive bound")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestClientDeletesWithOperationBoundIdempotency(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodDelete || request.URL.Path != "/v1/trusted-attachments/"+httpArtifactID || request.Header.Get("Idempotency-Key") != httpIdempotency || request.ContentLength != 0 {
			t.Fatalf("delete request=%s %s idempotency=%q length=%d", request.Method, request.URL, request.Header.Get("Idempotency-Key"), request.ContentLength)
		}
		return httpResponse(http.StatusOK, `{"artifact_id":"`+httpArtifactID+`","project_id":"`+httpProjectID+`","state":"tombstoned"}`, nil), nil
	})
	client, _ := New("https://punaro.test", "credential", &http.Client{Transport: transport})
	deletion, err := client.Delete(context.Background(), httpArtifactID, httpIdempotency)
	if err != nil || deletion.ArtifactID != httpArtifactID || deletion.ProjectID != httpProjectID || deletion.State != "tombstoned" {
		t.Fatalf("deletion=%#v err=%v", deletion, err)
	}
}

func TestClientDistinguishesRetryableAndTerminalResponses(t *testing.T) {
	statuses := []struct {
		status    int
		retryable bool
	}{{http.StatusServiceUnavailable, true}, {http.StatusLocked, true}, {http.StatusConflict, false}, {http.StatusUnauthorized, false}}
	for _, test := range statuses {
		transport := roundTripFunc(func(*http.Request) (*http.Response, error) { return httpResponse(test.status, `{}`, nil), nil })
		client, _ := New("https://punaro.test", "credential", &http.Client{Transport: transport})
		_, err := client.Delete(context.Background(), httpArtifactID, httpIdempotency)
		var requestErr *RequestError
		if !errors.As(err, &requestErr) || requestErr.StatusCode != test.status || requestErr.Retryable != test.retryable {
			t.Fatalf("status=%d error=%#v", test.status, err)
		}
	}
}

func TestClientClosesUploadAndDeleteResponseLossWithSameOperation(t *testing.T) {
	body := []byte("response loss")
	digest := sha256.Sum256(body)
	file := filepath.Join(t.TempDir(), "report.txt")
	if err := os.WriteFile(file, body, 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		switch calls {
		case 1:
			return httpResponse(http.StatusCreated, `{"artifact_id":"`+httpArtifactID+`","project_id":"`+httpProjectID+`","size_bytes":13,"sha256":"`+hex.EncodeToString(digest[:])+`","display_name":"report.txt","media_type":"text/plain","state":"reserved","expires_at":"`+httpExpiresAt+`"}`, nil), nil
		case 2:
			return nil, errors.New("response lost after upload commit")
		case 3:
			return httpResponse(http.StatusCreated, `{"artifact_id":"`+httpArtifactID+`","project_id":"`+httpProjectID+`","size_bytes":13,"sha256":"`+hex.EncodeToString(digest[:])+`","display_name":"report.txt","media_type":"text/plain","state":"ready","expires_at":"`+httpExpiresAt+`"}`, nil), nil
		case 4:
			return nil, errors.New("response lost after delete commit")
		case 5:
			return httpResponse(http.StatusOK, `{"artifact_id":"`+httpArtifactID+`","project_id":"`+httpProjectID+`","state":"tombstoned"}`, nil), nil
		default:
			t.Fatalf("unexpected request %d: %s", calls, request.Method)
			return nil, nil
		}
	})
	client, _ := New("https://punaro.test", "credential", &http.Client{Transport: transport})
	request := SendRequest{ProjectID: httpProjectID, IdempotencyKey: httpIdempotency, Path: file, DisplayName: "report.txt", MediaType: "text/plain"}
	if _, err := client.Send(context.Background(), request); err == nil {
		t.Fatal("lost upload response was reported as success")
	}
	if artifact, err := client.Send(context.Background(), request); err != nil || artifact.State != "ready" || calls != 3 {
		t.Fatalf("upload recovery artifact=%#v calls=%d err=%v", artifact, calls, err)
	}
	if _, err := client.Delete(context.Background(), httpArtifactID, httpIdempotency); err == nil {
		t.Fatal("lost delete response was reported as success")
	}
	if deletion, err := client.Delete(context.Background(), httpArtifactID, httpIdempotency); err != nil || deletion.State != "tombstoned" || calls != 5 {
		t.Fatalf("delete recovery=%#v calls=%d err=%v", deletion, calls, err)
	}
}
