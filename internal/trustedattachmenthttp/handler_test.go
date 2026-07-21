package trustedattachmenthttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rock3r/punaro/internal/ingress"
	"github.com/rock3r/punaro/internal/postgres"
	"github.com/rock3r/punaro/internal/trustedattachment"
	"github.com/rock3r/punaro/internal/trustedattachmentclient"
)

const (
	httpPrincipalID = "11111111-1111-4111-8111-111111111111"
	httpLookupID    = "22222222-2222-4222-8222-222222222222"
	httpProjectID   = "33333333-3333-4333-8333-333333333333"
	httpArtifactID  = "44444444-4444-4444-8444-444444444444"
	httpIdempotency = "55555555-5555-4555-8555-555555555555"
)

type fakeDatabase struct {
	device      postgres.AuthenticatedDevice
	authErr     error
	reservation postgres.AttachmentReservation
	request     postgres.AttachmentReservationRequest
}

func (database *fakeDatabase) AuthenticateDevice(context.Context, string) (postgres.AuthenticatedDevice, error) {
	return database.device, database.authErr
}

func (database *fakeDatabase) ReserveAttachment(_ context.Context, request postgres.AttachmentReservationRequest) (postgres.AttachmentReservation, error) {
	database.request = request
	return database.reservation, nil
}

type fakeLifecycle struct {
	uploadPrincipal  string
	uploadLookup     string
	uploadGeneration int64
	uploadArtifact   string
	uploadBody       []byte
	uploadLifetime   time.Duration
	downloadRequest  postgres.AttachmentDownloadRequest
	deleteRequest    postgres.AttachmentDeleteRequest
	metadata         postgres.AttachmentDownload
	uploadErr        error
}

func (lifecycle *fakeLifecycle) Upload(_ context.Context, device postgres.AuthenticatedDevice, artifactID string, lifetime time.Duration, source io.Reader) (postgres.AttachmentArtifact, error) {
	lifecycle.uploadPrincipal = device.PrincipalID
	lifecycle.uploadLookup = device.LookupID
	lifecycle.uploadGeneration = device.Generation
	lifecycle.uploadArtifact = artifactID
	lifecycle.uploadLifetime = lifetime
	lifecycle.uploadBody, _ = io.ReadAll(source)
	if lifecycle.uploadErr != nil {
		return postgres.AttachmentArtifact{}, lifecycle.uploadErr
	}
	return postgres.AttachmentArtifact{ArtifactID: artifactID, ProjectID: httpProjectID, StoragePath: "ready/" + artifactID + ".blob", SizeBytes: int64(len(lifecycle.uploadBody)), SHA256: sha256.Sum256(lifecycle.uploadBody), State: postgres.AttachmentReady, ReadyAt: time.Now().UTC()}, nil
}

func (lifecycle *fakeLifecycle) DownloadPrepared(_ context.Context, request postgres.AttachmentDownloadRequest, destination trustedattachment.DownloadWriter, prepare func(postgres.AttachmentDownload) error) (postgres.AttachmentDownload, error) {
	lifecycle.downloadRequest = request
	if err := prepare(lifecycle.metadata); err != nil {
		return postgres.AttachmentDownload{}, err
	}
	_, err := destination.Write([]byte("download body"))
	return lifecycle.metadata, err
}

func (lifecycle *fakeLifecycle) Delete(_ context.Context, request postgres.AttachmentDeleteRequest) (postgres.AttachmentDeletion, error) {
	lifecycle.deleteRequest = request
	return postgres.AttachmentDeletion{ArtifactID: request.ArtifactID, ProjectID: httpProjectID, StoragePath: "ready/" + request.ArtifactID + ".blob", State: postgres.AttachmentTombstoned}, nil
}

func newHTTPTestHandler(t *testing.T) (http.Handler, *fakeDatabase, *fakeLifecycle) {
	t.Helper()
	body := []byte("download body")
	digest := sha256.Sum256(body)
	database := &fakeDatabase{device: postgres.AuthenticatedDevice{PrincipalID: httpPrincipalID, LookupID: httpLookupID, Generation: 7}, reservation: postgres.AttachmentReservation{ArtifactID: httpArtifactID, ProjectID: httpProjectID, PrincipalID: httpPrincipalID, SizeBytes: int64(len(body)), SHA256: digest, DisplayName: "report.txt", MediaType: "text/plain", State: postgres.AttachmentReserved, ExpiresAt: time.Now().Add(time.Hour)}}
	lifecycle := &fakeLifecycle{metadata: postgres.AttachmentDownload{ArtifactID: httpArtifactID, ProjectID: httpProjectID, StoragePath: "ready/" + httpArtifactID + ".blob", SizeBytes: int64(len(body)), SHA256: digest, DisplayName: "report.txt", MediaType: "text/plain"}}
	policy := &ingress.Policy{Mode: ingress.LAN, ListenAddr: "127.0.0.1:8443", PublicURL: "https://punaro.test"}
	return New(database, lifecycle, policy), database, lifecycle
}

func authenticatedRequest(method, target string, body io.Reader) *http.Request {
	request := httptest.NewRequestWithContext(context.Background(), method, target, body)
	request.Header.Set("Authorization", "Bearer device-credential")
	request.Header.Set("X-Forwarded-Proto", "https")
	return request
}

func TestHandlerBindsReservationUploadDownloadAndDeleteToDevice(t *testing.T) {
	handler, database, lifecycle := newHTTPTestHandler(t)
	digest := sha256.Sum256([]byte("download body"))
	reservationBody := `{"project_id":"` + httpProjectID + `","idempotency_key":"` + httpIdempotency + `","size_bytes":13,"sha256":"` + hex.EncodeToString(digest[:]) + `","display_name":"report.txt","media_type":"text/plain","lifetime_seconds":3600}`
	request := authenticatedRequest(http.MethodPost, "https://punaro.test/v1/trusted-attachments", bytes.NewBufferString(reservationBody))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || database.request.PrincipalID != httpPrincipalID || database.request.CredentialLookupID != httpLookupID || database.request.CredentialGeneration != 7 || database.request.IdempotencyKey != httpIdempotency {
		t.Fatalf("reservation status=%d request=%#v body=%s", response.Code, database.request, response.Body.String())
	}

	request = authenticatedRequest(http.MethodPut, "https://punaro.test/v1/trusted-attachments/"+httpArtifactID+"/content", bytes.NewBufferString("download body"))
	request.Header.Set("Content-Type", "application/octet-stream")
	request.ContentLength = 13
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || lifecycle.uploadPrincipal != httpPrincipalID || lifecycle.uploadLookup != httpLookupID || lifecycle.uploadGeneration != 7 || lifecycle.uploadArtifact != httpArtifactID || lifecycle.uploadLifetime != 10*time.Minute || string(lifecycle.uploadBody) != "download body" {
		t.Fatalf("upload status=%d principal=%q artifact=%q body=%q response=%s", response.Code, lifecycle.uploadPrincipal, lifecycle.uploadArtifact, lifecycle.uploadBody, response.Body.String())
	}

	request = authenticatedRequest(http.MethodGet, "https://punaro.test/v1/trusted-attachments/"+httpArtifactID, nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "download body" || response.Header().Get("X-Punaro-SHA256") != hex.EncodeToString(digest[:]) || lifecycle.downloadRequest.CredentialGeneration != 7 {
		t.Fatalf("download status=%d headers=%v request=%#v body=%q", response.Code, response.Header(), lifecycle.downloadRequest, response.Body.String())
	}

	request = authenticatedRequest(http.MethodDelete, "https://punaro.test/v1/trusted-attachments/"+httpArtifactID, nil)
	request.Header.Set("Idempotency-Key", httpIdempotency)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || lifecycle.deleteRequest.PrincipalID != httpPrincipalID || lifecycle.deleteRequest.CredentialLookupID != httpLookupID || lifecycle.deleteRequest.IdempotencyKey != httpIdempotency {
		t.Fatalf("delete status=%d request=%#v body=%s", response.Code, lifecycle.deleteRequest, response.Body.String())
	}
}

func TestHandlerRejectsUnauthenticatedAndNonCanonicalRequests(t *testing.T) {
	handler, database, lifecycle := newHTTPTestHandler(t)
	cases := []*http.Request{
		httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://punaro.test/v1/trusted-attachments/"+httpArtifactID, nil),
		authenticatedRequest(http.MethodGet, "https://punaro.test/v1/trusted-attachments/not-an-id", nil),
		authenticatedRequest(http.MethodPut, "https://punaro.test/v1/trusted-attachments/"+httpArtifactID+"/content", bytes.NewBufferString("body")),
		authenticatedRequest(http.MethodDelete, "https://punaro.test/v1/trusted-attachments/"+httpArtifactID, nil),
	}
	for index, request := range cases {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code < 400 {
			t.Fatalf("case %d status=%d body=%s", index, response.Code, response.Body.String())
		}
	}
	if database.request.PrincipalID != "" || lifecycle.downloadRequest.ArtifactID != "" || lifecycle.deleteRequest.ArtifactID != "" {
		t.Fatalf("invalid requests reached authority: reserve=%#v download=%#v delete=%#v", database.request, lifecycle.downloadRequest, lifecycle.deleteRequest)
	}
}

type handlerTransport struct{ handler http.Handler }

func (transport handlerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	request.TLS = &tls.ConnectionState{}
	request.RemoteAddr = "127.0.0.1:12345"
	recorder := httptest.NewRecorder()
	transport.handler.ServeHTTP(recorder, request)
	return recorder.Result(), nil
}

func TestNativeClientAndHandlerShareOneStrictStreamingContract(t *testing.T) {
	handler, _, _ := newHTTPTestHandler(t)
	client, err := trustedattachmentclient.New("https://punaro.test", "device-credential", &http.Client{Transport: handlerTransport{handler: handler}})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	source := filepath.Join(root, "report.txt")
	if err := os.WriteFile(source, []byte("download body"), 0o600); err != nil {
		t.Fatal(err)
	}
	artifact, err := client.Send(context.Background(), trustedattachmentclient.SendRequest{ProjectID: httpProjectID, IdempotencyKey: httpIdempotency, Path: source, DisplayName: "report.txt", MediaType: "text/plain"})
	if err != nil || artifact.ArtifactID != httpArtifactID || artifact.State != "ready" {
		t.Fatalf("artifact=%#v err=%v", artifact, err)
	}
	downloadRoot := filepath.Join(root, "downloads")
	if err := os.Mkdir(downloadRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	name, err := client.Receive(context.Background(), httpArtifactID, downloadRoot)
	if err != nil || name != "report.txt" {
		t.Fatalf("name=%q err=%v", name, err)
	}
	// #nosec G304 -- name is the native receiver's validated basename inside t.TempDir.
	body, err := os.ReadFile(filepath.Join(downloadRoot, name))
	if err != nil || string(body) != "download body" {
		t.Fatalf("body=%q err=%v", body, err)
	}
}

func TestHandlerRejectsDuplicateUnknownAndRevokedUploadBeforePublication(t *testing.T) {
	handler, database, lifecycle := newHTTPTestHandler(t)
	digest := sha256.Sum256([]byte("download body"))
	base := `"idempotency_key":"` + httpIdempotency + `","size_bytes":13,"sha256":"` + hex.EncodeToString(digest[:]) + `","display_name":"report.txt","media_type":"text/plain","lifetime_seconds":3600`
	for _, body := range []string{
		`{"project_id":"` + httpProjectID + `","project_id":"` + httpProjectID + `",` + base + `}`,
		`{"project_id":"` + httpProjectID + `",` + base + `,"unexpected":true}`,
		`{"project_id":"not-a-uuid",` + base + `}`,
		`{"project_id":"` + httpProjectID + `","idempotency_key":"` + httpIdempotency + `","size_bytes":13,"sha256":"` + hex.EncodeToString(digest[:]) + `","display_name":"report.txt","media_type":"text/plain; charset=utf-8","lifetime_seconds":3600}`,
		`{"project_id":"` + httpProjectID + `","idempotency_key":"` + httpIdempotency + `","size_bytes":13,"sha256":"` + hex.EncodeToString(digest[:]) + `","display_name":"report.txt","media_type":"text/plain","lifetime_seconds":0}`,
		`{"project_id":"` + httpProjectID + `","idempotency_key":"` + httpIdempotency + `","size_bytes":13,"sha256":"` + hex.EncodeToString(digest[:]) + `","display_name":"report.txt","media_type":"text/plain","lifetime_seconds":36028797018967568}`,
	} {
		request := authenticatedRequest(http.MethodPost, "https://punaro.test/v1/trusted-attachments", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("body=%s status=%d response=%s", body, response.Code, response.Body.String())
		}
	}
	if database.request.PrincipalID != "" {
		t.Fatalf("invalid reservation reached database: %#v", database.request)
	}
	lifecycle.uploadErr = postgres.ErrForbidden
	request := authenticatedRequest(http.MethodPut, "https://punaro.test/v1/trusted-attachments/"+httpArtifactID+"/content", strings.NewReader("download body"))
	request.Header.Set("Content-Type", "application/octet-stream")
	request.ContentLength = 13
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || lifecycle.uploadArtifact != httpArtifactID {
		t.Fatalf("revoked upload status=%d artifact=%q body=%s", response.Code, lifecycle.uploadArtifact, response.Body.String())
	}
	database.authErr = postgres.ErrUnauthenticated
	lifecycle.downloadRequest = postgres.AttachmentDownloadRequest{}
	request = authenticatedRequest(http.MethodGet, "https://punaro.test/v1/trusted-attachments/"+httpArtifactID, nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || lifecycle.downloadRequest.ArtifactID != "" {
		t.Fatalf("revoked credential status=%d request=%#v", response.Code, lifecycle.downloadRequest)
	}
}

type blockingLifecycle struct {
	entered chan struct{}
	release chan struct{}
}

func (*blockingLifecycle) Upload(context.Context, postgres.AuthenticatedDevice, string, time.Duration, io.Reader) (postgres.AttachmentArtifact, error) {
	return postgres.AttachmentArtifact{}, errors.New("unused")
}

func (lifecycle *blockingLifecycle) DownloadPrepared(ctx context.Context, _ postgres.AttachmentDownloadRequest, _ trustedattachment.DownloadWriter, _ func(postgres.AttachmentDownload) error) (postgres.AttachmentDownload, error) {
	lifecycle.entered <- struct{}{}
	select {
	case <-lifecycle.release:
		return postgres.AttachmentDownload{}, context.Canceled
	case <-ctx.Done():
		return postgres.AttachmentDownload{}, ctx.Err()
	}
}

func (*blockingLifecycle) Delete(context.Context, postgres.AttachmentDeleteRequest) (postgres.AttachmentDeletion, error) {
	return postgres.AttachmentDeletion{}, errors.New("unused")
}

func TestHandlerBoundsConcurrentStreamsWithoutConsumingMailCapacity(t *testing.T) {
	database := &fakeDatabase{device: postgres.AuthenticatedDevice{PrincipalID: httpPrincipalID, LookupID: httpLookupID, Generation: 1}}
	lifecycle := &blockingLifecycle{entered: make(chan struct{}, maxConcurrentRequests), release: make(chan struct{})}
	policy := &ingress.Policy{Mode: ingress.LAN, ListenAddr: "127.0.0.1:8443", PublicURL: "https://punaro.test"}
	handler := New(database, lifecycle, policy)
	var wait sync.WaitGroup
	for range maxConcurrentRequests {
		wait.Add(1)
		go func() {
			defer wait.Done()
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, authenticatedRequest(http.MethodGet, "https://punaro.test/v1/trusted-attachments/"+httpArtifactID, nil))
		}()
	}
	for range maxConcurrentRequests {
		select {
		case <-lifecycle.entered:
		case <-time.After(time.Second):
			t.Fatal("stream did not enter bounded handler")
		}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, authenticatedRequest(http.MethodGet, "https://punaro.test/v1/trusted-attachments/"+httpArtifactID, nil))
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("overflow status=%d body=%s", response.Code, response.Body.String())
	}
	close(lifecycle.release)
	wait.Wait()
}
