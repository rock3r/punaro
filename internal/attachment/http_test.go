package attachment

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestHTTPCreateOfferUsesAuthenticatedPrincipal(t *testing.T) {
	service := NewService(PolicyFunc(func(sender, conversation, recipient string, action Action) bool {
		return sender == "sender" && conversation == "conversation" && recipient == "recipient" && action == ActionCreate
	}))
	handler := NewHTTP(service, AuthFunc(func(context.Context, *http.Request) (Principal, error) {
		return Principal{DeviceID: "sender"}, nil
	}))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/conversations/conversation/attachments", bytes.NewBufferString(validAttachmentCreateBody()))
	req.Header.Set("Idempotency-Key", "create-authenticated")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}
}

func TestHTTPCreateOfferDeduplicatesIdempotencyKey(t *testing.T) {
	service := NewService(PolicyFunc(func(_, _, _ string, _ Action) bool { return true }))
	handler := NewHTTP(service, AuthFunc(func(context.Context, *http.Request) (Principal, error) {
		return Principal{DeviceID: "sender"}, nil
	}))
	create := func() string {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/conversations/conversation/attachments", bytes.NewBufferString(validAttachmentCreateBody()))
		req.Header.Set("Idempotency-Key", "same-request")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusCreated {
			t.Fatalf("create status = %d", res.Code)
		}
		var body struct {
			OfferID string `json:"offer_id"`
		}
		if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body.OfferID
	}
	if first, second := create(), create(); first != second {
		t.Fatalf("idempotent offer IDs = %q, %q", first, second)
	}
}

func TestHTTPCreateOfferRejectsUnknownControlFields(t *testing.T) {
	service := NewService(PolicyFunc(func(_, _, _ string, _ Action) bool { return true }))
	handler := NewHTTP(service, AuthFunc(func(context.Context, *http.Request) (Principal, error) {
		return Principal{DeviceID: "sender"}, nil
	}))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/conversations/conversation/attachments", bytes.NewBufferString(`{"recipient":"recipient","transfer_id":"transfer","artifact_id":"artifact","chunk_count":1,"max_ciphertext_bytes":32,"plaintext_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","admin":true}`))
	req.Header.Set("Idempotency-Key", "unknown-field")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusBadRequest)
	}
}

func TestHTTPRejectsQueryParametersOutsideTheSignature(t *testing.T) {
	service := NewService(PolicyFunc(func(_, _, _ string, _ Action) bool { return true }))
	handler := NewHTTP(service, AuthFunc(func(context.Context, *http.Request) (Principal, error) {
		return Principal{DeviceID: "sender"}, nil
	}))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/conversations/conversation/attachments?recipient=attacker", bytes.NewBufferString(validAttachmentCreateBody()))
	req.Header.Set("Idempotency-Key", "query-rejected")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusBadRequest)
	}
}

func TestHTTPAcceptFencesEarlierSession(t *testing.T) {
	service := NewService(PolicyFunc(func(_, _, _ string, _ Action) bool { return true }))
	handler := NewHTTP(service, AuthFunc(func(_ context.Context, request *http.Request) (Principal, error) {
		return Principal{DeviceID: request.Header.Get("X-Test-Device")}, nil
	}))
	create := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/conversations/conversation/attachments", bytes.NewBufferString(validAttachmentCreateBody()))
	create.Header.Set("X-Test-Device", "sender")
	create.Header.Set("Idempotency-Key", "fence-session")
	created := httptest.NewRecorder()
	handler.ServeHTTP(created, create)
	var offer struct {
		OfferID string `json:"offer_id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &offer); err != nil {
		t.Fatal(err)
	}
	accept := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/attachment-offers/"+offer.OfferID+"/accept", nil)
	accept.Header.Set("X-Test-Device", "recipient")
	accepted := httptest.NewRecorder()
	handler.ServeHTTP(accepted, accept)
	if accepted.Code != http.StatusOK {
		t.Fatalf("accept status = %d, body = %s", accepted.Code, accepted.Body.String())
	}
}

func TestHTTPCiphertextUploadAndFencedDownload(t *testing.T) {
	service := NewService(PolicyFunc(func(_, _, _ string, _ Action) bool { return true }))
	handler := NewHTTP(service, AuthFunc(func(_ context.Context, request *http.Request) (Principal, error) {
		return Principal{DeviceID: request.Header.Get("X-Test-Device")}, nil
	}))
	create := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/conversations/conversation/attachments", bytes.NewBufferString(validAttachmentCreateBody()))
	create.Header.Set("X-Test-Device", "sender")
	create.Header.Set("Idempotency-Key", "upload-download")
	created := httptest.NewRecorder()
	handler.ServeHTTP(created, create)
	var offer struct {
		OfferID string `json:"offer_id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &offer); err != nil {
		t.Fatal(err)
	}
	accept := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/attachment-offers/"+offer.OfferID+"/accept", nil)
	accept.Header.Set("X-Test-Device", "recipient")
	accepted := httptest.NewRecorder()
	handler.ServeHTTP(accepted, accept)
	var session struct {
		Generation uint64 `json:"generation"`
		Token      string `json:"token"`
	}
	if err := json.Unmarshal(accepted.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	upload := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/v1/attachment-offers/"+offer.OfferID+"/artifacts/artifact/chunks/0", bytes.NewBufferString("ciphertext"))
	upload.Header.Set("X-Test-Device", "sender")
	uploaded := httptest.NewRecorder()
	handler.ServeHTTP(uploaded, upload)
	if uploaded.Code != http.StatusNoContent {
		t.Fatalf("upload status = %d", uploaded.Code)
	}
	download := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/attachment-offers/"+offer.OfferID+"/artifacts/artifact/chunks/0", nil)
	download.Header.Set("X-Test-Device", "recipient")
	download.Header.Set("X-Punaro-Attachment-Session", session.Token)
	download.Header.Set("X-Punaro-Attachment-Generation", strconv.FormatUint(session.Generation, 10))
	downloaded := httptest.NewRecorder()
	handler.ServeHTTP(downloaded, download)
	if downloaded.Code != http.StatusOK || downloaded.Body.String() != "ciphertext" {
		t.Fatalf("download status/body = %d/%q", downloaded.Code, downloaded.Body.String())
	}
}

func TestHTTPCompletionRequiresFencedSession(t *testing.T) {
	service := NewService(PolicyFunc(func(_, _, _ string, _ Action) bool { return true }))
	handler := NewHTTP(service, AuthFunc(func(_ context.Context, request *http.Request) (Principal, error) {
		return Principal{DeviceID: request.Header.Get("X-Test-Device")}, nil
	}))
	create := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/conversations/conversation/attachments", bytes.NewBufferString(validAttachmentCreateBody()))
	create.Header.Set("X-Test-Device", "sender")
	create.Header.Set("Idempotency-Key", "complete")
	created := httptest.NewRecorder()
	handler.ServeHTTP(created, create)
	var offer struct {
		OfferID string `json:"offer_id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &offer); err != nil {
		t.Fatal(err)
	}
	accept := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/attachment-offers/"+offer.OfferID+"/accept", nil)
	accept.Header.Set("X-Test-Device", "recipient")
	accepted := httptest.NewRecorder()
	handler.ServeHTTP(accepted, accept)
	var session struct {
		Generation uint64 `json:"generation"`
		Token      string `json:"token"`
	}
	if err := json.Unmarshal(accepted.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	upload := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/v1/attachment-offers/"+offer.OfferID+"/artifacts/artifact/chunks/0", bytes.NewBufferString("ciphertext"))
	upload.Header.Set("X-Test-Device", "sender")
	uploaded := httptest.NewRecorder()
	handler.ServeHTTP(uploaded, upload)
	if uploaded.Code != http.StatusNoContent {
		t.Fatalf("upload status = %d", uploaded.Code)
	}
	body := `{"plaintext_hash":"` + base64.RawStdEncoding.EncodeToString(make([]byte, hashSize)) + `"}`
	complete := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/attachment-offers/"+offer.OfferID+"/complete", bytes.NewBufferString(body))
	complete.Header.Set("X-Test-Device", "recipient")
	complete.Header.Set("X-Punaro-Attachment-Session", session.Token)
	complete.Header.Set("X-Punaro-Attachment-Generation", strconv.FormatUint(session.Generation, 10))
	completed := httptest.NewRecorder()
	handler.ServeHTTP(completed, complete)
	if completed.Code != http.StatusNoContent {
		t.Fatalf("completion status = %d", completed.Code)
	}
}

func TestHTTPSignalAcceptsBoundedOpaqueSenderPayload(t *testing.T) {
	service := NewService(PolicyFunc(func(_, _, _ string, _ Action) bool { return true }))
	handler := NewHTTP(service, AuthFunc(func(_ context.Context, request *http.Request) (Principal, error) {
		return Principal{DeviceID: request.Header.Get("X-Test-Device")}, nil
	}))
	create := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/conversations/conversation/attachments", bytes.NewBufferString(validAttachmentCreateBody()))
	create.Header.Set("X-Test-Device", "sender")
	create.Header.Set("Idempotency-Key", "signal")
	created := httptest.NewRecorder()
	handler.ServeHTTP(created, create)
	var offer struct {
		OfferID string `json:"offer_id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &offer); err != nil {
		t.Fatal(err)
	}
	signal := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/attachment-offers/"+offer.OfferID+"/signal", bytes.NewBufferString("opaque-sdp-free-signal"))
	signal.Header.Set("X-Test-Device", "sender")
	responded := httptest.NewRecorder()
	handler.ServeHTTP(responded, signal)
	if responded.Code != http.StatusNoContent {
		t.Fatalf("signal status = %d", responded.Code)
	}
}

func validAttachmentCreateBody() string {
	return `{"recipient":"recipient","transfer_id":"transfer","artifact_id":"artifact","chunk_count":1,"max_ciphertext_bytes":32,"plaintext_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`
}
