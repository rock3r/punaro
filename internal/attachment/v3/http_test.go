package v3

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAttachmentHTTPHandlerFailsClosedBeforeAuthorityLookup(t *testing.T) {
	store, err := openSourceStore(privateDatabase(t), defaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	if _, err := NewAttachmentHTTPHandler(AttachmentHTTPHandlerOptions{}); err == nil {
		t.Fatal("handler accepted missing dependencies")
	}
	handler, err := NewAttachmentHTTPHandler(AttachmentHTTPHandlerOptions{Store: store, Authority: panicAuthorityProvider{}, Authorize: panicRequestAuthorizer{}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v3/attachments/05000000000000000000000000000000/source?x=1", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("query status=%d", response.Code)
	}
	request = httptest.NewRequest(http.MethodPost, "/v3/attachments/05000000000000000000000000000000/source", nil)
	request.Header.Add("Content-Encoding", "")
	request.Header.Add("Content-Encoding", "gzip")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("duplicate content encoding status=%d", response.Code)
	}
	request = httptest.NewRequest(http.MethodPost, "/v3/attachments/05000000000000000000000000000000/source", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("empty source status=%d", response.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/v3/attachments/05000000000000000000000000000000/chunks/0", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("missing credentials status=%d", response.Code)
	}
}

type panicAuthorityProvider struct{}

func (panicAuthorityProvider) ResolveAttachmentAuthority(context.Context, time.Time) (AttachmentAuthority, error) {
	panic("unreachable")
}

type panicRequestAuthorizer struct{}

func (panicRequestAuthorizer) AuthorizeAttachmentRequest(context.Context, Permit) error {
	return errors.New("unreachable")
}
