package devicehttp

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rock3r/punaro/internal/ingress"
	punaropostgres "github.com/rock3r/punaro/internal/postgres"
)

type fakeStore struct {
	redeem     punaropostgres.RedeemEnrollment
	credential punaropostgres.DeviceCredential
	auth       punaropostgres.AuthenticatedDevice
	err        error
}

type blockingStore struct{ started chan struct{} }

func (b *blockingStore) RedeemEnrollment(ctx context.Context, _ punaropostgres.RedeemEnrollment) (punaropostgres.DeviceCredential, error) {
	close(b.started)
	<-ctx.Done()
	return punaropostgres.DeviceCredential{}, ctx.Err()
}

func (b *blockingStore) AuthenticateDevice(ctx context.Context, _ string) (punaropostgres.AuthenticatedDevice, error) {
	close(b.started)
	<-ctx.Done()
	return punaropostgres.AuthenticatedDevice{}, ctx.Err()
}

func (f *fakeStore) RedeemEnrollment(_ context.Context, redeem punaropostgres.RedeemEnrollment) (punaropostgres.DeviceCredential, error) {
	f.redeem = redeem
	if f.err != nil {
		return punaropostgres.DeviceCredential{}, f.err
	}
	if f.credential.Encoded != "" {
		return f.credential, nil
	}
	return punaropostgres.DeviceCredential{Encoded: "punaro_device_credential"}, nil
}

func (f *fakeStore) AuthenticateDevice(_ context.Context, _ string) (punaropostgres.AuthenticatedDevice, error) {
	if f.err != nil {
		return punaropostgres.AuthenticatedDevice{}, f.err
	}
	return f.auth, nil
}

func testPolicy(t *testing.T) *ingress.Policy {
	t.Helper()
	p := &ingress.Policy{Mode: ingress.LAN, ListenAddr: "192.168.1.4:8080", TrustedLAN: "192.168.1.0/24", AllowPlaintext: true}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRedeemEnrollmentUsesStrictBoundedRequest(t *testing.T) {
	store := &fakeStore{}
	handler := New(store, testPolicy(t))
	body := `{"enrollment_id":"11111111-1111-4111-8111-111111111111","client_binding":"22222222-2222-4222-8222-222222222222","code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","idempotency_key":"33333333-3333-4333-8333-333333333333"}`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/enrollments/redeem", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.168.1.20:1234"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusCreated || store.redeem.EnrollmentID == "" || !strings.Contains(response.Body.String(), "credential") || strings.Contains(response.Body.String(), "expires_at") || strings.Contains(response.Body.String(), "0001-01-01") {
		t.Fatalf("status=%d body=%q redeem=%#v", response.Code, response.Body.String(), store.redeem)
	}
	expiresAt := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	store.credential = punaropostgres.DeviceCredential{Encoded: "expiring_credential", ExpiresAt: expiresAt}
	expiring := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/enrollments/redeem", strings.NewReader(body))
	expiring.Header.Set("Content-Type", "application/json")
	expiring.RemoteAddr = "192.168.1.20:1234"
	expiringResponse := httptest.NewRecorder()
	handler.ServeHTTP(expiringResponse, expiring)
	if expiringResponse.Code != http.StatusCreated || !strings.Contains(expiringResponse.Body.String(), `"expires_at":"2030-01-02T03:04:05Z"`) {
		t.Fatalf("expiring status=%d body=%q", expiringResponse.Code, expiringResponse.Body.String())
	}

	badBodies := []struct {
		name string
		body string
	}{
		{name: "duplicate", body: `{"enrollment_id":"11111111-1111-4111-8111-111111111111","enrollment_id":"11111111-1111-4111-8111-111111111111","client_binding":"22222222-2222-4222-8222-222222222222","code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","idempotency_key":"33333333-3333-4333-8333-333333333333"}`},
		{name: "unknown", body: `{"enrollment_id":"11111111-1111-4111-8111-111111111111","client_binding":"22222222-2222-4222-8222-222222222222","code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","idempotency_key":"33333333-3333-4333-8333-333333333333","extra":true}`},
		{name: "trailing", body: body + `{}`},
	}
	for _, test := range badBodies {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/enrollments/redeem", strings.NewReader(test.body))
			r.Header.Set("Content-Type", "application/json")
			r.RemoteAddr = "192.168.1.20:1234"
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
			}
		})
	}

	large := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/enrollments/redeem", bytes.NewReader(make([]byte, maxRequestBytes+1)))
	large.Header.Set("Content-Type", "application/json")
	large.RemoteAddr = "192.168.1.20:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, large)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize status=%d", w.Code)
	}
}

func TestCredentialRoutesEnforceTransportAndUniformAuthentication(t *testing.T) {
	store := &fakeStore{auth: punaropostgres.AuthenticatedDevice{PrincipalID: "11111111-1111-4111-8111-111111111111", LookupID: "22222222-2222-4222-8222-222222222222", Generation: 2}}
	handler := New(store, testPolicy(t))

	request := func(remote, authorization string) *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/device/session", nil)
		r.RemoteAddr = remote
		r.Header.Set("Authorization", authorization)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if got := request("192.168.1.20:1234", "Bearer opaque"); got.Code != http.StatusOK {
		t.Fatalf("trusted status=%d body=%q", got.Code, got.Body.String())
	}
	if got := request("203.0.113.20:1234", "Bearer opaque"); got.Code != http.StatusForbidden {
		t.Fatalf("public plaintext status=%d", got.Code)
	}
	for _, authorization := range []string{"", "Basic opaque", "Bearer ", "Bearer one two"} {
		if got := request("192.168.1.20:1234", authorization); got.Code != http.StatusUnauthorized || !strings.Contains(got.Body.String(), "unauthenticated") {
			t.Fatalf("authorization=%q status=%d body=%q", authorization, got.Code, got.Body.String())
		}
	}
	store.err = errors.New("database detail that must not escape")
	if got := request("192.168.1.20:1234", "Bearer opaque"); got.Code != http.StatusUnauthorized || strings.Contains(got.Body.String(), "database") {
		t.Fatalf("store failure status=%d body=%q", got.Code, got.Body.String())
	}
	duplicate := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/device/session", nil)
	duplicate.RemoteAddr = "192.168.1.20:1234"
	duplicate.Header["Authorization"] = []string{"Bearer opaque", "Bearer second"}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, duplicate)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("duplicate Authorization status=%d", w.Code)
	}
}

func TestCredentialIngressBoundsBlockedStoreWork(t *testing.T) {
	store := &blockingStore{started: make(chan struct{})}
	handler := newHandler(store, testPolicy(t), 1, 25*time.Millisecond)
	request := func() *http.Request {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/device/session", nil)
		r.RemoteAddr = "192.168.1.20:1234"
		r.Header.Set("Authorization", "Bearer opaque")
		return r
	}
	first := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(first, request())
		close(done)
	}()
	<-store.started
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, request())
	if second.Code != http.StatusTooManyRequests || second.Header().Get("Retry-After") == "" {
		t.Fatalf("overflow status=%d headers=%v", second.Code, second.Header())
	}
	select {
	case <-done:
		if first.Code != http.StatusUnauthorized {
			t.Fatalf("timed-out auth status=%d body=%q", first.Code, first.Body.String())
		}
	case <-time.After(time.Second):
		t.Fatal("blocked store request outlived its operation deadline")
	}
}
