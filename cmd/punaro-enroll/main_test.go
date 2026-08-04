package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareThenRedeemKeepsSecretsOutOfOutputAndRecoversIdempotently(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	var prepared publicEnrollment
	credential := "22222222-2222-4222-8222-222222222222." + strings.Repeat("A", 43)
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/v1/enrollments/redeem" || r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("request=%s %s headers=%v", r.Method, r.URL.Path, r.Header)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || !strings.Contains(string(body), prepared.ClientBinding) || !strings.Contains(string(body), `"idempotency_key"`) {
			t.Fatalf("body=%q err=%v", body, err)
		}
		if calls == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"principal_id":"11111111-1111-4111-8111-111111111111","lookup_id":"22222222-2222-4222-8222-222222222222","credential":"`+credential+`","generation":1}`)
	}))
	defer server.Close()
	var firstOut, firstErr bytes.Buffer
	if code := run([]string{"prepare", "--origin", server.URL, "--state-dir", stateDir}, &firstOut, &firstErr); code != 0 || firstErr.Len() != 0 {
		t.Fatalf("prepare code=%d stdout=%q stderr=%q", code, firstOut.String(), firstErr.String())
	}
	if err := json.Unmarshal(firstOut.Bytes(), &prepared); err != nil || prepared.Origin != server.URL || prepared.ClientBinding == "" {
		t.Fatalf("prepare=%q parsed=%#v err=%v", firstOut.String(), prepared, err)
	}
	original := newEnrollmentHTTPClient
	newEnrollmentHTTPClient = func() *http.Client { return server.Client() }
	t.Cleanup(func() { newEnrollmentHTTPClient = original })

	material := filepath.Join(t.TempDir(), "material.json")
	if err := os.WriteFile(material, []byte(`{"enrollment_id":"33333333-3333-4333-8333-333333333333","client_binding":"`+prepared.ClientBinding+`","code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	credentialFile := filepath.Join(stateDir, "device.credential")
	var firstRedeemOut, firstRedeemErr bytes.Buffer
	if code := run([]string{"redeem", "--state-dir", stateDir, "--enrollment-file", material, "--credential-file", credentialFile}, &firstRedeemOut, &firstRedeemErr); code != 1 || !strings.Contains(firstRedeemErr.String(), "retry") {
		t.Fatalf("first redeem code=%d stdout=%q stderr=%q", code, firstRedeemOut.String(), firstRedeemErr.String())
	}
	if raw, err := os.ReadFile(filepath.Join(stateDir, redemptionJournalName)); err != nil || !strings.Contains(string(raw), `"code"`) { // #nosec G304 -- test reads a recovery file created below its own private fixture.
		t.Fatalf("recovery journal err=%v raw=%q", err, raw)
	}
	var secondOut, secondErr bytes.Buffer
	if code := run([]string{"redeem", "--state-dir", stateDir, "--enrollment-file", material, "--credential-file", credentialFile}, &secondOut, &secondErr); code != 0 || secondErr.Len() != 0 {
		t.Fatalf("second redeem code=%d stdout=%q stderr=%q", code, secondOut.String(), secondErr.String())
	}
	if calls != 2 || strings.Contains(firstOut.String()+firstRedeemOut.String()+firstRedeemErr.String()+secondOut.String()+secondErr.String(), credential) || strings.Contains(secondOut.String(), "code") {
		t.Fatalf("calls=%d output leaked secret: prepare=%q first=%q/%q second=%q/%q", calls, firstOut.String(), firstRedeemOut.String(), firstRedeemErr.String(), secondOut.String(), secondErr.String())
	}
	if raw, err := os.ReadFile(credentialFile); err != nil || string(raw) != credential+"\n" { // #nosec G304 -- test reads the credential created below its own private fixture.
		t.Fatalf("credential err=%v raw=%q", err, raw)
	}
	if _, err := os.Lstat(filepath.Join(stateDir, redemptionJournalName)); !os.IsNotExist(err) {
		t.Fatalf("recovery journal remains: %v", err)
	}
}

func TestRedeemFailsClosedForBindingMismatchWithoutContactingOrigin(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	if code := run([]string{"prepare", "--origin", "https://punaro.test", "--state-dir", stateDir}, io.Discard, io.Discard); code != 0 {
		t.Fatal("prepare failed")
	}
	material := filepath.Join(t.TempDir(), "material.json")
	if err := os.WriteFile(material, []byte(`{"enrollment_id":"33333333-3333-4333-8333-333333333333","client_binding":"44444444-4444-4444-8444-444444444444","code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"redeem", "--state-dir", stateDir, "--enrollment-file", material, "--credential-file", filepath.Join(stateDir, "credential")}, &stdout, &stderr); code != 2 || stdout.Len() != 0 || stderr.String() != "punaro-enroll: enrollment material does not match this device\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestEnrollmentMaterialRejectsDuplicateOrUnknownFields(t *testing.T) {
	directory := t.TempDir()
	for name, raw := range map[string]string{
		"duplicate": `{"enrollment_id":"33333333-3333-4333-8333-333333333333","enrollment_id":"33333333-3333-4333-8333-333333333333","client_binding":"44444444-4444-4444-8444-444444444444","code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`,
		"unknown":   `{"enrollment_id":"33333333-3333-4333-8333-333333333333","client_binding":"44444444-4444-4444-8444-444444444444","code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","origin":"https://attacker.test"}`,
	} {
		path := filepath.Join(directory, name+".json")
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadMaterial(path); err == nil {
			t.Fatalf("%s material was accepted", name)
		}
	}
}

func TestRedemptionResponseAcceptsOptionalExpiryWithoutRelaxingItsSchema(t *testing.T) {
	response, err := decodeRedemptionResponse([]byte(`{"principal_id":"11111111-1111-4111-8111-111111111111","lookup_id":"22222222-2222-4222-8222-222222222222","credential":"22222222-2222-4222-8222-222222222222.` + strings.Repeat("A", 43) + `","generation":1,"expires_at":"2030-01-02T03:04:05Z"}`))
	if err != nil || response.ExpiresAt.IsZero() {
		t.Fatalf("expiring response err=%v response=%#v", err, response)
	}
	if _, err := decodeRedemptionResponse([]byte(`{"principal_id":"11111111-1111-4111-8111-111111111111","lookup_id":"22222222-2222-4222-822222222222","credential":"punaro_device_credential","generation":1,"expires_at":"invalid"}`)); err == nil {
		t.Fatal("invalid expiry was accepted")
	}
}

func TestRejectedEnrollmentClearsRecoverySoReplacementCanProceed(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) }))
	defer server.Close()
	original := newEnrollmentHTTPClient
	newEnrollmentHTTPClient = func() *http.Client { return server.Client() }
	t.Cleanup(func() { newEnrollmentHTTPClient = original })
	stateDir := filepath.Join(t.TempDir(), "state")
	if code := run([]string{"prepare", "--origin", server.URL, "--state-dir", stateDir}, io.Discard, io.Discard); code != 0 {
		t.Fatal("prepare failed")
	}
	identity, err := loadIdentity(filepath.Join(stateDir, identityFileName))
	if err != nil {
		t.Fatal(err)
	}
	material := filepath.Join(t.TempDir(), "material.json")
	if err := os.WriteFile(material, []byte(`{"enrollment_id":"33333333-3333-4333-8333-333333333333","client_binding":"`+identity.ClientBinding+`","code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if code := run([]string{"redeem", "--state-dir", stateDir, "--enrollment-file", material, "--credential-file", filepath.Join(stateDir, "credential")}, io.Discard, &stderr); code != 1 || !strings.Contains(stderr.String(), "request a new enrollment") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if _, err := os.Lstat(filepath.Join(stateDir, redemptionJournalName)); !os.IsNotExist(err) {
		t.Fatalf("rejected enrollment recovery was retained: %v", err)
	}
}
