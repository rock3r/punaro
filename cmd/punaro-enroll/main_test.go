package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rock3r/punaro/internal/clientidentity"
	"github.com/rock3r/punaro/internal/legacyexchange"
	punaropostgres "github.com/rock3r/punaro/internal/postgres"
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

	material := writeTestMaterial(t, `{"enrollment_id":"33333333-3333-4333-8333-333333333333","client_binding":"`+prepared.ClientBinding+`","code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)
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

func TestPrepareThenRedeemOverLoopbackHTTP(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	credential := "22222222-2222-4222-8222-222222222222." + strings.Repeat("A", 43)
	var prepared publicEnrollment
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/enrollments/redeem" {
			t.Errorf("request=%s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"principal_id":"11111111-1111-4111-8111-111111111111","lookup_id":"22222222-2222-4222-8222-222222222222","credential":"`+credential+`","generation":1}`)
	}))
	defer server.Close()

	var prepareOut, prepareErr bytes.Buffer
	if code := run([]string{"prepare", "--origin", server.URL, "--state-dir", stateDir}, &prepareOut, &prepareErr); code != 0 || prepareErr.Len() != 0 {
		t.Fatalf("prepare code=%d stdout=%q stderr=%q", code, prepareOut.String(), prepareErr.String())
	}
	if err := json.Unmarshal(prepareOut.Bytes(), &prepared); err != nil {
		t.Fatalf("parse prepare output: %v", err)
	}
	material := writeTestMaterial(t, `{"enrollment_id":"33333333-3333-4333-8333-333333333333","client_binding":"`+prepared.ClientBinding+`","code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)
	credentialFile := filepath.Join(stateDir, "device.credential")
	var redeemOut, redeemErr bytes.Buffer
	if code := run([]string{"redeem", "--state-dir", stateDir, "--enrollment-file", material, "--credential-file", credentialFile}, &redeemOut, &redeemErr); code != 0 || redeemErr.Len() != 0 {
		t.Fatalf("redeem code=%d stdout=%q stderr=%q", code, redeemOut.String(), redeemErr.String())
	}
	if raw, err := os.ReadFile(credentialFile); err != nil || string(raw) != credential+"\n" { // #nosec G304 -- test reads its own protected credential fixture.
		t.Fatalf("credential persistence err=%v", err)
	}
}

func TestLegacyPrepareAndRedeemUsesProofBoundExchangeRoute(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "legacy-state")
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var prepared publicEnrollment
	credential := "22222222-2222-4222-8222-222222222222." + strings.Repeat("A", 43)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/legacy-enrollments/redeem" {
			t.Fatalf("request=%s %s", r.Method, r.URL.Path)
		}
		var request struct {
			EnrollmentID   string `json:"enrollment_id"`
			ClientBinding  string `json:"client_binding"`
			Code           string `json:"code"`
			IdempotencyKey string `json:"idempotency_key"`
			PublicKey      string `json:"legacy_public_key"`
			Signature      string `json:"legacy_signature"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil || request.ClientBinding != prepared.ClientBinding {
			t.Fatal("legacy redemption body is invalid")
		}
		gotPublic, publicErr := base64.RawURLEncoding.Strict().DecodeString(request.PublicKey)
		signature, signatureErr := base64.RawURLEncoding.Strict().DecodeString(request.Signature)
		code, codeErr := base64.RawURLEncoding.Strict().DecodeString(request.Code)
		digest := sha256.Sum256(code)
		if publicErr != nil || signatureErr != nil || codeErr != nil || !bytes.Equal(gotPublic, public) || !ed25519.Verify(public, legacyexchange.Transcript(request.EnrollmentID, request.ClientBinding, request.IdempotencyKey, digest), signature) {
			t.Fatal("legacy redemption proof is invalid")
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"principal_id":"11111111-1111-4111-8111-111111111111","lookup_id":"22222222-2222-4222-8222-222222222222","credential":"`+credential+`","generation":1}`)
	}))
	defer server.Close()
	var prepareOut, prepareErr bytes.Buffer
	if code := run([]string{"prepare", "--origin", server.URL, "--state-dir", stateDir, "--legacy-machine-id", "legacy-a"}, &prepareOut, &prepareErr); code != 0 {
		t.Fatalf("prepare code=%d stderr=%q", code, prepareErr.String())
	}
	if err := json.Unmarshal(prepareOut.Bytes(), &prepared); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(stateDir, "legacy.key")
	if err := os.WriteFile(keyFile, []byte(base64.RawURLEncoding.EncodeToString(private)), 0o600); err != nil {
		t.Fatal(err)
	}
	material := writeTestMaterial(t, `{"enrollment_id":"33333333-3333-4333-8333-333333333333","client_binding":"`+prepared.ClientBinding+`","code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)
	credentialFile := filepath.Join(stateDir, "device.credential")
	original := newEnrollmentHTTPClient
	newEnrollmentHTTPClient = func() *http.Client { return server.Client() }
	t.Cleanup(func() { newEnrollmentHTTPClient = original })
	var redeemOut, redeemErr bytes.Buffer
	if code := run([]string{"redeem", "--state-dir", stateDir, "--enrollment-file", material, "--credential-file", credentialFile, "--legacy-private-key-file", keyFile}, &redeemOut, &redeemErr); code != 0 || redeemErr.Len() != 0 || strings.Contains(redeemOut.String(), credential) {
		t.Fatalf("redeem code=%d stdout=%q stderr=%q", code, redeemOut.String(), redeemErr.String())
	}
}

func TestLegacyRecoveryRejectsChangedProofWithoutDiscardingJournal(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "legacy-state")
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, wrongPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credential := "22222222-2222-4222-8222-222222222222." + strings.Repeat("A", 43)
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var request struct {
			PublicKey string `json:"legacy_public_key"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil || request.PublicKey != base64.RawURLEncoding.EncodeToString(public) {
			t.Fatal("legacy recovery used a changed proof")
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
	var prepared publicEnrollment
	var prepareOut bytes.Buffer
	if code := run([]string{"prepare", "--origin", server.URL, "--state-dir", stateDir, "--legacy-machine-id", "legacy-a"}, &prepareOut, io.Discard); code != 0 || json.Unmarshal(prepareOut.Bytes(), &prepared) != nil {
		t.Fatalf("prepare code=%d output=%q", code, prepareOut.String())
	}
	keyPath := filepath.Join(stateDir, "legacy.key")
	wrongKeyPath := filepath.Join(stateDir, "wrong-legacy.key")
	if err := os.WriteFile(keyPath, []byte(base64.RawURLEncoding.EncodeToString(private)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wrongKeyPath, []byte(base64.RawURLEncoding.EncodeToString(wrongPrivate)), 0o600); err != nil {
		t.Fatal(err)
	}
	material := writeTestMaterial(t, `{"enrollment_id":"33333333-3333-4333-8333-333333333333","client_binding":"`+prepared.ClientBinding+`","code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)
	credentialPath := filepath.Join(stateDir, "device.credential")
	original := newEnrollmentHTTPClient
	newEnrollmentHTTPClient = func() *http.Client { return server.Client() }
	t.Cleanup(func() { newEnrollmentHTTPClient = original })
	if code := run([]string{"redeem", "--state-dir", stateDir, "--enrollment-file", material, "--credential-file", credentialPath, "--legacy-private-key-file", keyPath}, io.Discard, io.Discard); code != 1 {
		t.Fatalf("initial redeem code=%d", code)
	}
	journalPath := filepath.Join(stateDir, redemptionJournalName)
	before, err := os.ReadFile(journalPath) // #nosec G304 -- test reads its own private recovery fixture.
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if code := run([]string{"recover", "--state-dir", stateDir, "--credential-file", credentialPath, "--legacy-private-key-file", wrongKeyPath}, io.Discard, &stderr); code != 2 || !strings.Contains(stderr.String(), "does not match existing enrollment recovery") {
		t.Fatalf("wrong-key recovery code=%d stderr=%q", code, stderr.String())
	}
	after, err := os.ReadFile(journalPath) // #nosec G304 -- test proves the private recovery fixture was retained exactly.
	if err != nil || !bytes.Equal(before, after) || calls != 1 {
		t.Fatalf("journal changed=%t calls=%d err=%v", !bytes.Equal(before, after), calls, err)
	}
	if code := run([]string{"recover", "--state-dir", stateDir, "--credential-file", credentialPath, "--legacy-private-key-file", keyPath}, io.Discard, io.Discard); code != 0 || calls != 2 {
		t.Fatalf("correct recovery code=%d calls=%d", code, calls)
	}
}

func TestRedeemRejectsCredentialPathsThatCannotFitRecoveryJournal(t *testing.T) {
	journal := redemptionJournal{
		EnrollmentID:   "33333333-3333-4333-8333-333333333333",
		ClientBinding:  "11111111-1111-4111-8111-111111111111",
		Code:           strings.Repeat("A", 43),
		IdempotencyKey: "44444444-4444-4444-8444-444444444444",
		CredentialPath: "/state/" + strings.Repeat("a", maxEnrollmentFile),
	}
	if journalCanPersistCredential(journal) {
		t.Fatal("credential path that exceeds the recovery-journal limit was accepted")
	}
}

func TestPrepareRejectsChangingExistingFreshStateToLegacyMode(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	args := []string{"prepare", "--origin", "https://punaro.test", "--state-dir", stateDir}
	if code := run(args, io.Discard, io.Discard); code != 0 {
		t.Fatalf("fresh prepare code=%d", code)
	}
	var stdout, stderr bytes.Buffer
	legacyArgs := append(append([]string(nil), args...), "--legacy-machine-id", "legacy-a")
	if code := run(legacyArgs, &stdout, &stderr); code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "state preparation failed") || strings.Contains(stderr.String(), "legacy-a") {
		t.Fatalf("legacy prepare code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if code := run(args, io.Discard, io.Discard); code != 0 {
		t.Fatalf("fresh retry code=%d", code)
	}
}

func TestPrepareRetriesIdentityDirectorySyncBeforePublishingBinding(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory-sync durability contract")
	}
	stateDir := filepath.Join(t.TempDir(), "state")
	parentDir := filepath.Dir(stateDir)
	originalSync := syncPrivateDirectory
	parentSyncs := 0
	syncPrivateDirectory = func(path string) error {
		if path == parentDir {
			parentSyncs++
			if parentSyncs == 1 {
				return os.ErrInvalid
			}
		}
		return nil
	}
	t.Cleanup(func() { syncPrivateDirectory = originalSync })
	if code := run([]string{"prepare", "--origin", "https://punaro.test", "--state-dir", stateDir}, io.Discard, io.Discard); code != 2 {
		t.Fatalf("first prepare code=%d", code)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"prepare", "--origin", "https://punaro.test", "--state-dir", stateDir}, &stdout, &stderr); code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "client_binding") {
		t.Fatalf("retry code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if parentSyncs != 2 {
		t.Fatalf("state directory parent syncs=%d", parentSyncs)
	}
}

func TestPreparePersistsExplicitTrustedLANPolicy(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	if code := run([]string{"prepare", "--origin", "http://192.168.1.4:8080", "--state-dir", stateDir, "--allow-lan-http", "--trusted-lan-cidr", "192.168.1.0/24"}, io.Discard, io.Discard); code != 0 {
		t.Fatalf("LAN prepare code=%d", code)
	}
	state, err := loadIdentity(filepath.Join(stateDir, identityFileName))
	if err != nil {
		t.Fatal(err)
	}
	if state.Version != clientidentity.LANVersion || !state.AllowLANHTTP || state.TrustedLANCIDR != "192.168.1.0/24" {
		t.Fatalf("identity=%#v", state)
	}
	if code := run([]string{"prepare", "--origin", "http://192.168.2.4:8080", "--state-dir", filepath.Join(t.TempDir(), "outside"), "--allow-lan-http", "--trusted-lan-cidr", "192.168.1.0/24"}, io.Discard, io.Discard); code != 2 {
		t.Fatalf("out-of-CIDR prepare code=%d", code)
	}
}

func TestPreparePersistsLoopbackHTTPWithoutTrustedLANPolicy(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	args := []string{"prepare", "--origin", "http://127.0.0.1:18080/", "--state-dir", stateDir}
	for attempt := 1; attempt <= 2; attempt++ {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
			t.Fatalf("attempt=%d code=%d stdout=%q stderr=%q", attempt, code, stdout.String(), stderr.String())
		}
	}
	state, err := loadIdentity(filepath.Join(stateDir, identityFileName))
	if err != nil {
		t.Fatal(err)
	}
	if state.Version != clientidentity.Version || state.Origin != "http://127.0.0.1:18080" || state.AllowLANHTTP || state.TrustedLANCIDR != "" {
		t.Fatalf("identity=%#v", state)
	}
	if code := run([]string{"prepare", "--origin", "http://127.0.0.1:18080", "--state-dir", filepath.Join(t.TempDir(), "policy"), "--allow-lan-http", "--trusted-lan-cidr", "127.0.0.0/8"}, io.Discard, io.Discard); code != 2 {
		t.Fatalf("loopback with trusted-LAN policy code=%d", code)
	}
}

func TestUnverifiedBadRequestRetainsRecoveryJournal(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"request is malformed"}`)
	}))
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
	material := writeTestMaterial(t, `{"enrollment_id":"33333333-3333-4333-8333-333333333333","client_binding":"`+identity.ClientBinding+`","code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)
	var stderr bytes.Buffer
	if code := run([]string{"redeem", "--state-dir", stateDir, "--enrollment-file", material, "--credential-file", filepath.Join(stateDir, "credential")}, io.Discard, &stderr); code != 1 || !strings.Contains(stderr.String(), "retry") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if _, err := os.Lstat(filepath.Join(stateDir, redemptionJournalName)); err != nil {
		t.Fatalf("unverified bad request removed recovery journal: %v", err)
	}
}

func TestVerifiedBadRequestClearsRecoveryJournal(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"request is malformed"}`)
	}))
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
	material := writeTestMaterial(t, `{"enrollment_id":"33333333-3333-4333-8333-333333333333","client_binding":"`+identity.ClientBinding+`","code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)
	if code := run([]string{"redeem", "--state-dir", stateDir, "--enrollment-file", material, "--credential-file", filepath.Join(stateDir, "credential")}, io.Discard, io.Discard); code != 1 {
		t.Fatalf("code=%d", code)
	}
	if _, err := os.Lstat(filepath.Join(stateDir, redemptionJournalName)); !os.IsNotExist(err) {
		t.Fatalf("verified bad request retained recovery journal: %v", err)
	}
}

func TestRedeemFailsClosedForBindingMismatchWithoutContactingOrigin(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	if code := run([]string{"prepare", "--origin", "https://punaro.test", "--state-dir", stateDir}, io.Discard, io.Discard); code != 0 {
		t.Fatal("prepare failed")
	}
	material := writeTestMaterial(t, `{"enrollment_id":"33333333-3333-4333-8333-333333333333","client_binding":"44444444-4444-4444-8444-444444444444","code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"redeem", "--state-dir", stateDir, "--enrollment-file", material, "--credential-file", filepath.Join(stateDir, "credential")}, &stdout, &stderr); code != 2 || stdout.Len() != 0 || stderr.String() != "punaro-enroll: enrollment material does not match this device\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestRedeemPreflightsCredentialDestinationBeforeContactingOrigin(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("redemption contacted the origin before preflighting credential destination")
	}))
	defer server.Close()
	original := newEnrollmentHTTPClient
	newEnrollmentHTTPClient = func() *http.Client { return server.Client() }
	t.Cleanup(func() { newEnrollmentHTTPClient = original })
	stateDir := filepath.Join(t.TempDir(), "state")
	var prepared publicEnrollment
	var preparedOut bytes.Buffer
	if code := run([]string{"prepare", "--origin", server.URL, "--state-dir", stateDir}, &preparedOut, io.Discard); code != 0 || json.Unmarshal(preparedOut.Bytes(), &prepared) != nil {
		t.Fatalf("prepare code=%d output=%q", code, preparedOut.String())
	}
	material := writeTestMaterial(t, `{"enrollment_id":"33333333-3333-4333-8333-333333333333","client_binding":"`+prepared.ClientBinding+`","code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)
	credentialPath := filepath.Join(stateDir, "credential")
	if err := writePrivateNew(credentialPath, []byte("existing credential\n")); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if code := run([]string{"redeem", "--state-dir", stateDir, "--enrollment-file", material, "--credential-file", credentialPath}, io.Discard, &stderr); code != 2 || stderr.String() != "punaro-enroll: private credential destination is unavailable\n" {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if _, err := os.Lstat(filepath.Join(stateDir, redemptionJournalName)); !os.IsNotExist(err) {
		t.Fatalf("preflight created a recovery journal: %v", err)
	}
}

func TestRedeemRejectsRecoveryJournalAsCredentialDestinationBeforeContactingOrigin(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("redemption contacted the origin before rejecting the reserved credential path")
	}))
	defer server.Close()
	original := newEnrollmentHTTPClient
	newEnrollmentHTTPClient = func() *http.Client { return server.Client() }
	t.Cleanup(func() { newEnrollmentHTTPClient = original })
	stateDir := filepath.Join(t.TempDir(), "state")
	var prepared publicEnrollment
	var preparedOut bytes.Buffer
	if code := run([]string{"prepare", "--origin", server.URL, "--state-dir", stateDir}, &preparedOut, io.Discard); code != 0 || json.Unmarshal(preparedOut.Bytes(), &prepared) != nil {
		t.Fatalf("prepare code=%d output=%q", code, preparedOut.String())
	}
	material := writeTestMaterial(t, `{"enrollment_id":"33333333-3333-4333-8333-333333333333","client_binding":"`+prepared.ClientBinding+`","code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)
	caseVariant := strings.ToUpper(redemptionJournalName)
	if code := run([]string{"redeem", "--state-dir", stateDir, "--enrollment-file", material, "--credential-file", filepath.Join(stateDir, caseVariant)}, io.Discard, io.Discard); code != 2 {
		t.Fatalf("code=%d", code)
	}
	if _, err := os.Lstat(filepath.Join(stateDir, redemptionJournalName)); !os.IsNotExist(err) {
		t.Fatalf("reserved credential path created a recovery journal: %v", err)
	}
}

func TestRecoverCompletesWhenCredentialWasPersistedBeforeJournalCleanup(t *testing.T) {
	credential := "22222222-2222-4222-8222-222222222222." + strings.Repeat("A", 43)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || strings.Contains(string(body), `"credential"`) {
			t.Fatalf("recovery body=%q err=%v", body, err)
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"principal_id":"11111111-1111-4111-8111-111111111111","lookup_id":"22222222-2222-4222-8222-222222222222","credential":"`+credential+`","generation":1}`)
	}))
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
	credentialPath := filepath.Join(stateDir, "credential")
	journal := redemptionJournal{EnrollmentID: "33333333-3333-4333-8333-333333333333", ClientBinding: identity.ClientBinding, Code: strings.Repeat("A", 43), IdempotencyKey: "44444444-4444-4444-8444-444444444444", CredentialPath: credentialPath, Credential: credential}
	if err := writePrivateNew(filepath.Join(stateDir, redemptionJournalName), mustJSON(journal)); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateNew(credentialPath, []byte(credential+"\n")); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"recover", "--state-dir", stateDir, "--credential-file", credentialPath}, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("recover code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if _, err := os.Lstat(filepath.Join(stateDir, redemptionJournalName)); !os.IsNotExist(err) {
		t.Fatalf("recovery journal remains: %v", err)
	}
}

func TestRecoverRejectsADifferentCredentialDestination(t *testing.T) {
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
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
	material := writeTestMaterial(t, `{"enrollment_id":"33333333-3333-4333-8333-333333333333","client_binding":"`+identity.ClientBinding+`","code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)
	credentialA := filepath.Join(stateDir, "credential-a")
	if code := run([]string{"redeem", "--state-dir", stateDir, "--enrollment-file", material, "--credential-file", credentialA}, io.Discard, io.Discard); code != 1 {
		t.Fatalf("initial redeem code=%d", code)
	}
	credentialB := filepath.Join(stateDir, "credential-b")
	var stderr bytes.Buffer
	if code := run([]string{"recover", "--state-dir", stateDir, "--credential-file", credentialB}, io.Discard, &stderr); code != 2 || !strings.Contains(stderr.String(), "bound to a different credential destination") {
		t.Fatalf("recover code=%d stderr=%q", code, stderr.String())
	}
	if calls != 1 {
		t.Fatalf("recovery contacted origin after destination mismatch: %d calls", calls)
	}
	if _, err := os.Lstat(filepath.Join(stateDir, redemptionJournalName)); err != nil {
		t.Fatalf("recovery journal was removed: %v", err)
	}
}

func TestRemoveJournalIfCurrentPreservesAReplacementJournal(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	if err := ensurePrivateDir(stateDir); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(stateDir, redemptionJournalName)
	old := redemptionJournal{EnrollmentID: "33333333-3333-4333-8333-333333333333", ClientBinding: "11111111-1111-4111-8111-111111111111", Code: strings.Repeat("A", 43), IdempotencyKey: "44444444-4444-4444-8444-444444444444", CredentialPath: filepath.Join(stateDir, "credential")}
	if err := writePrivateNew(journalPath, mustJSON(old)); err != nil {
		t.Fatal(err)
	}
	replacement := old
	replacement.EnrollmentID = "55555555-5555-4555-8555-555555555555"
	replacement.IdempotencyKey = "66666666-6666-4666-8666-666666666666"
	if err := writePrivateAtomic(journalPath, mustJSON(replacement)); err != nil {
		t.Fatal(err)
	}
	if err := removeJournalIfCurrent(journalPath, old); err != nil {
		t.Fatal(err)
	}
	current, err := loadJournal(journalPath)
	if err != nil || current != replacement {
		t.Fatalf("replacement journal err=%v current=%#v", err, current)
	}
}

func TestRemoveJournalIfCurrentToleratesConcurrentRemoval(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	if err := ensurePrivateDir(stateDir); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(stateDir, redemptionJournalName)
	journal := redemptionJournal{EnrollmentID: "33333333-3333-4333-8333-333333333333", ClientBinding: "11111111-1111-4111-8111-111111111111", Code: strings.Repeat("A", 43), IdempotencyKey: "44444444-4444-4444-8444-444444444444", CredentialPath: filepath.Join(stateDir, "credential")}
	if err := writePrivateNew(journalPath, mustJSON(journal)); err != nil {
		t.Fatal(err)
	}
	original := removeJournalFile
	removeJournalFile = func(string) error { return os.ErrNotExist }
	t.Cleanup(func() { removeJournalFile = original })
	if err := removeJournalIfCurrent(journalPath, journal); err != nil {
		t.Fatalf("concurrent journal removal reported as failure: %v", err)
	}
}

func TestRedeemSendsProtectedAccessServiceToken(t *testing.T) {
	credential := "22222222-2222-4222-8222-222222222222." + strings.Repeat("A", 43)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("CF-Access-Client-Id") != "access-id" || r.Header.Get("CF-Access-Client-Secret") != "access-secret" {
			t.Fatalf("Access headers were missing: %#v", r.Header)
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"principal_id":"11111111-1111-4111-8111-111111111111","lookup_id":"22222222-2222-4222-8222-222222222222","credential":"`+credential+`","generation":1}`)
	}))
	defer server.Close()
	original := newEnrollmentHTTPClient
	newEnrollmentHTTPClient = func() *http.Client { return server.Client() }
	t.Cleanup(func() { newEnrollmentHTTPClient = original })
	stateDir := filepath.Join(t.TempDir(), "state")
	var prepared publicEnrollment
	var preparedOut bytes.Buffer
	if code := run([]string{"prepare", "--origin", server.URL, "--state-dir", stateDir}, &preparedOut, io.Discard); code != 0 || json.Unmarshal(preparedOut.Bytes(), &prepared) != nil {
		t.Fatalf("prepare code=%d output=%q", code, preparedOut.String())
	}
	material := writeTestMaterial(t, `{"enrollment_id":"33333333-3333-4333-8333-333333333333","client_binding":"`+prepared.ClientBinding+`","code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)
	accessFile := writeTestMaterial(t, `{"client_id":"access-id","client_secret":"access-secret"}`)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"redeem", "--state-dir", stateDir, "--enrollment-file", material, "--credential-file", filepath.Join(stateDir, "credential"), "--access-file", accessFile}, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("redeem code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestEnsurePrivateDirCreatesNestedStateDirectory(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "first", "second", "state")
	if err := ensurePrivateDir(stateDir); err != nil {
		t.Fatalf("ensure private state directory: %v", err)
	}
	if err := privateDir(stateDir); err != nil {
		t.Fatalf("created state directory is not private: %v", err)
	}
}

func TestSafeStateChildRejectsNonCanonicalTraversal(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if !safeStateChild(directory, filepath.Join(directory, "credential")) {
		t.Fatal("direct state child was rejected")
	}
	nonCanonical := directory + string(filepath.Separator) + "link" + string(filepath.Separator) + ".." + string(filepath.Separator) + "credential"
	if safeStateChild(directory, nonCanonical) {
		t.Fatal("non-canonical child path was accepted")
	}
}

func TestEnrollmentMaterialRejectsDuplicateOrUnknownFields(t *testing.T) {
	for name, raw := range map[string]string{
		"duplicate": `{"enrollment_id":"33333333-3333-4333-8333-333333333333","enrollment_id":"33333333-3333-4333-8333-333333333333","client_binding":"44444444-4444-4444-8444-444444444444","code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`,
		"unknown":   `{"enrollment_id":"33333333-3333-4333-8333-333333333333","client_binding":"44444444-4444-4444-8444-444444444444","code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","origin":"https://attacker.test"}`,
	} {
		path := writeTestMaterial(t, raw)
		if _, err := loadMaterial(path); err == nil {
			t.Fatalf("%s material was accepted", name)
		}
	}
}

func TestEnrollmentMaterialAcceptsStrictAdminEnvelope(t *testing.T) {
	path := writeTestMaterial(t, `{"enrollment_id":"33333333-3333-4333-8333-333333333333","client_binding":"44444444-4444-4444-8444-444444444444","code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","expires_at":"2030-01-02T03:04:05Z","preview_hash":"0000000000000000000000000000000000000000000000000000000000000000","grants":[{"scope":"installation","capability":"project.create"}]}`)
	material, err := loadMaterial(path)
	if err != nil || material.EnrollmentID != "33333333-3333-4333-8333-333333333333" {
		t.Fatalf("admin envelope material=%#v err=%v", material, err)
	}
	invalid := writeTestMaterial(t, `{"enrollment_id":"33333333-3333-4333-8333-333333333333","client_binding":"44444444-4444-4444-8444-444444444444","code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","expires_at":"2030-01-02T03:04:05Z","preview_hash":"0000000000000000000000000000000000000000000000000000000000000000","grants":[{"scope":"installation","capability":"project.create","ignored":true}]}`)
	if _, err := loadMaterial(invalid); err == nil {
		t.Fatal("admin envelope accepted an unknown grant field")
	}
	longGrants := "[" + strings.TrimSuffix(strings.Repeat(`{"scope":"installation","capability":"project.create"},`, 100), ",") + "]"
	longEnvelope := `{"enrollment_id":"33333333-3333-4333-8333-333333333333","client_binding":"44444444-4444-4444-8444-444444444444","code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","expires_at":"2030-01-02T03:04:05Z","preview_hash":"0000000000000000000000000000000000000000000000000000000000000000","grants":` + longGrants + `}`
	if len(longEnvelope) <= maxEnrollmentFile {
		t.Fatalf("long enrollment material=%d bytes", len(longEnvelope))
	}
	if _, err := loadMaterial(writeTestMaterial(t, longEnvelope)); err != nil {
		t.Fatalf("large admin envelope rejected: %v", err)
	}
}

func TestEnrollmentMaterialAcceptsExactServiceAdminOutput(t *testing.T) {
	grants, previewHash, err := punaropostgres.PreviewServiceEnrollment()
	if err != nil {
		t.Fatal(err)
	}
	preview := struct {
		Template    string                     `json:"template"`
		PreviewHash string                     `json:"preview_hash"`
		Grants      []punaropostgres.GrantSpec `json:"grants"`
	}{Template: "service", PreviewHash: previewHash, Grants: grants}
	pending := punaropostgres.PendingEnrollment{ID: "33333333-3333-4333-8333-333333333333", ClientBinding: "44444444-4444-4444-8444-444444444444", Code: strings.Repeat("A", 43), ExpiresAt: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC), PreviewHash: previewHash, Grants: grants}
	previewRaw, err := json.MarshalIndent(preview, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	pendingRaw, err := json.MarshalIndent(pending, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	material, err := loadMaterial(writeTestMaterial(t, string(append(append(previewRaw, '\n'), append(pendingRaw, '\n')...))))
	if err != nil || material.EnrollmentID != pending.ID {
		t.Fatalf("service admin output material=%#v err=%v", material, err)
	}
}

func TestEnrollmentMaterialAcceptsExactLegacyServiceAdminOutput(t *testing.T) {
	legacyPrincipalID := "55555555-5555-4555-8555-555555555555"
	grants, previewHash, err := punaropostgres.PreviewServiceEnrollmentForLegacy(legacyPrincipalID)
	if err != nil {
		t.Fatal(err)
	}
	preview := struct {
		Template          string                     `json:"template"`
		LegacyPrincipalID string                     `json:"legacy_principal_id"`
		PreviewHash       string                     `json:"preview_hash"`
		Grants            []punaropostgres.GrantSpec `json:"grants"`
	}{Template: "service", LegacyPrincipalID: legacyPrincipalID, PreviewHash: previewHash, Grants: grants}
	pending := punaropostgres.PendingEnrollment{ID: "33333333-3333-4333-8333-333333333333", ClientBinding: "44444444-4444-4444-8444-444444444444", Code: strings.Repeat("A", 43), ExpiresAt: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC), PreviewHash: previewHash, Grants: grants}
	previewRaw, err := json.MarshalIndent(preview, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	pendingRaw, err := json.MarshalIndent(pending, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	material, err := loadMaterial(writeTestMaterial(t, string(append(append(previewRaw, '\n'), append(pendingRaw, '\n')...))))
	if err != nil || material.EnrollmentID != pending.ID {
		t.Fatalf("legacy service admin output material=%#v err=%v", material, err)
	}
	preview.LegacyPrincipalID = "not-a-principal"
	previewRaw, err = json.MarshalIndent(preview, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadMaterial(writeTestMaterial(t, string(append(append(previewRaw, '\n'), append(pendingRaw, '\n')...)))); err == nil {
		t.Fatal("legacy service admin output accepted an invalid legacy principal")
	}
	preview.LegacyPrincipalID = "66666666-6666-4666-8666-666666666666"
	previewRaw, err = json.MarshalIndent(preview, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadMaterial(writeTestMaterial(t, string(append(append(previewRaw, '\n'), append(pendingRaw, '\n')...)))); err == nil {
		t.Fatal("legacy service admin output accepted a legacy principal not bound by preview_hash")
	}
}

func TestEnrollmentMaterialAcceptsExactLegacyTrustedAgentAdminOutput(t *testing.T) {
	legacyPrincipalID := "55555555-5555-4555-8555-555555555555"
	projectID := "77777777-7777-4777-8777-777777777777"
	grants, previewHash, err := punaropostgres.PreviewTrustedAgentEnrollmentForLegacy([]string{projectID}, false, legacyPrincipalID)
	if err != nil {
		t.Fatal(err)
	}
	preview := struct {
		Template          string                     `json:"template"`
		LegacyPrincipalID string                     `json:"legacy_principal_id"`
		PreviewHash       string                     `json:"preview_hash"`
		Grants            []punaropostgres.GrantSpec `json:"grants"`
	}{Template: "trusted-agent", LegacyPrincipalID: legacyPrincipalID, PreviewHash: previewHash, Grants: grants}
	pending := punaropostgres.PendingEnrollment{ID: "33333333-3333-4333-8333-333333333333", ClientBinding: "44444444-4444-4444-8444-444444444444", Code: strings.Repeat("A", 43), ExpiresAt: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC), PreviewHash: previewHash, Grants: grants}
	previewRaw, err := json.MarshalIndent(preview, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	pendingRaw, err := json.MarshalIndent(pending, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	material, err := loadMaterial(writeTestMaterial(t, string(append(append(previewRaw, '\n'), append(pendingRaw, '\n')...))))
	if err != nil || material.EnrollmentID != pending.ID {
		t.Fatalf("legacy trusted-agent admin output material=%#v err=%v", material, err)
	}
}

func TestProtectMaterialTightensTransferredFileWithoutReadingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrollment-material.json")
	want := []byte("private enrollment material")
	if err := os.WriteFile(path, want, 0o644); err != nil { // #nosec G306 -- deliberately models a transferred file with an inherited broad mode.
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"protect-material", "--file", path}, &stdout, &stderr); code != 0 || stdout.String() != "enrollment material protected\n" || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if _, err := readPrivate(path, maxEnrollmentMaterial); err != nil {
		t.Fatalf("protected material remained unreadable: %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, want) { // #nosec G304 -- fixed child of t.TempDir verifies that permission repair did not rewrite contents.
		t.Fatalf("protected material content changed: got=%q err=%v", got, err)
	}
}

func TestEnrollmentMaterialAcceptsExactAdminOutputAtProjectLimit(t *testing.T) {
	projectIDs := make([]string, 100)
	for i := range projectIDs {
		projectIDs[i] = fmt.Sprintf("%08d-0000-4000-8000-000000000000", i+1)
	}
	grants, previewHash, err := punaropostgres.PreviewTrustedAgentEnrollment(projectIDs, false)
	if err != nil {
		t.Fatal(err)
	}
	preview := struct {
		Template    string                     `json:"template"`
		PreviewHash string                     `json:"preview_hash"`
		Grants      []punaropostgres.GrantSpec `json:"grants"`
	}{Template: "trusted-agent", PreviewHash: previewHash, Grants: grants}
	pending := punaropostgres.PendingEnrollment{ID: "33333333-3333-4333-8333-333333333333", ClientBinding: "44444444-4444-4444-8444-444444444444", Code: strings.Repeat("A", 43), ExpiresAt: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC), PreviewHash: previewHash, Grants: grants}
	previewRaw, err := json.MarshalIndent(preview, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	pendingRaw, err := json.MarshalIndent(pending, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	output := append(append(previewRaw, '\n'), append(pendingRaw, '\n')...)
	if len(output) <= 64*1024 || len(output) > maxEnrollmentMaterial {
		t.Fatalf("bounded admin output has unexpected size: %d", len(output))
	}
	material, err := loadMaterial(writeTestMaterial(t, string(output)))
	if err != nil || material.EnrollmentID != pending.ID {
		t.Fatalf("exact admin output material=%#v err=%v", material, err)
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
	response, err = decodeRedemptionResponse([]byte(`{"client_id":"33333333-3333-4333-8333-333333333333","machine_id":"laptop-a","endpoint_prefix":"agent/laptop-a/","principal_id":"11111111-1111-4111-8111-111111111111","lookup_id":"22222222-2222-4222-8222-222222222222","credential":"22222222-2222-4222-8222-222222222222.` + strings.Repeat("A", 43) + `","generation":1}`))
	if err != nil || response.ClientID == "" || response.MachineID != "laptop-a" || response.EndpointPrefix != "agent/laptop-a/" {
		t.Fatalf("lifecycle response err=%v response=%#v", err, response)
	}
	for _, malformed := range []string{
		`{"client_id":"33333333-3333-4333-8333-333333333333","principal_id":"11111111-1111-4111-8111-111111111111","lookup_id":"22222222-2222-4222-8222-222222222222","credential":"22222222-2222-4222-8222-222222222222.` + strings.Repeat("A", 43) + `","generation":1}`,
		`{"client_id":"33333333-3333-4333-8333-333333333333","machine_id":"Laptop","endpoint_prefix":"agent/Laptop/","principal_id":"11111111-1111-4111-8111-111111111111","lookup_id":"22222222-2222-4222-8222-222222222222","credential":"22222222-2222-4222-8222-222222222222.` + strings.Repeat("A", 43) + `","generation":1}`,
	} {
		if _, err := decodeRedemptionResponse([]byte(malformed)); err == nil {
			t.Fatalf("malformed lifecycle response was accepted: %s", malformed)
		}
	}
}

func TestRejectedEnrollmentClearsRecoverySoReplacementCanProceed(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("WWW-Authenticate", "Bearer")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"unauthenticated"}`)
	}))
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
	material := writeTestMaterial(t, `{"enrollment_id":"33333333-3333-4333-8333-333333333333","client_binding":"`+identity.ClientBinding+`","code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)
	var stderr bytes.Buffer
	if code := run([]string{"redeem", "--state-dir", stateDir, "--enrollment-file", material, "--credential-file", filepath.Join(stateDir, "credential")}, io.Discard, &stderr); code != 1 || !strings.Contains(stderr.String(), "request a new enrollment") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if _, err := os.Lstat(filepath.Join(stateDir, redemptionJournalName)); !os.IsNotExist(err) {
		t.Fatalf("rejected enrollment recovery was retained: %v", err)
	}
}

func TestUnverifiedUnauthorizedRetainsRecoveryJournal(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"unauthenticated"}`)
	}))
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
	material := writeTestMaterial(t, `{"enrollment_id":"33333333-3333-4333-8333-333333333333","client_binding":"`+identity.ClientBinding+`","code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)
	var stderr bytes.Buffer
	if code := run([]string{"redeem", "--state-dir", stateDir, "--enrollment-file", material, "--credential-file", filepath.Join(stateDir, "credential")}, io.Discard, &stderr); code != 1 || !strings.Contains(stderr.String(), "retry") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if _, err := os.Lstat(filepath.Join(stateDir, redemptionJournalName)); err != nil {
		t.Fatalf("unverified unauthorized response removed recovery journal: %v", err)
	}
}

func TestAccessDenialRetainsRecoveryJournal(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
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
			material := writeTestMaterial(t, `{"enrollment_id":"33333333-3333-4333-8333-333333333333","client_binding":"`+identity.ClientBinding+`","code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)
			var stderr bytes.Buffer
			if code := run([]string{"redeem", "--state-dir", stateDir, "--enrollment-file", material, "--credential-file", filepath.Join(stateDir, "credential")}, io.Discard, &stderr); code != 1 || !strings.Contains(stderr.String(), "retry") {
				t.Fatalf("code=%d stderr=%q", code, stderr.String())
			}
			if _, err := os.Lstat(filepath.Join(stateDir, redemptionJournalName)); err != nil {
				t.Fatalf("Access denial removed recovery journal: %v", err)
			}
		})
	}
}

func TestRecoverRejectsUnrelatedExistingCredentialBeforeContactingOrigin(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("recovery contacted the origin before rejecting an unrelated credential file")
	}))
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
	journal := redemptionJournal{EnrollmentID: "33333333-3333-4333-8333-333333333333", ClientBinding: identity.ClientBinding, Code: strings.Repeat("A", 43), IdempotencyKey: "44444444-4444-4444-8444-444444444444", CredentialPath: filepath.Join(stateDir, identityFileName)}
	if err := writePrivateNew(filepath.Join(stateDir, redemptionJournalName), mustJSON(journal)); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if code := run([]string{"recover", "--state-dir", stateDir, "--credential-file", filepath.Join(stateDir, identityFileName)}, io.Discard, &stderr); code != 2 || !strings.Contains(stderr.String(), "private credential destination is unavailable") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}

func writeTestMaterial(t *testing.T, raw string) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "material")
	if err := ensurePrivateDir(directory); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "material.json")
	if err := writePrivateNew(path, []byte(raw)); err != nil {
		t.Fatal(err)
	}
	return path
}
