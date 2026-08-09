package main

import (
	"bytes"
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
