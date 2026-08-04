// punaro-enroll creates and redeems a device-bound client enrollment without
// accepting secret material in command arguments or environment variables.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rock3r/punaro/internal/adapter"
	"github.com/rock3r/punaro/internal/clientidentity"
)

const (
	identityFileName      = "client-identity.json"
	redemptionJournalName = "redemption-recovery.json"
	maxEnrollmentFile     = 4096
	maxEnrollmentMaterial = 64 * 1024
)

var newEnrollmentHTTPClient = func() *http.Client {
	return &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

type publicEnrollment struct {
	Origin        string `json:"origin"`
	ClientBinding string `json:"client_binding"`
}

type enrollmentMaterial struct {
	EnrollmentID  string `json:"enrollment_id"`
	ClientBinding string `json:"client_binding"`
	Code          string `json:"code"`
}

type enrollmentEnvelope struct {
	EnrollmentID  string            `json:"enrollment_id"`
	ClientBinding string            `json:"client_binding"`
	Code          string            `json:"code"`
	ExpiresAt     time.Time         `json:"expires_at"`
	PreviewHash   string            `json:"preview_hash"`
	Grants        []json.RawMessage `json:"grants"`
}

type enrollmentGrantPreview struct {
	Scope      string `json:"scope"`
	ProjectID  string `json:"project_id"`
	Capability string `json:"capability"`
}

type accessMaterial struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type redemptionJournal struct {
	EnrollmentID   string `json:"enrollment_id"`
	ClientBinding  string `json:"client_binding"`
	Code           string `json:"code"`
	IdempotencyKey string `json:"idempotency_key"`
	Credential     string `json:"credential,omitempty"`
}

type redemptionResponse struct {
	PrincipalID string    `json:"principal_id"`
	LookupID    string    `json:"lookup_id"`
	Credential  string    `json:"credential"`
	Generation  int64     `json:"generation"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "usage: punaro-enroll prepare|redeem|recover")
		return 2
	}
	switch args[0] {
	case "prepare":
		return runPrepare(args[1:], stdout, stderr)
	case "redeem":
		return runRedeem(args[1:], stdout, stderr, false)
	case "recover":
		return runRedeem(args[1:], stdout, stderr, true)
	default:
		_, _ = fmt.Fprintln(stderr, "usage: punaro-enroll prepare|redeem|recover")
		return 2
	}
}

func runPrepare(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("prepare", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	origin := flags.String("origin", "", "fixed Punaro HTTPS origin")
	stateDir := flags.String("state-dir", "", "absolute private enrollment state directory")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *stateDir == "" {
		return invalid(stderr)
	}
	canonical, ok := clientidentity.CanonicalOrigin(*origin)
	if !ok || !safeStateDir(*stateDir) || ensurePrivateDir(*stateDir) != nil {
		return enrollmentError(stderr, "state preparation failed", 2)
	}
	identityPath := filepath.Join(*stateDir, identityFileName)
	state, err := loadIdentity(identityPath)
	if errors.Is(err, os.ErrNotExist) {
		binding := uuid.NewString()
		state = clientidentity.State{Version: clientidentity.Version, Origin: canonical, ClientBinding: binding}
		if err := writePrivateNew(identityPath, mustEncodeIdentity(state)); err != nil {
			return enrollmentError(stderr, "state preparation failed", 2)
		}
	} else if err != nil || state.Match(canonical, state.ClientBinding, "") != nil || state.LegacyMachineID != "" {
		return enrollmentError(stderr, "state preparation failed", 2)
	}
	return writeJSON(stdout, publicEnrollment{Origin: state.Origin, ClientBinding: state.ClientBinding})
}

func runRedeem(args []string, stdout, stderr io.Writer, recoveryOnly bool) int {
	flags := flag.NewFlagSet("redeem", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	stateDir := flags.String("state-dir", "", "absolute private enrollment state directory")
	materialPath := flags.String("enrollment-file", "", "absolute protected enrollment material file")
	credentialPath := flags.String("credential-file", "", "absolute private credential destination under state-dir")
	accessPath := flags.String("access-file", "", "absolute protected Cloudflare Access service-token file")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *stateDir == "" || *credentialPath == "" || (!recoveryOnly && *materialPath == "") || (recoveryOnly && *materialPath != "") {
		return invalid(stderr)
	}
	if !safeStateDir(*stateDir) || !safeStateChild(*stateDir, *credentialPath) || filepath.Base(*credentialPath) == redemptionJournalName || privateDir(*stateDir) != nil {
		return enrollmentError(stderr, "private enrollment state is unsafe", 2)
	}
	state, err := loadIdentity(filepath.Join(*stateDir, identityFileName))
	if err != nil || state.LegacyMachineID != "" {
		return enrollmentError(stderr, "private enrollment state is unsafe", 2)
	}
	accessToken, err := loadAccessToken(*accessPath)
	if err != nil {
		return enrollmentError(stderr, "Access admission material is invalid", 2)
	}
	journalPath := filepath.Join(*stateDir, redemptionJournalName)
	journal, journalErr := loadJournal(journalPath)
	if recoveryOnly {
		if journalErr != nil {
			return enrollmentError(stderr, "no recoverable enrollment was found", 2)
		}
		if err := preflightCredentialDestination(*credentialPath, journal.Credential); err != nil {
			return enrollmentError(stderr, "private credential destination is unavailable", 2)
		}
	} else {
		material, err := loadMaterial(*materialPath)
		if err != nil {
			return enrollmentError(stderr, "enrollment material is invalid", 2)
		}
		if material.ClientBinding != state.ClientBinding {
			return enrollmentError(stderr, "enrollment material does not match this device", 2)
		}
		switch {
		case journalErr == nil:
			if journal.EnrollmentID != material.EnrollmentID || journal.ClientBinding != material.ClientBinding || journal.Code != material.Code {
				return enrollmentError(stderr, "existing enrollment recovery does not match material", 2)
			}
			if err := preflightCredentialDestination(*credentialPath, journal.Credential); err != nil {
				return enrollmentError(stderr, "private credential destination is unavailable", 2)
			}
		case !errors.Is(journalErr, os.ErrNotExist):
			return enrollmentError(stderr, "private enrollment state is unsafe", 2)
		default:
			if err := preflightCredentialDestination(*credentialPath, ""); err != nil {
				return enrollmentError(stderr, "private credential destination is unavailable", 2)
			}
			key, err := uuid.NewRandom()
			if err != nil {
				return enrollmentError(stderr, "enrollment recovery could not be created", 1)
			}
			journal = redemptionJournal{EnrollmentID: material.EnrollmentID, ClientBinding: material.ClientBinding, Code: material.Code, IdempotencyKey: key.String()}
			if err := writePrivateNew(journalPath, mustJSON(journal)); err != nil {
				return enrollmentError(stderr, "enrollment recovery could not be created", 1)
			}
		}
	}
	if journal.ClientBinding != state.ClientBinding || !validJournal(journal) {
		return enrollmentError(stderr, "private enrollment state is unsafe", 2)
	}
	if err := syncPrivateDirectory(*stateDir); err != nil {
		return enrollmentError(stderr, "enrollment recovery could not be made durable; retry this command", 1)
	}
	response, result := postRedemption(state.Origin, journal, accessToken)
	if result == redemptionRejected {
		if err := removePrivate(journalPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return enrollmentError(stderr, "enrollment was rejected; remove the private recovery file before requesting a new enrollment", 1)
		}
		return enrollmentError(stderr, "enrollment was rejected; request a new enrollment", 1)
	}
	if result != redemptionSucceeded {
		return enrollmentError(stderr, "enrollment is temporarily unavailable; retry this command", 1)
	}
	if journal.Credential != "" && journal.Credential != response.Credential {
		return enrollmentError(stderr, "enrollment is temporarily unavailable; retry this command", 1)
	}
	journal.Credential = response.Credential
	if err := writePrivateAtomic(journalPath, mustJSON(journal)); err != nil {
		return enrollmentError(stderr, "enrollment recovery could not be made durable; retry this command", 1)
	}
	if err := writeCredential(*credentialPath, response.Credential); err != nil {
		return enrollmentError(stderr, "credential persistence failed; retry this command", 1)
	}
	if err := removePrivate(journalPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return enrollmentError(stderr, "credential persisted; remove the private recovery file before continuing", 1)
	}
	return writeJSON(stdout, struct {
		Origin     string `json:"origin"`
		LookupID   string `json:"lookup_id"`
		Generation int64  `json:"generation"`
	}{Origin: state.Origin, LookupID: response.LookupID, Generation: response.Generation})
}

func preflightCredentialDestination(path, expectedCredential string) error {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if expectedCredential != "" {
		// A matching credential can already be present if the process crashed
		// after persistence and before removing the journal. The journal stores
		// the server-confirmed value before it publishes the credential, so an
		// unrelated protected state file cannot be mistaken for that credential.
		raw, err := readPrivate(path, maxEnrollmentFile)
		if err != nil || string(raw) != expectedCredential+"\n" {
			return errors.New("credential destination exists")
		}
		return nil
	}
	// A credential path is single-use. Treat every existing entry, including a
	// regular private credential, as unavailable before the first redemption so
	// no server principal is minted when the response cannot be persisted.
	return errors.New("credential destination exists")
}

func invalid(stderr io.Writer) int { return enrollmentError(stderr, "invalid arguments", 2) }
func enrollmentError(stderr io.Writer, message string, code int) int {
	_, _ = fmt.Fprintf(stderr, "punaro-enroll: %s\n", message)
	return code
}

func writeJSON(destination io.Writer, value any) int {
	if err := json.NewEncoder(destination).Encode(value); err != nil {
		return 1
	}
	return 0
}

func mustEncodeIdentity(value clientidentity.State) []byte {
	raw, err := value.Encode()
	if err != nil {
		return nil
	}
	return append(raw, '\n')
}

func mustJSON(value any) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	return append(raw, '\n')
}

func loadIdentity(path string) (clientidentity.State, error) {
	raw, err := readPrivate(path, maxEnrollmentFile)
	if err != nil {
		return clientidentity.State{}, err
	}
	return clientidentity.Parse(raw)
}

func loadMaterial(path string) (enrollmentMaterial, error) {
	raw, err := readPrivate(path, maxEnrollmentMaterial)
	if err != nil {
		return enrollmentMaterial{}, err
	}
	var value enrollmentMaterial
	if err := decodeExact(raw, &value, "enrollment_id", "client_binding", "code"); err == nil && validMaterial(value) {
		return value, nil
	}
	var envelope enrollmentEnvelope
	if err := decodeExact(raw, &envelope, "enrollment_id", "client_binding", "code", "expires_at", "preview_hash", "grants"); err != nil || !validMaterial(enrollmentMaterial{EnrollmentID: envelope.EnrollmentID, ClientBinding: envelope.ClientBinding, Code: envelope.Code}) || envelope.ExpiresAt.IsZero() || !validPreviewHash(envelope.PreviewHash) || !validGrantPreview(envelope.Grants) {
		return enrollmentMaterial{}, errors.New("invalid enrollment material")
	}
	return enrollmentMaterial{EnrollmentID: envelope.EnrollmentID, ClientBinding: envelope.ClientBinding, Code: envelope.Code}, nil
}

func validPreviewHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}

func validGrantPreview(rawGrants []json.RawMessage) bool {
	if len(rawGrants) == 0 {
		return false
	}
	for _, raw := range rawGrants {
		var grant enrollmentGrantPreview
		if err := decodeFields(raw, &grant, []string{"scope", "capability"}, []string{"project_id"}); err != nil || !validGrantPreviewItem(grant) {
			return false
		}
	}
	return true
}

func validGrantPreviewItem(grant enrollmentGrantPreview) bool {
	if grant.Capability == "" || len(grant.Capability) > 128 || strings.ContainsAny(grant.Capability, " \t\r\n") {
		return false
	}
	switch grant.Scope {
	case "installation", "all_projects":
		return grant.ProjectID == ""
	case "project":
		return validUUID(grant.ProjectID)
	default:
		return false
	}
}

func loadAccessToken(path string) (adapter.AccessServiceToken, error) {
	if path == "" {
		return adapter.AccessServiceToken{}, nil
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return adapter.AccessServiceToken{}, errors.New("unsafe Access material")
	}
	raw, err := readPrivate(path, maxEnrollmentFile)
	if err != nil {
		return adapter.AccessServiceToken{}, err
	}
	var value accessMaterial
	if err := decodeExact(raw, &value, "client_id", "client_secret"); err != nil || !validAccessValue(value.ClientID) || !validAccessValue(value.ClientSecret) {
		return adapter.AccessServiceToken{}, errors.New("invalid Access material")
	}
	return adapter.AccessServiceToken{ClientID: value.ClientID, ClientSecret: value.ClientSecret}, nil
}

func validAccessValue(value string) bool {
	return value != "" && !strings.ContainsAny(value, " \t\r\n")
}

func loadJournal(path string) (redemptionJournal, error) {
	raw, err := readPrivate(path, maxEnrollmentFile)
	if err != nil {
		return redemptionJournal{}, err
	}
	var value redemptionJournal
	if err := decodeFields(raw, &value, []string{"enrollment_id", "client_binding", "code", "idempotency_key"}, []string{"credential"}); err != nil || !validJournal(value) {
		return redemptionJournal{}, errors.New("invalid recovery journal")
	}
	return value, nil
}

func validMaterial(value enrollmentMaterial) bool {
	return validUUID(value.EnrollmentID) && validUUID(value.ClientBinding) && validCode(value.Code)
}
func validJournal(value redemptionJournal) bool {
	return validMaterial(enrollmentMaterial{EnrollmentID: value.EnrollmentID, ClientBinding: value.ClientBinding, Code: value.Code}) && validUUID(value.IdempotencyKey) && (value.Credential == "" || validStoredCredential(value.Credential))
}
func validUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value
}
func validCode(value string) bool {
	return len(value) == 43 && !strings.ContainsAny(value, " \t\r\n")
}

func validCredential(value, lookupID string) bool {
	prefix, secret, found := strings.Cut(value, ".")
	if !found || prefix != lookupID || !validUUID(prefix) || strings.ContainsAny(secret, " \t\r\n") {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(secret)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == secret
}

func validStoredCredential(value string) bool {
	prefix, secret, found := strings.Cut(value, ".")
	if !found || !validUUID(prefix) || strings.ContainsAny(secret, " \t\r\n") {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(secret)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == secret
}

func decodeExact(raw []byte, target any, fields ...string) error {
	return decodeFields(raw, target, fields, nil)
}

func decodeFields(raw []byte, target any, required, optional []string) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("invalid object")
	}
	expected := make(map[string]bool, len(required))
	allowed := make(map[string]bool, len(required)+len(optional))
	seen := make(map[string]bool, len(required)+len(optional))
	for _, field := range required {
		expected[field] = false
		allowed[field] = true
	}
	for _, field := range optional {
		allowed[field] = true
	}
	for decoder.More() {
		token, err := decoder.Token()
		field, ok := token.(string)
		if err != nil || !ok {
			return errors.New("invalid object")
		}
		if _, known := allowed[field]; !known {
			return errors.New("invalid object")
		}
		if seen[field] {
			return errors.New("invalid object")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return errors.New("invalid object")
		}
		seen[field] = true
		if _, required := expected[field]; required {
			expected[field] = true
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("invalid object")
	}
	for _, present := range expected {
		if !present {
			return errors.New("incomplete object")
		}
	}
	if json.Unmarshal(raw, target) != nil {
		return errors.New("invalid object")
	}
	return nil
}

func decodeRedemptionResponse(raw []byte) (redemptionResponse, error) {
	var value redemptionResponse
	if err := decodeFields(raw, &value, []string{"principal_id", "lookup_id", "credential", "generation"}, []string{"expires_at"}); err != nil || !validUUID(value.PrincipalID) || !validUUID(value.LookupID) || !validCredential(value.Credential, value.LookupID) || value.Generation < 1 {
		return redemptionResponse{}, errors.New("invalid redemption response")
	}
	return value, nil
}

type redemptionResult uint8

const (
	redemptionUnavailable redemptionResult = iota
	redemptionRejected
	redemptionSucceeded
)

func postRedemption(origin string, journal redemptionJournal, accessToken adapter.AccessServiceToken) (redemptionResponse, redemptionResult) {
	body, err := json.Marshal(journal)
	if err != nil {
		return redemptionResponse{}, redemptionUnavailable
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, origin+"/v1/enrollments/redeem", bytes.NewReader(body))
	if err != nil {
		return redemptionResponse{}, redemptionUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	client, err := adapter.OpenAccessSession(context.Background(), origin, newEnrollmentHTTPClient(), accessToken)
	if err != nil {
		return redemptionResponse{}, redemptionUnavailable
	}
	if accessToken.ClientID != "" {
		request.Header.Set("CF-Access-Client-Id", accessToken.ClientID)
		request.Header.Set("CF-Access-Client-Secret", accessToken.ClientSecret)
	}
	clientCopy := *client
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := clientCopy.Do(request)
	if err != nil {
		return redemptionResponse{}, redemptionUnavailable
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode == http.StatusBadRequest || (response.StatusCode == http.StatusUnauthorized && response.Header.Get("WWW-Authenticate") == "Bearer" && responseDeclaresUnauthenticated(response.Body)) {
		return redemptionResponse{}, redemptionRejected
	}
	if response.StatusCode != http.StatusCreated || response.Header.Get("Cache-Control") != "no-store" {
		return redemptionResponse{}, redemptionUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxEnrollmentFile+1))
	if err != nil || len(raw) > maxEnrollmentFile {
		return redemptionResponse{}, redemptionUnavailable
	}
	value, err := decodeRedemptionResponse(raw)
	if err != nil {
		return redemptionResponse{}, redemptionUnavailable
	}
	return value, redemptionSucceeded
}

func responseDeclaresUnauthenticated(body io.Reader) bool {
	raw, err := io.ReadAll(io.LimitReader(body, 1025))
	if err != nil || len(raw) > 1024 {
		return false
	}
	var value struct {
		Error string `json:"error"`
	}
	return decodeExact(raw, &value, "error") == nil && value.Error == "unauthenticated"
}
