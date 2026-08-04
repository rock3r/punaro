// punaro-enroll creates and redeems a device-bound client enrollment without
// accepting secret material in command arguments or environment variables.
package main

import (
	"bytes"
	"context"
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
	"github.com/rock3r/punaro/internal/clientidentity"
)

const (
	identityFileName      = "client-identity.json"
	redemptionJournalName = "redemption-recovery.json"
	maxEnrollmentFile     = 4096
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

type redemptionJournal struct {
	EnrollmentID   string `json:"enrollment_id"`
	ClientBinding  string `json:"client_binding"`
	Code           string `json:"code"`
	IdempotencyKey string `json:"idempotency_key"`
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
	if flags.Parse(args) != nil || flags.NArg() != 0 || *stateDir == "" || *credentialPath == "" || (!recoveryOnly && *materialPath == "") || (recoveryOnly && *materialPath != "") {
		return invalid(stderr)
	}
	if !safeStateDir(*stateDir) || !safeStateChild(*stateDir, *credentialPath) || privateDir(*stateDir) != nil {
		return enrollmentError(stderr, "private enrollment state is unsafe", 2)
	}
	state, err := loadIdentity(filepath.Join(*stateDir, identityFileName))
	if err != nil || state.LegacyMachineID != "" {
		return enrollmentError(stderr, "private enrollment state is unsafe", 2)
	}
	journalPath := filepath.Join(*stateDir, redemptionJournalName)
	journal, journalErr := loadJournal(journalPath)
	if recoveryOnly {
		if journalErr != nil {
			return enrollmentError(stderr, "no recoverable enrollment was found", 2)
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
		case !errors.Is(journalErr, os.ErrNotExist):
			return enrollmentError(stderr, "private enrollment state is unsafe", 2)
		default:
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
	response, result := postRedemption(state.Origin, journal)
	if result == redemptionRejected {
		if err := os.Remove(journalPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return enrollmentError(stderr, "enrollment was rejected; remove the private recovery file before requesting a new enrollment", 1)
		}
		return enrollmentError(stderr, "enrollment was rejected; request a new enrollment", 1)
	}
	if result != redemptionSucceeded {
		return enrollmentError(stderr, "enrollment is temporarily unavailable; retry this command", 1)
	}
	if err := writeCredential(*credentialPath, response.Credential); err != nil {
		return enrollmentError(stderr, "credential persistence failed; retry this command", 1)
	}
	if err := os.Remove(journalPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return enrollmentError(stderr, "credential persisted; remove the private recovery file before continuing", 1)
	}
	return writeJSON(stdout, struct {
		Origin     string `json:"origin"`
		LookupID   string `json:"lookup_id"`
		Generation int64  `json:"generation"`
	}{Origin: state.Origin, LookupID: response.LookupID, Generation: response.Generation})
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
	raw, err := readPrivate(path, maxEnrollmentFile)
	if err != nil {
		return enrollmentMaterial{}, err
	}
	var value enrollmentMaterial
	if err := decodeExact(raw, &value, "enrollment_id", "client_binding", "code"); err != nil || !validMaterial(value) {
		return enrollmentMaterial{}, errors.New("invalid enrollment material")
	}
	return value, nil
}

func loadJournal(path string) (redemptionJournal, error) {
	raw, err := readPrivate(path, maxEnrollmentFile)
	if err != nil {
		return redemptionJournal{}, err
	}
	var value redemptionJournal
	if err := decodeExact(raw, &value, "enrollment_id", "client_binding", "code", "idempotency_key"); err != nil || !validJournal(value) {
		return redemptionJournal{}, errors.New("invalid recovery journal")
	}
	return value, nil
}

func validMaterial(value enrollmentMaterial) bool {
	return validUUID(value.EnrollmentID) && validUUID(value.ClientBinding) && validCode(value.Code)
}
func validJournal(value redemptionJournal) bool {
	return validMaterial(enrollmentMaterial{EnrollmentID: value.EnrollmentID, ClientBinding: value.ClientBinding, Code: value.Code}) && validUUID(value.IdempotencyKey)
}
func validUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value
}
func validCode(value string) bool {
	return len(value) == 43 && !strings.ContainsAny(value, " \t\r\n")
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
	if err := decodeFields(raw, &value, []string{"principal_id", "lookup_id", "credential", "generation"}, []string{"expires_at"}); err != nil || !validUUID(value.PrincipalID) || !validUUID(value.LookupID) || value.Credential == "" || strings.ContainsAny(value.Credential, " \t\r\n") || value.Generation < 1 {
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

func postRedemption(origin string, journal redemptionJournal) (redemptionResponse, redemptionResult) {
	body, err := json.Marshal(journal)
	if err != nil {
		return redemptionResponse{}, redemptionUnavailable
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, origin+"/v1/enrollments/redeem", bytes.NewReader(body))
	if err != nil {
		return redemptionResponse{}, redemptionUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := newEnrollmentHTTPClient().Do(request)
	if err != nil {
		return redemptionResponse{}, redemptionUnavailable
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusBadRequest {
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
