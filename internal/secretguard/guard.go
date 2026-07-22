// Package secretguard provides the single deterministic content guard used by
// canonical memory writers and future ingestion/derived-content paths.
package secretguard

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// RuleVersion changes whenever detection or accepted-reference semantics change.
	RuleVersion int64 = 1

	// RulePrivateKey identifies a private-key envelope finding.
	RulePrivateKey = "private-key"
	// RuleBearerToken identifies a supported bearer-token family finding.
	RuleBearerToken = "bearer-token"
	// RuleCredentialAssignment identifies a resolved credential assignment.
	RuleCredentialAssignment = "credential-assignment" // #nosec G101 -- content-free detector rule ID, not a credential.
	// RuleSensitiveField identifies a resolved value in a credential-named field.
	RuleSensitiveField = "sensitive-field"
)

var (
	privateKeyPattern = regexp.MustCompile(`-----BEGIN (?:PGP PRIVATE KEY BLOCK|(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----`)
	bearerPatterns    = []*regexp.Regexp{
		regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`),
		regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`),
		regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{20,}\b`),
		regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}\b`),
		regexp.MustCompile(`\b[0-9]{6,12}:[A-Za-z0-9_-]{30,}\b`),
		regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`),
	}
	credentialAssignmentPattern = regexp.MustCompile(`(?i)(?:password|passwd|secret|token|api[_-]?key|private[_-]?key)\s*[:=]\s*([^\s,;]+)`)
	environmentReferencePattern = regexp.MustCompile(`^(?:\$\{[A-Z][A-Z0-9_]{2,}\}|\$[A-Z][A-Z0-9_]{2,})$`)
	environmentNamePattern      = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,}$`)
	opReferencePattern          = regexp.MustCompile(`^op://[^/\s]+/[^/\s]+/(?:[^/\s]+/)?[^/\s]+$`)
	sensitiveFieldMarkers       = []string{"password", "passwd", "secret", "token", "apikey", "privatekey", "credential"}
	acceptedPlaceholders        = []string{"redacted", "placeholder", "changeme", "[redacted]", "<secret>", "<redacted>", "***", "xxxxx"}
)

// Finding is content-free except for the one-way exact-match fingerprint.
type Finding struct {
	RuleID      string
	FieldPath   string
	RuleVersion int64
	Fingerprint [sha256.Size]byte
}

// RejectionError is safe for client responses, logs, and metrics.
type RejectionError struct {
	Finding Finding
}

func (e RejectionError) Error() string {
	return fmt.Sprintf("memory content rejected by secret guard at %q (%s)", e.Finding.FieldPath, e.Finding.RuleID)
}

// ValidIdentity validates content-free exception coordinates.
func ValidIdentity(ruleID, fieldPath string, ruleVersion int64, fingerprint [sha256.Size]byte) bool {
	// PostgreSQL text/jsonb cannot persist U+0000; every other valid UTF-8
	// JSON Pointer coordinate remains eligible for an exact exception.
	if ruleVersion != RuleVersion || !KnownRule(ruleID) || len(fieldPath) < 1 || len(fieldPath) > 1024 || !strings.HasPrefix(fieldPath, "/") || !utf8.ValidString(fieldPath) || strings.ContainsRune(fieldPath, '\x00') || fingerprint == ([sha256.Size]byte{}) {
		return false
	}
	return true
}

// KnownRule reports whether a rule ID belongs to this exact compiled version.
func KnownRule(ruleID string) bool {
	switch ruleID {
	case RulePrivateKey, RuleBearerToken, RuleCredentialAssignment, RuleSensitiveField:
		return true
	default:
		return false
	}
}

// ScanDocument scans every string in one JSON object in deterministic path order.
func ScanDocument(document []byte) ([]Finding, error) {
	var value any
	if len(document) == 0 || json.Unmarshal(document, &value) != nil {
		return nil, errors.New("secret guard requires a valid JSON object")
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("secret guard requires a valid JSON object")
	}
	findings := make([]Finding, 0)
	scanObject(object, "", &findings)
	return findings, nil
}

func scanObject(object map[string]any, path string, findings *[]Finding) {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		scanValue(object[key], path+"/"+escapePointerToken(key), key, findings)
	}
}

func scanValue(value any, path, fieldName string, findings *[]Finding) {
	switch typed := value.(type) {
	case map[string]any:
		scanObject(typed, path, findings)
	case []any:
		for index, element := range typed {
			scanValue(element, path+"/"+strconv.Itoa(index), fieldName, findings)
		}
	case string:
		*findings = append(*findings, scanString(typed, path, fieldName)...)
	}
}

func escapePointerToken(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}

func scanString(value, path, fieldName string) []Finding {
	findings := make([]Finding, 0, 3)
	specific := false
	if privateKeyPattern.MatchString(value) {
		findings = append(findings, newFinding(RulePrivateKey, path, value))
		specific = true
	}
	for _, pattern := range bearerPatterns {
		if pattern.MatchString(value) {
			findings = append(findings, newFinding(RuleBearerToken, path, value))
			specific = true
			break
		}
	}
	for _, match := range credentialAssignmentPattern.FindAllStringSubmatch(value, -1) {
		if len(match) == 2 && !acceptedReference(match[1]) {
			findings = append(findings, newFinding(RuleCredentialAssignment, path, value))
			specific = true
			break
		}
	}
	if !specific && sensitiveField(fieldName) && !acceptedReference(value) {
		findings = append(findings, newFinding(RuleSensitiveField, path, value))
	}
	return findings
}

func newFinding(ruleID, path, value string) Finding {
	digest := sha256.New()
	_, _ = digest.Write([]byte(ruleID))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(path))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(value))
	var fingerprint [sha256.Size]byte
	copy(fingerprint[:], digest.Sum(nil))
	return Finding{RuleID: ruleID, FieldPath: path, RuleVersion: RuleVersion, Fingerprint: fingerprint}
}

func sensitiveField(fieldName string) bool {
	normalized := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToLower(r)
		}
		return -1
	}, fieldName)
	for _, marker := range sensitiveFieldMarkers {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func acceptedReference(value string) bool {
	trimmed := strings.TrimSpace(value)
	lower := strings.ToLower(trimmed)
	if environmentNamePattern.MatchString(trimmed) || environmentReferencePattern.MatchString(trimmed) || opReferencePattern.MatchString(trimmed) {
		return true
	}
	for _, placeholder := range acceptedPlaceholders {
		if lower == placeholder {
			return true
		}
	}
	return false
}

// Digest binds database readiness to this exact compiled rule contract.
func Digest() [sha256.Size]byte {
	return sha256.Sum256([]byte(strings.Join([]string{
		"version=1",
		privateKeyPattern.String(),
		bearerPatterns[0].String(), bearerPatterns[1].String(), bearerPatterns[2].String(), bearerPatterns[3].String(), bearerPatterns[4].String(), bearerPatterns[5].String(),
		credentialAssignmentPattern.String(), environmentReferencePattern.String(), environmentNamePattern.String(), opReferencePattern.String(),
		"sensitive-fields=" + strings.Join(sensitiveFieldMarkers, ","),
		"placeholders=" + strings.Join(acceptedPlaceholders, ","),
		"scan=all-distinct-specific-rules-per-string-with-sensitive-fallback",
		"assignments=inspect-all-and-reject-if-any-capture-is-not-an-exact-reference",
		"fingerprint=sha256(rule-id,nul,json-pointer,nul,complete-string-value)",
		"path=json-pointer-rfc6901",
		"accepted=exact-placeholder-or-complete-op-reference-or-complete-environment-reference",
	}, "\n")))
}
