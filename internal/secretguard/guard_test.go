package secretguard

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestScanDocumentDetectsHighConfidenceSecretsWithoutEcho(t *testing.T) {
	secret := "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
	findings, err := ScanDocument([]byte(`{"nested":{"token":"` + secret + `"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings=%#v", findings)
	}
	finding := findings[0]
	if finding.RuleID != RuleBearerToken || finding.FieldPath != "/nested/token" || finding.RuleVersion != RuleVersion || finding.Fingerprint == ([32]byte{}) {
		t.Fatalf("finding=%#v", finding)
	}
	rejection := RejectionError{Finding: finding}
	if strings.Contains(rejection.Error(), secret) || strings.Contains(rejection.Error(), hex.EncodeToString(finding.Fingerprint[:])) {
		t.Fatalf("rejection disclosed secret or fingerprint: %q", rejection.Error())
	}
	if rejection.Error() != `memory content rejected by secret guard at "/nested/token" (bearer-token)` {
		t.Fatalf("rejection=%q", rejection.Error())
	}
	again, err := ScanDocument([]byte(`{"nested":{"token":"` + secret + `"}}`))
	if err != nil || len(again) != 1 || again[0] != finding {
		t.Fatalf("unstable finding=%#v err=%v", again, err)
	}
}

func TestRejectionErrorEscapesHostileJSONPointerControls(t *testing.T) {
	findings, err := ScanDocument([]byte("{\"to\\nken\":\"resolved-value-123\"}"))
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings=%#v err=%v", findings, err)
	}
	if findings[0].FieldPath != "/to\nken" {
		t.Fatalf("field path=%q", findings[0].FieldPath)
	}
	message := (RejectionError{Finding: findings[0]}).Error()
	if strings.ContainsAny(message, "\n\r\t") || !strings.Contains(message, `"/to\nken"`) {
		t.Fatalf("rejection contains raw controls or lacks escaped path: %q", message)
	}
	if !ValidIdentity(findings[0].RuleID, findings[0].FieldPath, findings[0].RuleVersion, findings[0].Fingerprint) {
		t.Fatalf("scanner finding cannot be used as an exact exception: %#v", findings[0])
	}
}

func TestValidIdentityAcceptsEmptyPropertyJSONPointer(t *testing.T) {
	findings, err := ScanDocument([]byte(`{"":"-----BEGIN ` + `PRIVATE KEY-----\nmaterial"}`))
	if err != nil || len(findings) != 1 || findings[0].FieldPath != "/" {
		t.Fatalf("findings=%#v err=%v", findings, err)
	}
	if !ValidIdentity(findings[0].RuleID, findings[0].FieldPath, findings[0].RuleVersion, findings[0].Fingerprint) {
		t.Fatalf("scanner finding cannot be used as an exact exception: %#v", findings[0])
	}
}

func TestValidIdentityRejectsPostgresUnstorableNULPath(t *testing.T) {
	fingerprint := [32]byte{1}
	if ValidIdentity(RuleSensitiveField, "/to\x00ken", RuleVersion, fingerprint) {
		t.Fatal("accepted JSON Pointer containing PostgreSQL-unstorable NUL")
	}
}

func TestScanDocumentFindsPrivateKeyAndCredentialAssignment(t *testing.T) {
	document := []byte(`{
  "key":"-----BEGIN ` + `PRIVATE KEY-----\nencoded-material\n-----END PRIVATE KEY-----",
  "notes":["safe", "password = resolved-value-123"]
}`)
	findings, err := ScanDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 || findings[0].RuleID != RulePrivateKey || findings[0].FieldPath != "/key" || findings[1].RuleID != RuleCredentialAssignment || findings[1].FieldPath != "/notes/1" {
		t.Fatalf("findings=%#v", findings)
	}
}

func TestScanDocumentDetectsPGPPrivateKeyAndFineGrainedGitHubPAT(t *testing.T) {
	document := []byte(`{
  "key":"-----BEGIN PGP PRIVATE KEY BLOCK-----\nencoded-material",
  "auth":"github_pat_abcdefghijklmnopqrstuvwxyz_1234567890"
}`)
	findings, err := ScanDocument(document)
	if err != nil || len(findings) != 2 || findings[0].RuleID != RuleBearerToken || findings[1].RuleID != RulePrivateKey {
		t.Fatalf("findings=%#v err=%v", findings, err)
	}
}

func TestScanDocumentDetectsEncryptedPKCS8AtNeutralPath(t *testing.T) {
	findings, err := ScanDocument([]byte(`{"material":"-----BEGIN ` + `ENCRYPTED PRIVATE KEY-----\nencoded-material"}`))
	if err != nil || len(findings) != 1 || findings[0].RuleID != RulePrivateKey || findings[0].FieldPath != "/material" {
		t.Fatalf("findings=%#v err=%v", findings, err)
	}
}

func TestScanDocumentAllowsReferencesEnvironmentAndPlaceholders(t *testing.T) {
	document := []byte(`{
  "password":"<secret>",
  "token":"${PUNARO_AGENT_TOKEN}",
  "api_key":"PUNARO_API_KEY",
  "instructions":"Retrieve it just in time from op://Engineering/Punaro/token",
  "redacted":"[REDACTED]"
}`)
	findings, err := ScanDocument(document)
	if err != nil || len(findings) != 0 {
		t.Fatalf("findings=%#v err=%v", findings, err)
	}
}

func TestReferencesCannotMaskResolvedValues(t *testing.T) {
	for _, document := range [][]byte{
		[]byte(`{"token":"resolved-value-123 op://Engineering/Punaro/token"}`),
		[]byte(`{"password":"stolen-${PUNARO_PASSWORD}"}`),
		[]byte(`{"notes":"password=op://Vault/item/field token=resolved-value-123"}`),
		[]byte(`{"token":"op://resolved-value-123"}`),
	} {
		findings, err := ScanDocument(document)
		if err != nil || len(findings) == 0 {
			t.Fatalf("mixed reference bypass document=%s findings=%#v err=%v", document, findings, err)
		}
	}
}

func TestCredentialNamedFieldsAreSensitive(t *testing.T) {
	for _, field := range []string{"credential", "credentials", "service_credential"} {
		findings, err := ScanDocument([]byte(`{"` + field + `":"resolved-value-123"}`))
		if err != nil || len(findings) != 1 || findings[0].RuleID != RuleSensitiveField {
			t.Fatalf("field=%q findings=%#v err=%v", field, findings, err)
		}
	}
}

func TestScanDocumentRejectsResolvedSensitiveFieldButNotOrdinaryProse(t *testing.T) {
	document := []byte(`{
  "token":"resolved-value-123",
  "title":"How to rotate a secret token safely"
}`)
	findings, err := ScanDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].RuleID != RuleSensitiveField || findings[0].FieldPath != "/token" {
		t.Fatalf("findings=%#v", findings)
	}
}

func TestSensitiveFieldsRejectShortResolvedValues(t *testing.T) {
	findings, err := ScanDocument([]byte(`{"password":"abc123"}`))
	if err != nil || len(findings) != 1 || findings[0].RuleID != RuleSensitiveField {
		t.Fatalf("findings=%#v err=%v", findings, err)
	}
}

func TestFingerprintsBindCompleteValueAndAllDistinctRules(t *testing.T) {
	first, err := ScanDocument([]byte(`{"value":"-----BEGIN PRIVATE KEY-----\nfirst\nghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"}`))
	if err != nil || len(first) != 2 || first[0].RuleID != RulePrivateKey || first[1].RuleID != RuleBearerToken {
		t.Fatalf("first=%#v err=%v", first, err)
	}
	second, err := ScanDocument([]byte(`{"value":"-----BEGIN PRIVATE KEY-----\nsecond\nghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"}`))
	if err != nil || len(second) != 2 || first[0].Fingerprint == second[0].Fingerprint || first[1].Fingerprint == second[1].Fingerprint {
		t.Fatalf("first=%#v second=%#v err=%v", first, second, err)
	}
}

func TestScanDocumentUsesUnambiguousJSONPointerPaths(t *testing.T) {
	findings, err := ScanDocument([]byte(`{"a/b":{"to~ken":"resolved-value-123"}}`))
	if err != nil || len(findings) != 1 || findings[0].FieldPath != "/a~1b/to~0ken" {
		t.Fatalf("findings=%#v err=%v", findings, err)
	}
}

func TestScanDocumentRejectsMalformedOrNonObjectJSON(t *testing.T) {
	for _, document := range [][]byte{[]byte(`{"x":`), []byte(`[]`), nil} {
		if _, err := ScanDocument(document); err == nil {
			t.Fatalf("accepted %q", document)
		}
	}
}

func TestRuleDigestIsStableAndNonZero(t *testing.T) {
	digest := Digest()
	const expected = "39fb102e3a58faf1e5b7d0045caed1c2110da2f622102c088aeef16f775dfa22"
	if digest == ([32]byte{}) || digest != Digest() || hex.EncodeToString(digest[:]) != expected {
		t.Fatalf("digest=%x", digest)
	}
}
