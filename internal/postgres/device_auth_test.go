package postgres

import (
	"crypto/sha256"
	"strings"
	"testing"
	"time"
)

func TestTrustedAgentGrantPreviewIsExactAndNonAdministrative(t *testing.T) {
	selected, err := TrustedAgentGrantPreview([]string{testProjectA}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 13 {
		t.Fatalf("selected grant count=%d, want 13", len(selected))
	}
	if selected[0] != (GrantSpec{Scope: ScopeInstallation, Capability: CapabilityProjectCreate}) {
		t.Fatalf("first grant=%#v", selected[0])
	}
	for _, grant := range selected {
		if grant.Scope == ScopeAllProjects || grant.Capability == CapabilityProjectAdminister || grant.Capability == CapabilityConversationAdminister || grant.Capability == CapabilityMemoryAdminister || grant.Capability == CapabilityMemoryPurge || grant.Capability == CapabilityAttachmentDelete {
			t.Fatalf("trusted-agent preview included broad/admin authority: %#v", grant)
		}
		if grant.Scope == ScopeProject && grant.ProjectID != testProjectA {
			t.Fatalf("selected grant targeted wrong project: %#v", grant)
		}
	}

	allProjects, err := TrustedAgentGrantPreview(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(allProjects) != len(selected) {
		t.Fatalf("all-project grant count=%d, want %d", len(allProjects), len(selected))
	}
	for _, grant := range allProjects[1:] {
		if grant.Scope != ScopeAllProjects || grant.ProjectID != "" {
			t.Fatalf("dynamic grant is not all-projects: %#v", grant)
		}
	}
	if _, err := TrustedAgentGrantPreview([]string{testProjectA}, true); err == nil {
		t.Fatal("mixed selected and all-projects request accepted")
	}
	if _, err := TrustedAgentGrantPreview(nil, false); err == nil {
		t.Fatal("empty project selection accepted")
	}
}

func TestDeviceCredentialEncodingHasOpaqueLookupAnd256BitSecret(t *testing.T) {
	encoded, lookupID, digest, err := newDeviceCredential()
	if err != nil {
		t.Fatal(err)
	}
	parsedLookup, secret, err := parseDeviceCredential(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsedLookup != lookupID || len(secret) != 32 || sha256.Sum256(secret) != digest {
		t.Fatal("credential encoding did not preserve its lookup and 256-bit secret")
	}
	if strings.Contains(encoded, "=") {
		t.Fatal("credential uses padded encoding")
	}
	for _, malformed := range []string{"", lookupID, lookupID + ".short", strings.ToUpper(lookupID) + "." + strings.Repeat("A", 43), lookupID + "." + strings.Repeat("A", 44), lookupID + "." + strings.Repeat("!", 43)} {
		if _, _, err := parseDeviceCredential(malformed); err == nil {
			t.Fatalf("malformed credential accepted: %q", malformed)
		}
	}
}

func TestEnrollmentAndCredentialBounds(t *testing.T) {
	valid := EnrollmentRequest{ClientBinding: testPrincipalB, Label: "laptop", ProjectIDs: []string{testProjectA}, TTL: 10 * time.Minute}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, request := range map[string]EnrollmentRequest{
		"binding": {ClientBinding: "laptop", Label: valid.Label, ProjectIDs: valid.ProjectIDs, TTL: valid.TTL},
		"label":   {ClientBinding: valid.ClientBinding, Label: "", ProjectIDs: valid.ProjectIDs, TTL: valid.TTL},
		"ttl":     {ClientBinding: valid.ClientBinding, Label: valid.Label, ProjectIDs: valid.ProjectIDs, TTL: 25 * time.Hour},
		"projects": {ClientBinding: valid.ClientBinding, Label: valid.Label,
			ProjectIDs: append(make([]string, maxEnrollmentProjects), testProjectA), TTL: valid.TTL},
	} {
		t.Run(name, func(t *testing.T) {
			if err := request.Validate(); err == nil {
				t.Fatal("invalid enrollment accepted")
			}
		})
	}
}
