package diagnostic

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestNewReportSortsChecksAndComputesHealth(t *testing.T) {
	report, err := New(ComponentAdapter, Identity{MachineID: "machine-a", Release: "v0.1.0-alpha.1", ReleaseSequence: 1, Protocol: 1, Platform: "darwin-arm64"}, []Check{
		Pass("relay_transport"),
		Fail("mailbox_mcp", "repair_mailbox_mcp"),
		OptionalFail("plugin_registration", "repair_plugin_registration"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != SchemaVersion || report.Healthy || len(report.Checks) != 3 {
		t.Fatalf("report=%#v", report)
	}
	if got := []string{report.Checks[0].Code, report.Checks[1].Code, report.Checks[2].Code}; strings.Join(got, ",") != "mailbox_mcp,plugin_registration,relay_transport" {
		t.Fatalf("check order=%v", got)
	}
	if ExitCode(report) != ExitUnhealthy {
		t.Fatalf("exit=%d", ExitCode(report))
	}

	healthy, err := New(ComponentServer, Identity{}, []Check{Pass("database_schema"), OptionalFail("gateway_present", "install_gateway")})
	if err != nil || !healthy.Healthy || ExitCode(healthy) != ExitHealthy {
		t.Fatalf("healthy=%#v err=%v exit=%d", healthy, err, ExitCode(healthy))
	}
}

func TestNewReportRejectsUnboundedOrUnstableFields(t *testing.T) {
	tests := []struct {
		name      string
		component Component
		identity  Identity
		checks    []Check
	}{
		{name: "component", component: "private-service", checks: []Check{Pass("ok")}},
		{name: "machine path", component: ComponentAdapter, identity: Identity{MachineID: "/Users/private/key"}, checks: []Check{Pass("ok")}},
		{name: "release control", component: ComponentAdapter, identity: Identity{Release: "alpha\nsecret"}, checks: []Check{Pass("ok")}},
		{name: "code", component: ComponentAdapter, checks: []Check{Pass("provider/error")}},
		{name: "remediation", component: ComponentAdapter, checks: []Check{Fail("relay_transport", "curl https://token.example")}},
		{name: "duplicate", component: ComponentAdapter, checks: []Check{Pass("same"), Pass("same")}},
		{name: "too many", component: ComponentAdapter, checks: make([]Check, MaximumChecks+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := New(test.component, test.identity, test.checks); err == nil {
				t.Fatal("invalid report was accepted")
			}
		})
	}
}

func TestReportJSONIsDeterministicStrictAndContentFree(t *testing.T) {
	report, err := New(ComponentBootstrap, Identity{Release: "v0.1.0-alpha.1", ReleaseSequence: 1, CatalogSequence: 2, ArtifactDigest: "sha256:" + strings.Repeat("a", 64), Platform: "darwin-arm64"}, []Check{
		Fail("slot_integrity", "reinstall_signed_release"),
		Pass("catalog_signature"),
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(report)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("first=%s second=%s err=%v", first, second, err)
	}
	for _, forbidden := range []string{"/Users/", "postgres://", "https://", "token", "private key"} {
		if bytes.Contains(bytes.ToLower(first), []byte(forbidden)) {
			t.Fatalf("report leaked %q: %s", forbidden, first)
		}
	}
	decoded, err := Decode(bytes.NewReader(first))
	if err != nil || decoded.Component != ComponentBootstrap || len(decoded.Checks) != 2 {
		t.Fatalf("decoded=%#v err=%v", decoded, err)
	}
	if _, err := Decode(strings.NewReader(string(first[:len(first)-1]) + `,"unexpected":true}`)); err == nil {
		t.Fatal("unknown report field was accepted")
	}
	if _, err := Decode(strings.NewReader(strings.Repeat(" ", MaximumReportBytes+1))); err == nil {
		t.Fatal("oversized report was accepted")
	}
}

func TestDecodeRejectsForgedOrNonCanonicalReports(t *testing.T) {
	valid := `{"schema_version":1,"component":"adapter","identity":{},"healthy":false,"checks":[{"code":"mailbox_mcp","status":"fail","required":true,"remediation":"repair_mailbox_mcp"},{"code":"relay_transport","status":"pass","required":true}]}`
	tests := map[string]string{
		"missing":          "",
		"trailing":         valid + `{}`,
		"forged health":    strings.Replace(valid, `"healthy":false`, `"healthy":true`, 1),
		"wrong schema":     strings.Replace(valid, `"schema_version":1`, `"schema_version":2`, 1),
		"unsorted":         strings.Replace(valid, `[{"code":"mailbox_mcp","status":"fail","required":true,"remediation":"repair_mailbox_mcp"},{"code":"relay_transport","status":"pass","required":true}]`, `[{"code":"relay_transport","status":"pass","required":true},{"code":"mailbox_mcp","status":"fail","required":true,"remediation":"repair_mailbox_mcp"}]`, 1),
		"unknown identity": strings.Replace(valid, `"identity":{}`, `"identity":{"private_path":"/private"}`, 1),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(strings.NewReader(input)); err == nil {
				t.Fatal("invalid report was accepted")
			}
		})
	}
}

func TestNewReportRejectsInvalidIdentityAndCheckCombinations(t *testing.T) {
	validDigest := "sha256:" + strings.Repeat("a", 64)
	tests := []struct {
		name     string
		identity Identity
		check    Check
	}{
		{name: "negative release sequence", identity: Identity{ReleaseSequence: -1}, check: Pass("ok")},
		{name: "invalid platform", identity: Identity{Platform: "darwin/arm64"}, check: Pass("ok")},
		{name: "invalid artifact digest", identity: Identity{ArtifactDigest: strings.TrimPrefix(validDigest, "sha256:")}, check: Pass("ok")},
		{name: "invalid skill digest", identity: Identity{SkillSetDigest: "sha256:" + strings.Repeat("A", 64)}, check: Pass("ok")},
		{name: "unsorted capabilities", identity: Identity{Capabilities: []string{"relay", "postgresql"}}, check: Pass("ok")},
		{name: "duplicate capabilities", identity: Identity{Capabilities: []string{"relay", "relay"}}, check: Pass("ok")},
		{name: "passing remediation", check: Check{Code: "ok", Status: StatusPass, Required: true, Remediation: "do_something"}},
		{name: "failed without remediation", check: Check{Code: "broken", Status: StatusFail, Required: true}},
		{name: "unknown status", check: Check{Code: "broken", Status: "maybe", Required: true, Remediation: "repair_broken"}},
		{name: "token code", check: Pass("bot_token")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := New(ComponentAdapter, test.identity, []Check{test.check}); err == nil {
				t.Fatal("invalid report was accepted")
			}
		})
	}
}
