package diagnostic

import "testing"

func TestFleetConfigChecksAreContentFree(t *testing.T) {
	t.Parallel()
	checks := FleetConfigChecks("abc", []string{"current", "drifted", "unsupported"})
	if len(checks) != 5 {
		t.Fatalf("checks=%#v", checks)
	}
	byCode := map[string]Check{}
	for _, check := range checks {
		byCode[check.Code] = check
		if check.Code == "" || (check.Status != StatusPass && check.Remediation == "") {
			t.Fatalf("invalid %#v", check)
		}
	}
	if byCode["fleet_config_desired"].Status != StatusPass || byCode["fleet_config_drifted"].Status != StatusFail || byCode["fleet_config_unsupported"].Status != StatusFail {
		t.Fatalf("byCode=%#v", byCode)
	}
}
