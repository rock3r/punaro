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

func TestFleetConfigChecksTreatOfflineNotPendingAsStale(t *testing.T) {
	t.Parallel()
	pending := FleetConfigChecks("digest", []string{"pending", "applying", "current"})
	offline := FleetConfigChecks("digest", []string{"offline"})
	byPending, byOffline := map[string]Check{}, map[string]Check{}
	for _, check := range pending {
		byPending[check.Code] = check
	}
	for _, check := range offline {
		byOffline[check.Code] = check
	}
	if byPending["fleet_config_client_stale"].Status != StatusPass {
		t.Fatalf("pending marked stale: %#v", pending)
	}
	if byOffline["fleet_config_client_stale"].Status != StatusFail {
		t.Fatalf("offline not stale: %#v", offline)
	}
}

func TestRequiredServerChecksIncludeFleetConfig(t *testing.T) {
	t.Parallel()
	codes := RequiredComponentCheckCodes(ComponentServer)
	want := map[string]bool{
		"fleet_config_desired": false, "fleet_config_client_stale": false, "fleet_config_failed": false,
		"fleet_config_drifted": false, "fleet_config_unsupported": false,
	}
	for _, code := range codes {
		if _, ok := want[code]; ok {
			want[code] = true
		}
	}
	for code, found := range want {
		if !found {
			t.Fatalf("missing required server check %s", code)
		}
	}
}
